package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	"github.com/go-tangra/go-tangra-portal/v4/internal/identity"
	"github.com/go-tangra/go-tangra-portal/v4/internal/proxy/httpproxy"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra-portal/v4/internal/route"
	fidentity "github.com/go-tangra/go-tangra/v4/identity"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
)

// Backend is a forwarder to one module instance (httpproxy.Proxy).
type Backend interface {
	http.Handler
	Target() string
}

// ProxyFactory builds a forwarder for a module instance.
type ProxyFactory func(module string, id fidentity.SPIFFEID, target string) (Backend, error)

// Authorizer decides a protected route (installed by the identity story).
// It returns the request context to forward with (carrying the bearer
// token) or a refusal; nil Authorizer refuses every protected route.
type Authorizer interface {
	Authorize(r *http.Request, rt route.Route) (context.Context, *Error)
}

// HealthReporter receives forwarding outcomes (health.Checker).
type HealthReporter interface {
	Report(ctx context.Context, module, instance string, ok bool)
}

// Limits bound forwarded requests.
type Limits struct {
	BodyBytes     int64
	ModuleTimeout time.Duration
}

// Dispatcher routes public traffic to modules: content type (gRPC, gRPC-web,
// HTTP) → normalise → route snapshot → state → authorization → backend → proxy.
type Dispatcher struct {
	Reg      *registry.Registry
	Proxies  ProxyFactory
	Auth     Authorizer
	Health   HealthReporter
	Limits   Limits
	Audit    *audit.Writer
	Logger   *slog.Logger
	NotOwned http.HandlerFunc
	// GRPC serves application/grpc over HTTP/2 (the passthrough server);
	// GRPCWeb serves application/grpc-web*. Nil refuses those content types.
	GRPC    http.Handler
	GRPCWeb http.Handler
	// Traffic receives per-module request outcomes for the operations view.
	Traffic *Traffic
	// OnSignOut is called with the session cookie after a sign-out was relayed
	// to the auth module (cache invalidation).
	OnSignOut func(ctx context.Context, cookie string)
	// OnIdentityRefresh is called with the session cookie when a response
	// from AuthModule carries IdentityRefreshHeader (profile changed: drop the
	// cached identity). The header is never forwarded in either direction.
	OnIdentityRefresh func(ctx context.Context, cookie string)
	AuthModule        string

	mu    sync.Mutex
	cache map[string]Backend
	rr    map[string]*atomic.Uint32
}

// ServeHTTP implements http.Handler.
func (d *Dispatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ct := r.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "application/grpc-web"):
		if d.GRPCWeb == nil {
			WriteError(w, http.StatusNotImplemented, ErrNotImplemented.Reason)
			return
		}
		d.GRPCWeb.ServeHTTP(w, r)
		return
	case strings.HasPrefix(ct, "application/grpc"):
		if d.GRPC == nil || r.ProtoMajor != 2 {
			WriteError(w, http.StatusNotImplemented, ErrNotImplemented.Reason)
			return
		}
		d.GRPC.ServeHTTP(w, r)
		return
	}
	path, ok := route.Normalize(r.URL.Path)
	if !ok {
		WriteError(w, ErrNotFound.Status, ErrNotFound.Reason)
		return
	}
	rt, matched := d.Reg.Table().Match(r.Method, path)
	if !matched {
		if rt.Module == "" && d.NotOwned != nil {
			d.NotOwned(w, r)
			return
		}
		WriteError(w, ErrNotFound.Status, ErrNotFound.Reason)
		return
	}
	if rt.State != string(registry.StateActive) {
		WriteError(w, ErrUnavailable.Status, ErrUnavailable.Reason)
		return
	}
	ctx := r.Context()
	if !rt.Public {
		if d.Auth == nil {
			WriteError(w, ErrUnauthenticated.Status, ErrUnauthenticated.Reason)
			return
		}
		var refusal *Error
		ctx, refusal = d.Auth.Authorize(r, rt)
		if refusal != nil {
			WriteError(w, refusal.Status, refusal.Reason)
			return
		}
	}
	id, backends := d.Reg.Backends(rt.Module)
	if len(backends) == 0 {
		WriteError(w, ErrUnavailable.Status, ErrUnavailable.Reason)
		return
	}
	spiffe, err := fidentity.ParseSPIFFEID(id)
	if err != nil {
		WriteError(w, ErrUnavailable.Status, ErrUnavailable.Reason)
		return
	}
	in := backends[d.next(rt.Module)%uint32(len(backends))] // #nosec G115 -- small slice
	be, err := d.backend(rt.Module, spiffe, in.Backend.HTTPURL)
	if err != nil {
		if d.Logger != nil {
			d.Logger.Error("proxy build failed", "module", rt.Module, "err", err)
		}
		WriteError(w, ErrUnavailable.Status, ErrUnavailable.Reason)
		return
	}
	limit := rt.MaxBody
	if limit <= 0 {
		limit = d.Limits.BodyBytes
	}
	if limit > 0 && r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, limit)
	}
	timeout := rt.Timeout
	if timeout <= 0 {
		timeout = d.Limits.ModuleTimeout
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	r.Header.Del(IdentityRefreshHeader) // never trusted from clients
	r.Header.Del(httpproxy.ClientAddrHeader)
	if rt.ClientAddress {
		if ip := edge.ClientIP(r.Context()); ip != "" {
			ctx = httpproxy.WithClientAddr(ctx, ip)
		}
	}
	rec := &statusRecorder{ResponseWriter: w, onHeader: func(h http.Header) {
		if h.Get(IdentityRefreshHeader) != "" {
			h.Del(IdentityRefreshHeader)
			if d.OnIdentityRefresh != nil && rt.Module == d.AuthModule {
				if c, err := r.Cookie(identity.SessionCookie); err == nil && c.Value != "" {
					d.OnIdentityRefresh(r.Context(), c.Value)
				}
			}
		}
	}}
	started := time.Now()
	be.ServeHTTP(rec, r.WithContext(ctx))
	if d.Traffic != nil {
		d.Traffic.Record(rt.Module, rec.status, time.Since(started))
	}
	if d.OnSignOut != nil && rec.status < 300 && identity.IsSignOut(r.Method, path) {
		if c, err := r.Cookie(identity.SessionCookie); err == nil {
			d.OnSignOut(r.Context(), c.Value)
		}
	}
	if d.Health != nil {
		// Only transport-level failures count against the instance.
		d.Health.Report(r.Context(), rt.Module, in.ID, rec.status != http.StatusServiceUnavailable && rec.status != http.StatusGatewayTimeout)
	}
	if rec.status == http.StatusRequestEntityTooLarge && d.Audit != nil {
		_ = d.Audit.Emit(audit.Event{Type: audit.LimitExceeded, Module: rt.Module, ActorKind: "user", Outcome: "refused", Reason: "body_too_large",
			Details: map[string]any{"route": rt.Pattern, "client": edge.ClientIP(r.Context()) != ""}})
	}
}

func (d *Dispatcher) next(module string) uint32 {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.rr == nil {
		d.rr = map[string]*atomic.Uint32{}
	}
	c := d.rr[module]
	if c == nil {
		c = &atomic.Uint32{}
		d.rr[module] = c
	}
	return c.Add(1) - 1
}

func (d *Dispatcher) backend(module string, id fidentity.SPIFFEID, target string) (Backend, error) {
	key := module + "|" + id.String() + "|" + target
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cache == nil {
		d.cache = map[string]Backend{}
	}
	if b, ok := d.cache[key]; ok {
		return b, nil
	}
	b, err := d.Proxies(module, id, target)
	if err != nil {
		return nil, err
	}
	d.cache[key] = b
	return b, nil
}

// Forget drops cached forwarders of a module (its instances changed).
func (d *Dispatcher) Forget(module string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	next := map[string]Backend{}
	for k, v := range d.cache {
		if len(k) < len(module)+1 || k[:len(module)+1] != module+"|" {
			next[k] = v
		}
	}
	d.cache = next
}

// IdentityRefreshHeader is the auth module's hint that the caller's identity
// attributes changed (feature 004). Consumed by the dispatcher, never relayed.
const IdentityRefreshHeader = "X-Freya-Identity-Refresh"

type statusRecorder struct {
	http.ResponseWriter
	status   int
	onHeader func(http.Header) // runs once, just before headers are sent
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
		if s.onHeader != nil {
			s.onHeader(s.Header())
		}
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
		if s.onHeader != nil {
			s.onHeader(s.Header())
		}
	}
	return s.ResponseWriter.Write(b)
}

// Flush supports streaming responses.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
