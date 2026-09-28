// Package console is the gateway's console listener (feature 025): a second
// public TLS port on an origin of its own that serves only configured path
// prefixes (ipam's BMC KVM consoles under /bmc/) and forwards them — HTTP and
// WebSocket upgrades — to the owning module over the mesh. Vendor console
// JavaScript therefore never runs on the portal origin.
//
// The listener authenticates nobody: the module's console token gates access.
// It never lets portal credentials through: only allow-listed cookies are
// forwarded or relayed, Authorization and client forwarding headers are
// dropped, and the module's security headers are replaced by a console
// policy whose frame-ancestors is the portal origin. Every other path is 404.
package console

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra-portal/v4/internal/route"
	fidentity "github.com/go-tangra/go-tangra/v4/identity"
	"github.com/go-tangra/go-tangra/v4/observe"
)

// Registry is the part of the gateway registry the listener needs.
type Registry interface {
	State(module string) registry.State
	Backends(module string) (identity string, out []registry.Instance)
}

// TransportFactory returns the mesh round tripper that presents the gateway's
// SVID and pins the module's registered identity (thttp.NewClient).
type TransportFactory func(module string, id fidentity.SPIFFEID) (http.RoundTripper, error)

// Options configure the handler.
type Options struct {
	Routes        map[string]string // path prefix ("/bmc/") -> module
	Cookies       []string          // cookie names forwarded and relayed
	PortalOrigin  string            // the only origin allowed to frame consoles
	ConsoleOrigin string            // this listener's public origin
	Registry      Registry
	Transport     TransportFactory
	// RequestTimeout bounds plain requests (default 30s); SessionMax bounds
	// WebSocket upgrades (default 1h).
	RequestTimeout time.Duration
	SessionMax     time.Duration
	BodyBytes      int64 // default 1 MiB
	MaxConcurrent  int   // in-flight requests (default 64)
	Logger         *slog.Logger
	// OnForward receives every forwarded request's outcome (traffic view).
	OnForward func(module string, status int, d time.Duration)
}

// Handler is the console listener's http.Handler.
type Handler struct {
	o        Options
	prefixes []string // longest first
	cookies  map[string]bool
	host     string
	headers  http.Header
	sem      chan struct{}

	mu    sync.Mutex
	cache map[string]*httputil.ReverseProxy
	rr    map[string]*atomic.Uint32
}

// NewHandler validates o and builds the handler.
func NewHandler(o Options) (*Handler, error) {
	switch {
	case len(o.Routes) == 0:
		return nil, errors.New("console: at least one route is required")
	case o.Registry == nil || o.Transport == nil:
		return nil, errors.New("console: registry and transport are required")
	}
	portal, err := origin(o.PortalOrigin)
	if err != nil {
		return nil, fmt.Errorf("console: portal origin: %w", err)
	}
	self, err := origin(o.ConsoleOrigin)
	if err != nil {
		return nil, fmt.Errorf("console: console origin: %w", err)
	}
	if o.RequestTimeout <= 0 {
		o.RequestTimeout = 30 * time.Second
	}
	if o.SessionMax <= 0 {
		o.SessionMax = time.Hour
	}
	if o.BodyBytes <= 0 {
		o.BodyBytes = 1 << 20
	}
	if o.MaxConcurrent <= 0 {
		o.MaxConcurrent = 64
	}
	h := &Handler{o: o, cookies: map[string]bool{}, host: strings.TrimPrefix(self, "https://"),
		sem: make(chan struct{}, o.MaxConcurrent), cache: map[string]*httputil.ReverseProxy{}, rr: map[string]*atomic.Uint32{}}
	for p := range o.Routes {
		h.prefixes = append(h.prefixes, p)
	}
	sort.Slice(h.prefixes, func(i, j int) bool { return len(h.prefixes[i]) > len(h.prefixes[j]) })
	for _, c := range o.Cookies {
		h.cookies[c] = true
	}
	h.headers = consoleHeaders(portal, h.host)
	return h, nil
}

// consoleHeaders is the policy on every console response (research D6):
// vendor viewers need inline/eval scripts, blobs and a WebSocket to self;
// only the portal may frame them.
func consoleHeaders(portal, host string) http.Header {
	h := http.Header{}
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:; "+
		"style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' wss://"+host+"; "+
		"worker-src 'self' blob:; frame-src 'self'; frame-ancestors "+portal+"; base-uri 'self'; object-src 'none'; form-action 'self'")
	h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	return h
}

// replacedResponse are module headers the console policy replaces.
var replacedResponse = []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only", "X-Frame-Options",
	"Strict-Transport-Security", "Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy", "Cross-Origin-Resource-Policy",
	"Permissions-Policy", "Referrer-Policy", "Cache-Control", "Pragma", "Expires"}

// strippedRequest are client headers never forwarded (credentials and
// forwarding metadata the module must not trust).
var strippedRequest = []string{"Authorization", "Proxy-Authorization", "Forwarded", "X-Forwarded-For", "X-Forwarded-Proto",
	"X-Forwarded-Host", "X-Forwarded-Port", "X-Real-IP", "X-Request-Id", "X-CSP-Nonce"}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for k, v := range h.headers {
		w.Header()[k] = append([]string(nil), v...)
	}
	module, ok := h.match(r.URL.Path)
	if !ok {
		writeReason(w, http.StatusNotFound, "not_found")
		return
	}
	select {
	case h.sem <- struct{}{}:
		defer func() { <-h.sem }()
	default:
		writeReason(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	rp, ok := h.backend(module)
	if !ok {
		writeReason(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	ctx := r.Context()
	var cancel context.CancelFunc
	if isUpgrade(r) {
		ctx, cancel = context.WithTimeout(ctx, h.o.SessionMax)
	} else {
		ctx, cancel = context.WithTimeout(ctx, h.o.RequestTimeout)
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, h.o.BodyBytes)
		}
	}
	defer cancel()
	rec := &recorder{ResponseWriter: w}
	started := time.Now()
	rp.ServeHTTP(rec, r.WithContext(context.WithValue(ctx, moduleKey{}, module)))
	if rec.status == 0 { // a relayed upgrade writes its 101 on the hijacked connection
		rec.status = http.StatusSwitchingProtocols
	}
	if h.o.OnForward != nil {
		h.o.OnForward(module, rec.status, time.Since(started))
	}
}

// match returns the module owning path; paths the route normaliser refuses
// (dot segments, "//", control characters, oversize) match nothing.
func (h *Handler) match(path string) (string, bool) {
	if _, ok := route.Normalize(path); !ok {
		return "", false
	}
	for _, p := range h.prefixes {
		if strings.HasPrefix(path, p) {
			return h.o.Routes[p], true
		}
	}
	return "", false
}

// backend picks a healthy instance of an active module (round robin) and
// returns its cached reverse proxy.
func (h *Handler) backend(module string) (*httputil.ReverseProxy, bool) {
	if h.o.Registry.State(module) != registry.StateActive {
		return nil, false
	}
	id, instances := h.o.Registry.Backends(module)
	if len(instances) == 0 {
		return nil, false
	}
	spiffe, err := fidentity.ParseSPIFFEID(id)
	if err != nil {
		return nil, false
	}
	target := instances[h.next(module)%uint32(len(instances))].Backend.HTTPURL // #nosec G115 -- small slice
	tgt, err := url.Parse(target)
	if err != nil || tgt.Scheme != "https" || tgt.Host == "" {
		return nil, false
	}
	key := module + "|" + id + "|" + target
	h.mu.Lock()
	defer h.mu.Unlock()
	if rp, ok := h.cache[key]; ok {
		return rp, true
	}
	tr, err := h.o.Transport(module, spiffe)
	if err != nil {
		h.log("console transport", "module", module, "err", err)
		return nil, false
	}
	rp := &httputil.ReverseProxy{
		Transport:      tr,
		Rewrite:        func(pr *httputil.ProxyRequest) { h.rewrite(pr, tgt) },
		ModifyResponse: h.modifyResponse,
		ErrorHandler:   h.errorHandler,
		FlushInterval:  -1,
	}
	h.cache[key] = rp
	return rp, true
}

func (h *Handler) next(module string) uint32 {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.rr[module]
	if c == nil {
		c = &atomic.Uint32{}
		h.rr[module] = c
	}
	return c.Add(1) - 1
}

type moduleKey struct{}

func (h *Handler) rewrite(pr *httputil.ProxyRequest, tgt *url.URL) {
	pr.Out.URL.Scheme, pr.Out.URL.Host = tgt.Scheme, tgt.Host
	pr.Out.Host = tgt.Host
	out := pr.Out.Header
	for _, k := range strippedRequest {
		out.Del(k)
	}
	for k := range out {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-freya-") || strings.HasPrefix(lk, "x-gateway-") {
			out.Del(k)
		}
	}
	out.Del("Cookie")
	var kept []string
	for _, c := range pr.In.Cookies() {
		if h.cookies[c.Name] {
			kept = append(kept, c.Name+"="+c.Value)
		}
	}
	if len(kept) > 0 {
		out.Set("Cookie", strings.Join(kept, "; "))
	}
	cid := observe.CorrelationID(pr.In.Context())
	if cid == "" {
		cid = observe.NewCorrelationID()
	}
	out.Set("X-Request-Id", cid)
	out.Set("X-Forwarded-Proto", "https")
	out.Set("X-Forwarded-Host", h.host)
	module, _ := pr.In.Context().Value(moduleKey{}).(string)
	out.Set("X-Gateway-Module", module)
}

func (h *Handler) modifyResponse(resp *http.Response) error {
	for _, k := range replacedResponse {
		resp.Header.Del(k)
	}
	var kept []string
	for _, line := range resp.Header.Values("Set-Cookie") {
		name, _, found := strings.Cut(line, "=")
		if found && h.cookies[strings.TrimSpace(name)] {
			kept = append(kept, line)
		}
	}
	resp.Header.Del("Set-Cookie")
	for _, line := range kept {
		resp.Header.Add("Set-Cookie", line)
	}
	return nil
}

func (h *Handler) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	status, reason := http.StatusServiceUnavailable, "temporarily_unavailable"
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		status, reason = http.StatusRequestEntityTooLarge, "payload_too_large"
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(r.Context().Err(), context.DeadlineExceeded):
		status, reason = http.StatusGatewayTimeout, "timeout"
	default:
		h.log("console forward failed", "path", r.URL.Path, "err", err)
	}
	writeReason(w, status, reason)
}

func (h *Handler) log(msg string, args ...any) {
	if h.o.Logger != nil {
		h.o.Logger.Warn(msg, args...)
	}
}

func writeReason(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"reason":"` + reason + `"}`))
}

func isUpgrade(r *http.Request) bool {
	return r.Header.Get("Upgrade") != "" && strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// origin returns v as a lower-case https origin or an error.
func origin(v string) (string, error) {
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(v, " \t\r\n;,'\"") {
		return "", errors.New("must be an https origin")
	}
	return "https://" + strings.ToLower(u.Host), nil
}

// recorder captures the status (ReverseProxy always calls WriteHeader
// except for a relayed upgrade) and keeps Hijack/Flush reachable
// (http.ResponseController unwraps it) for WebSocket upgrades.
type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
