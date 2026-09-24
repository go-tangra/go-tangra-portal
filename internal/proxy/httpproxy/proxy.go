// Package httpproxy forwards HTTP requests to a module over the Freya channel:
// a reverse proxy per backend on a client that presents the gateway's SVID and
// pins the module's registered identity. Header policy: contracts/forwarding.md.
package httpproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/go-tangra/go-tangra/v4/identity"
	"github.com/go-tangra/go-tangra/v4/observe"
	"github.com/go-tangra/go-tangra/v4/transport"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
	thttp "github.com/go-tangra/go-tangra/v4/transport/http"
)

// Options describe one backend.
type Options struct {
	Module   string
	Identity identity.SPIFFEID // the module's registered SPIFFE ID (pinned)
	Target   string            // https://host:port of the module's Freya HTTP server
	// PublicHost is sent as X-Forwarded-Host; empty = the inbound Host.
	PublicHost string
	// AllowCookies forwards Cookie and relays Set-Cookie (the auth module only).
	AllowCookies bool
}

type tokenKey struct{}

type clientAddrKey struct{}

// ClientAddrHeader carries the client IP to modules whose route asked for it
// (manifest route client_address). Inbound copies are always dropped.
const ClientAddrHeader = "X-Gateway-Client-Addr"

// WithClientAddr marks the request context with the client address to
// forward as ClientAddrHeader; without it the header is never sent.
func WithClientAddr(ctx context.Context, addr string) context.Context {
	return context.WithValue(ctx, clientAddrKey{}, addr)
}

// ClientAddrFromContext returns the address set by WithClientAddr ("" when unset).
func ClientAddrFromContext(ctx context.Context) string {
	a, _ := ctx.Value(clientAddrKey{}).(string)
	return a
}

// WithToken marks the request context with the platform access token to
// forward as the bearer credential. Without it, Authorization is removed.
func WithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenKey{}, token)
}

// Proxy is an http.Handler forwarding to one backend.
type Proxy struct {
	o   Options
	rp  *httputil.ReverseProxy
	tgt *url.URL
}

// New builds the proxy; the client is pinned to o.Identity.
func New(rt transport.Runtime, o Options) (*Proxy, error) {
	tgt, err := url.Parse(o.Target)
	if err != nil || tgt.Scheme != "https" || tgt.Host == "" {
		return nil, errors.New("httpproxy: target must be an https URL")
	}
	client, err := thttp.NewClient(rt, o.Identity)
	if err != nil {
		return nil, err
	}
	p := &Proxy{o: o, tgt: tgt}
	p.rp = &httputil.ReverseProxy{
		Transport:      client.Transport,
		Rewrite:        p.rewrite,
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.errorHandler,
		FlushInterval:  -1,
	}
	return p, nil
}

// stripped inbound headers (client-controlled forwarding metadata and credentials).
var stripped = []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port", "X-Real-IP", "X-Request-Id", "X-Gateway-Module", "X-Gateway-Client"}

func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	pr.SetURL(p.tgt)
	pr.Out.Host = p.tgt.Host
	h := pr.Out.Header
	for _, k := range stripped {
		h.Del(k)
	}
	for k := range h {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-freya-") || strings.HasPrefix(lk, "x-gateway-") {
			h.Del(k)
		}
	}
	if tok, _ := pr.In.Context().Value(tokenKey{}).(string); tok != "" {
		h.Set("Authorization", "Bearer "+tok)
	} else {
		h.Del("Authorization")
	}
	if !p.o.AllowCookies {
		h.Del("Cookie")
	}
	cid := observe.CorrelationID(pr.In.Context())
	if cid == "" {
		cid = observe.NewCorrelationID()
	}
	h.Set("X-Request-Id", cid)
	h.Set("X-Forwarded-Proto", "https")
	host := p.o.PublicHost
	if host == "" {
		host = pr.In.Host
	}
	h.Set("X-Forwarded-Host", host)
	h.Set("X-Gateway-Module", p.o.Module)
	// The edge's CSP names this nonce; a module rendering HTML inline (the
	// auth console) must use it. Client-supplied values were dropped above.
	h.Del(CSPNonceHeader)
	if n := edge.Nonce(pr.In.Context()); n != "" {
		h.Set(CSPNonceHeader, n)
	}
	if ip := edge.ClientIP(pr.In.Context()); ip != "" {
		h.Set("X-Gateway-Client", ClientHash(ip))
	}
	if addr := ClientAddrFromContext(pr.In.Context()); addr != "" {
		h.Set(ClientAddrHeader, addr)
	}
}

// CSPNonceHeader carries the edge's per-request CSP nonce to the module.
const CSPNonceHeader = "X-CSP-Nonce"

// ClientHash is the pseudonym of a client address (same scheme as the auth service).
func ClientHash(ip string) string {
	sum := sha256.Sum256([]byte("ip:" + ip))
	return hex.EncodeToString(sum[:])
}

func (p *Proxy) modifyResponse(resp *http.Response) error {
	if !p.o.AllowCookies {
		resp.Header.Del("Set-Cookie")
	}
	resp.Header.Del("Content-Security-Policy")
	resp.Header.Del("Strict-Transport-Security")
	return nil
}

func (p *Proxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	status, reason := http.StatusServiceUnavailable, "temporarily_unavailable"
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge) || strings.Contains(err.Error(), "request body too large"):
		status, reason = http.StatusRequestEntityTooLarge, "payload_too_large"
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(r.Context().Err(), context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"reason":"` + reason + `"}`))
}

// ServeHTTP forwards the request; protocol upgrades are refused.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write([]byte(`{"reason":"not_implemented"}`))
		return
	}
	p.rp.ServeHTTP(w, r)
}

// Target is the backend URL.
func (p *Proxy) Target() string { return p.o.Target }
