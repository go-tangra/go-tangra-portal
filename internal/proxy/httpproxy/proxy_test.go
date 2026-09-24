package httpproxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra/v4/authn"
	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"
	"github.com/go-tangra/go-tangra/v4/identity"
	"github.com/go-tangra/go-tangra/v4/observe"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
	thttp "github.com/go-tangra/go-tangra/v4/transport/http"
)

type seen struct {
	Peer    string              `json:"peer"`
	Host    string              `json:"host"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

func startModule(t *testing.T, ca *testutil.CA, name string) (string, *testrt.Runtime) {
	t.Helper()
	rt := testrt.New(t, ca, name)
	srv, _ := thttp.NewServer(rt, thttp.WithAddress("127.0.0.1:0"))
	srv.HandleFunc("/api/echo", func(w http.ResponseWriter, r *http.Request) {
		p, _ := authn.FromContext(r.Context())
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Set-Cookie", "__Host-session=leak; Secure")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Strict-Transport-Security", "max-age=1")
		w.Header().Set("X-Module", name)
		_ = json.NewEncoder(w).Encode(seen{Peer: p.ServiceName, Host: r.Host, Path: r.URL.RequestURI(), Headers: r.Header, Body: string(body)})
	})
	srv.HandleFunc("/api/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	})
	stop := testrt.StartServer(t, srv)
	t.Cleanup(stop)
	ep, _ := srv.Endpoint()
	return "https://" + ep.Host, rt
}

func TestForwardingHeaderPolicy(t *testing.T) {
	ca := testutil.MustCA("example.org")
	target, _ := startModule(t, ca, "orders")
	gw := testrt.New(t, ca, "gateway")
	orders, _ := identity.NewSPIFFEID("example.org", "orders")
	p, err := New(gw, Options{Module: "orders", Identity: orders, Target: target, PublicHost: "platform.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://platform.example.org/api/echo?x=1", strings.NewReader("payload"))
	for k, v := range map[string]string{"Cookie": "__Host-session=abc", "Authorization": "Bearer client-supplied", "X-Forwarded-For": "1.2.3.4", "X-Real-IP": "1.2.3.4",
		"X-Freya-Internal": "x", "X-Gateway-Module": "spoof", "X-Gateway-Client": "spoof", "Forwarded": "for=1.2.3.4", "X-Request-Id": "spoof", "Content-Type": "text/plain", "X-CSP-Nonce": "spoof", "X-Gateway-Client-Addr": "spoof", "X-Gateway-Anything": "spoof"} {
		req.Header.Set(k, v)
	}
	ctx := observe.WithCorrelationID(req.Context(), "01a0a904-0000-7000-8000-000000000001")
	ctx = edge.WithClientIP(ctx, "203.0.113.9")
	ctx = edge.WithNonce(ctx, "edge-nonce")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var s seen
	_ = json.Unmarshal(rec.Body.Bytes(), &s)
	if s.Peer != "gateway" || s.Body != "payload" || s.Path != "/api/echo?x=1" || s.Host != strings.TrimPrefix(target, "https://") {
		t.Fatalf("%+v", s)
	}
	for _, gone := range []string{"Cookie", "Authorization", "X-Forwarded-For", "X-Real-Ip", "X-Freya-Internal", "Forwarded", "X-Gateway-Client-Addr", "X-Gateway-Anything"} {
		if _, ok := s.Headers[gone]; ok {
			t.Errorf("%s forwarded: %v", gone, s.Headers[gone])
		}
	}
	if s.Headers["X-Request-Id"][0] != "01a0a904-0000-7000-8000-000000000001" || s.Headers["X-Forwarded-Proto"][0] != "https" || s.Headers["X-Forwarded-Host"][0] != "platform.example.org" ||
		s.Headers["X-Gateway-Module"][0] != "orders" || s.Headers["X-Gateway-Client"][0] != ClientHash("203.0.113.9") || s.Headers["Content-Type"][0] != "text/plain" ||
		s.Headers["X-Csp-Nonce"][0] != "edge-nonce" {
		t.Fatalf("%v", s.Headers)
	}
	if rec.Header().Get("Set-Cookie") != "" || rec.Header().Get("Content-Security-Policy") != "" || rec.Header().Get("Strict-Transport-Security") != "" || rec.Header().Get("X-Module") != "orders" {
		t.Fatalf("response headers: %v", rec.Header())
	}
	// With a token in the context the bearer credential is set; cookies allowed for the auth module.
	pa, _ := New(gw, Options{Module: "auth", Identity: orders, Target: target, AllowCookies: true})
	req = httptest.NewRequest(http.MethodGet, "https://x/api/echo", nil)
	req.Header.Set("Cookie", "__Host-session=abc")
	req.Header.Set("Authorization", "Bearer client-supplied")
	rec = httptest.NewRecorder()
	pa.ServeHTTP(rec, req.WithContext(WithToken(req.Context(), "platform-token")))
	s = seen{}
	_ = json.Unmarshal(rec.Body.Bytes(), &s)
	if s.Headers["Authorization"][0] != "Bearer platform-token" || s.Headers["Cookie"][0] != "__Host-session=abc" || s.Headers["X-Forwarded-Host"][0] != "x" || len(s.Headers["X-Request-Id"][0]) < 20 {
		t.Fatalf("%v", s.Headers)
	}
	if rec.Header().Get("Set-Cookie") == "" {
		t.Fatal("auth module Set-Cookie must be relayed")
	}
	if _, ok := s.Headers["X-Gateway-Client"]; ok {
		t.Fatal("no client ip → no pseudonym")
	}
	// Routes flagged client_address get the plain address from the context only.
	req = httptest.NewRequest(http.MethodGet, "https://x/api/echo", nil)
	req.Header.Set("X-Gateway-Client-Addr", "spoof")
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req.WithContext(WithClientAddr(edge.WithClientIP(req.Context(), "203.0.113.9"), "203.0.113.9")))
	s = seen{}
	_ = json.Unmarshal(rec.Body.Bytes(), &s)
	if s.Headers["X-Gateway-Client-Addr"][0] != "203.0.113.9" || ClientAddrFromContext(context.Background()) != "" {
		t.Fatalf("client addr: %v", s.Headers)
	}
	if p.Target() != target {
		t.Fatal("target")
	}
}

func TestPinningTimeoutsAndErrors(t *testing.T) {
	ca := testutil.MustCA("example.org")
	target, _ := startModule(t, ca, "orders")
	gw := testrt.New(t, ca, "gateway")
	billing, _ := identity.NewSPIFFEID("example.org", "billing")
	// Backend presenting another identity than the registered one → refused, 503, never a body from the module.
	wrong, _ := New(gw, Options{Module: "orders", Identity: billing, Target: target})
	rec := httptest.NewRecorder()
	wrong.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://x/api/echo", nil))
	if rec.Code != 503 || strings.TrimSpace(rec.Body.String()) != `{"reason":"temporarily_unavailable"}` {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	orders, _ := identity.NewSPIFFEID("example.org", "orders")
	p, _ := New(gw, Options{Module: "orders", Identity: orders, Target: target})
	// Deadline from the dispatcher → 504 with the same reason.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://x/api/slow", nil).WithContext(ctx))
	if rec.Code != 504 || !strings.Contains(rec.Body.String(), "temporarily_unavailable") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	// Oversized body (dispatcher limit) → 413 payload_too_large.
	rec = httptest.NewRecorder()
	big := httptest.NewRequest(http.MethodPost, "https://x/api/echo", strings.NewReader(strings.Repeat("x", 100)))
	big.Body = http.MaxBytesReader(rec, big.Body, 10)
	p.ServeHTTP(rec, big)
	if rec.Code != 413 || !strings.Contains(rec.Body.String(), "payload_too_large") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	// Dead backend → 503.
	dead, _ := New(gw, Options{Module: "orders", Identity: orders, Target: "https://127.0.0.1:1"})
	rec = httptest.NewRecorder()
	dead.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://x/api/echo", nil))
	if rec.Code != 503 {
		t.Fatalf("%d", rec.Code)
	}
	// WebSocket upgrades are refused in v1.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://x/api/echo", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	p.ServeHTTP(rec, req)
	if rec.Code != 501 {
		t.Fatalf("upgrade → %d", rec.Code)
	}
	// Bad options.
	if _, err := New(gw, Options{Module: "x", Identity: orders, Target: "http://plain"}); err == nil {
		t.Fatal("plaintext target accepted")
	}
	if _, err := New(gw, Options{Module: "x", Identity: identity.SPIFFEID{}, Target: target}); err == nil {
		t.Fatal("zero identity accepted")
	}
}
