package httpapi

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
)

var shellFS = fstest.MapFS{
	"index.html":    {Data: []byte(`<html><head><meta property="csp-nonce" nonce="__CSP_NONCE__"></head></html>`)},
	"assets/app.js": {Data: []byte("console.log(1)")},
	"favicon.ico":   {Data: []byte("ico")},
}

func newTestServer(t *testing.T, opts ...Option) *Server {
	t.Helper()
	rt := testrt.New(t, testutil.MustCA("example.org"), "gateway")
	s, err := NewHandler(rt, append([]Option{WithShell(shellFS)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func do(s *Server, method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://localhost"+path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestDeclaredRoutesMountedAndValidated(t *testing.T) {
	s := newTestServer(t)
	if len(s.Declared()) < 12 {
		t.Fatalf("declared %d", len(s.Declared()))
	}
	w := do(s, "GET", "/gateway/v1/me", "", nil)
	if w.Code != 501 || strings.TrimSpace(w.Body.String()) != `{"reason":"not_implemented"}` {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	called := false
	s.MustHandle("POST", "/gateway/v1/ops/registrations/{module}/revoke", func(w http.ResponseWriter, r *http.Request) {
		called = true
		var in struct{ Reason string }
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		WriteJSON(w, 200, map[string]string{"module": r.PathValue("module"), "reason": in.Reason})
	})
	csrf := map[string]string{"X-CSRF-Token": "x"}
	for _, body := range []string{`{`, `{"reason":"short"}`, `{"reason":"long enough reason","extra":1}`, `[]`, strings.Repeat("a", MaxBodyBytes+10)} {
		called = false
		w = do(s, "POST", "/gateway/v1/ops/registrations/orders/revoke", body, csrf)
		if w.Code != 400 || !strings.HasPrefix(w.Body.String(), `{"reason":"`) || called {
			t.Fatalf("body %.20q → %d %s called=%v", body, w.Code, w.Body.String(), called)
		}
	}
	// The CSRF header is optional in the document (the edge enforces it for cookie-bearing requests).
	if w = do(s, "POST", "/gateway/v1/ops/registrations/orders/revoke", `{"reason":"decommissioned by ops"}`, nil); w.Code != 200 {
		t.Fatalf("bearer-style call without csrf header → %d", w.Code)
	}
	w = do(s, "POST", "/gateway/v1/ops/registrations/orders/revoke", `{"reason":"decommissioned by ops"}`, csrf)
	if w.Code != 200 || !called || !strings.Contains(w.Body.String(), `"module":"orders"`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if w = do(s, "DELETE", "/gateway/v1/me", "", nil); w.Code != 405 {
		t.Fatalf("405 expected, got %d", w.Code)
	}
	if w = do(s, "GET", "/gateway/v1/nope", "", nil); w.Code != 404 || !strings.Contains(w.Body.String(), "not_found") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if err := s.HandleFunc("GET", "/gateway/v1/secret", nil); err == nil {
		t.Fatal("undeclared route accepted")
	}
	if got := s.Implemented(); len(got) != 1 || !strings.HasSuffix(got[0].Path, "/revoke") {
		t.Fatalf("implemented %v", got)
	}
	// Remote assets are declared with a multi-segment tail.
	s.MustHandle("GET", "/m/{module}/{asset}", func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, 200, map[string]string{"module": r.PathValue("module"), "asset": r.PathValue("asset")})
	})
	if w = do(s, "GET", "/m/orders/assets/chunk-1.js", "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"asset":"assets/chunk-1.js"`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestErrorEncoderNeverLeaks(t *testing.T) {
	s := newTestServer(t)
	s.MustHandle("GET", "/gateway/v1/me", func(w http.ResponseWriter, r *http.Request) {
		Fail(w, r, s.rt.Logger(), errors.New("pq: password authentication failed for user gateway_app"))
	})
	w := do(s, "GET", "/gateway/v1/me", "", nil)
	if w.Code != 503 || strings.TrimSpace(w.Body.String()) != `{"reason":"temporarily_unavailable"}` {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	s.MustHandle("GET", "/gateway/v1/me", func(w http.ResponseWriter, r *http.Request) { Fail(w, r, nil, ErrForbidden) })
	if w = do(s, "GET", "/gateway/v1/me", "", nil); w.Code != 403 || !strings.Contains(w.Body.String(), "forbidden") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	for _, e := range []*Error{ErrUnauthenticated, ErrNotFound, ErrValidation, ErrUnavailable, ErrRateLimited, ErrTooLarge, ErrCSRF} {
		if e.Error() == "" || e.Status < 400 {
			t.Fatalf("%+v", e)
		}
	}
}

func TestShellAndFallback(t *testing.T) {
	s := newTestServer(t)
	w := do(s, "GET", "/orders/42", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "csp-nonce") || strings.Contains(w.Body.String(), "__CSP_NONCE__") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %q %v", w.Code, w.Body.String(), w.Header())
	}
	issued := false
	for _, c := range w.Result().Cookies() {
		if c.Name == edge.CSRFCookie && c.Value != "" && !c.HttpOnly {
			issued = true
		}
	}
	if !issued {
		t.Fatal("a fresh browser must receive the CSRF cookie with the shell")
	}
	if w = do(s, "GET", "/assets/app.js", "", nil); w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	if w = do(s, "GET", "/favicon.ico", "", nil); w.Code != 200 || w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	if w = do(s, "POST", "/orders", "", nil); w.Code != 404 {
		t.Fatalf("unowned POST → %d", w.Code)
	}
	if w = do(s, "GET", "/api/unowned", "", nil); w.Code != 404 {
		t.Fatalf("unowned API path must not serve the shell: %d", w.Code)
	}
	if w = do(s, "GET", "/a/../etc/passwd", "", nil); w.Code != 307 && w.Code != 301 {
		t.Fatalf("traversal → %d", w.Code)
	}
	// A forwarder takes over every unowned path.
	s.SetForwarder(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/orders" {
			WriteJSON(w, 200, map[string]string{"from": "module"})
			return
		}
		s.NotOwned(w, r)
	}))
	if w = do(s, "GET", "/api/orders", "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "module") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if w = do(s, "GET", "/orders/42", "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "<html>") {
		t.Fatalf("shell fallback through forwarder: %d", w.Code)
	}
	// Without a shell, navigations are 404.
	bare, _ := NewHandler(testrt.New(t, testutil.MustCA("example.org"), "gateway"))
	if w = do(bare, "GET", "/orders", "", nil); w.Code != 404 {
		t.Fatalf("%d", w.Code)
	}
	bare.ServeShell(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	rec := httptest.NewRecorder()
	s.ServeShell(rec, httptest.NewRequest("POST", "/", nil))
	if rec.Code != 405 {
		t.Fatalf("shell POST → %d", rec.Code)
	}
}

func TestMiddlewareOrder(t *testing.T) {
	var order []string
	mk := func(n string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { order = append(order, n); next.ServeHTTP(w, r) })
		}
	}
	s := newTestServer(t, WithMiddleware(mk("a"), mk("b")))
	do(s, "GET", "/gateway/v1/me", "", nil)
	if strings.Join(order, "") != "ab" {
		t.Fatal(order)
	}
}

func TestEdgeCSRFAndHeaders(t *testing.T) {
	rt := testrt.New(t, testutil.MustCA("example.org"), "gateway")
	s, err := New(rt, edge.Config{Addr: "127.0.0.1:0", Env: "test"}, WithShell(shellFS))
	if err != nil {
		t.Fatal(err)
	}
	s.MustHandle("POST", "/gateway/v1/ops/registrations/{module}/drain", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	s.SetForwarder(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/orders") {
			w.WriteHeader(204)
			return
		}
		s.NotOwned(w, r)
	}))
	stop := testrt.StartServer(t, s)
	defer stop()
	ep, _ := s.Edge().Endpoint()
	base := "https://" + ep.Host
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}}} //nolint:gosec // dev cert
	get := func(p string) *http.Response {
		resp, err := client.Get(base + p)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := get("/")
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "nonce-") || resp.Header.Get("X-Frame-Options") != "DENY" || resp.Header.Get("Strict-Transport-Security") == "" {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var csrf string
	for _, c := range resp.Cookies() {
		if c.Name == edge.CSRFCookie {
			csrf = c.Value
		}
	}
	if csrf == "" || !strings.Contains(string(body), "nonce=\"") {
		t.Fatal("csrf cookie / nonce")
	}
	post := func(p string, hdr map[string]string) int {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, base+p, nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// Browser-style state change without the double-submit → csrf.
	if c := post("/gateway/v1/ops/registrations/orders/drain", map[string]string{"Cookie": edge.CSRFCookie + "=" + csrf}); c != 403 {
		t.Fatalf("missing header → %d", c)
	}
	if c := post("/gateway/v1/ops/registrations/orders/drain", map[string]string{"Cookie": edge.CSRFCookie + "=" + csrf, edge.CSRFHeader: csrf, "Sec-Fetch-Site": "same-origin"}); c != 204 {
		t.Fatalf("double submit → %d", c)
	}
	// Machine client: bearer token, no cookies → exempt on forwarded routes.
	if c := post("/api/orders", map[string]string{"Authorization": "Bearer t"}); c != 204 {
		t.Fatalf("bearer client → %d", c)
	}
	if c := post("/api/orders", nil); c != 204 {
		t.Fatalf("anonymous POST without cookies is not a CSRF risk: %d", c)
	}
	if c := post("/api/orders", map[string]string{"Cookie": "__Host-session=abc"}); c != 403 {
		t.Fatalf("cookie-bearing POST without the double submit must be refused: %d", c)
	}
}
