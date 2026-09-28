package console

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	fidentity "github.com/go-tangra/go-tangra/v4/identity"
)

const (
	portal    = "https://portal.example.org"
	consoleO  = "https://portal.example.org:8444"
	ipamID    = "spiffe://example.org/svc/ipam"
	fwdModule = "ipam"
)

type fakeReg struct {
	mu       sync.Mutex
	state    map[string]registry.State
	id       map[string]string
	backends map[string][]registry.Instance
}

func (f *fakeReg) State(m string) registry.State {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state[m]
}

func (f *fakeReg) Backends(m string) (string, []registry.Instance) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.id[m], f.backends[m]
}

func regWith(targets ...string) *fakeReg {
	r := &fakeReg{state: map[string]registry.State{fwdModule: registry.StateActive}, id: map[string]string{fwdModule: ipamID}, backends: map[string][]registry.Instance{}}
	for i, t := range targets {
		r.backends[fwdModule] = append(r.backends[fwdModule], registry.Instance{ID: string(rune('a' + i)), Backend: registry.Backend{HTTPURL: t}})
	}
	return r
}

type transports struct{ calls atomic.Int32 }

func (tf *transports) factory(module string, id fidentity.SPIFFEID) (http.RoundTripper, error) {
	tf.calls.Add(1)
	if module != fwdModule || id.String() != ipamID {
		return nil, errors.New("unexpected module identity")
	}
	return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, nil //nolint:gosec // test backend
}

type harness struct {
	h       *Handler
	front   *httptest.Server
	reg     *fakeReg
	tf      *transports
	mu      sync.Mutex
	records []forward
}

type forward struct {
	module string
	status int
}

func newHarness(t *testing.T, reg *fakeReg, mut ...func(*Options)) *harness {
	t.Helper()
	hs := &harness{reg: reg, tf: &transports{}}
	o := Options{
		Routes: map[string]string{"/bmc/": fwdModule}, Cookies: []string{"freya_kvm"},
		PortalOrigin: portal, ConsoleOrigin: consoleO, Registry: reg, Transport: hs.tf.factory,
		RequestTimeout: 5 * time.Second, SessionMax: time.Minute, BodyBytes: 1 << 10, MaxConcurrent: 16,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnForward: func(module string, status int, _ time.Duration) {
			hs.mu.Lock()
			hs.records = append(hs.records, forward{module, status})
			hs.mu.Unlock()
		},
	}
	for _, f := range mut {
		f(&o)
	}
	h, err := NewHandler(o)
	if err != nil {
		t.Fatal(err)
	}
	hs.h = h
	hs.front = httptest.NewServer(h)
	t.Cleanup(hs.front.Close)
	return hs
}

// waitRecord waits for exactly one traffic record (the handler reports after
// the response was relayed, so the client may see it first).
func (hs *harness) waitRecord(t *testing.T, want forward) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		hs.mu.Lock()
		recs := append([]forward(nil), hs.records...)
		hs.mu.Unlock()
		if len(recs) == 1 {
			if recs[0] != want {
				t.Fatalf("traffic record %v, want %v", recs[0], want)
			}
			return
		}
		if len(recs) > 1 || time.Now().After(deadline) {
			t.Fatalf("traffic records %v", recs)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// backend is a module's mesh HTTP server; it records what it received.
type backend struct {
	srv  *httptest.Server
	hits atomic.Int32
	mu   sync.Mutex
	last *http.Request
}

func newBackend(t *testing.T, h http.HandlerFunc) *backend {
	t.Helper()
	b := &backend{}
	b.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.hits.Add(1)
		b.mu.Lock()
		b.last = r.Clone(r.Context())
		b.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *backend) lastReq() *http.Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.last
}

func TestForwardsAndAppliesPolicy(t *testing.T) {
	be := newBackend(t, func(w http.ResponseWriter, _ *http.Request) {
		h := w.Header()
		h.Add("Set-Cookie", "__Host-session=evil; Path=/; Secure; HttpOnly")
		h.Add("Set-Cookie", "__Host-csrf=evil; Path=/; Secure")
		h.Add("Set-Cookie", "other=1; Path=/")
		h.Add("Set-Cookie", "freya_kvm=new; Path=/bmc/dev1/; Secure; HttpOnly; SameSite=Strict")
		h.Add("Set-Cookie", "malformed-without-equals")
		h.Set("Content-Security-Policy", "default-src *")
		h.Set("Content-Security-Policy-Report-Only", "default-src *")
		h.Set("X-Frame-Options", "SAMEORIGIN")
		h.Set("Strict-Transport-Security", "max-age=0")
		h.Set("Cross-Origin-Opener-Policy", "unsafe-none")
		h.Set("Cross-Origin-Embedder-Policy", "require-corp")
		h.Set("Cross-Origin-Resource-Policy", "cross-origin")
		h.Set("Cache-Control", "public, max-age=600")
		h.Set("Expires", "Thu, 01 Jan 2099 00:00:00 GMT")
		h.Set("Pragma", "cache")
		h.Set("Permissions-Policy", "camera=*")
		h.Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "console-ok")
	})
	hs := newHarness(t, regWith(be.srv.URL))
	req, _ := http.NewRequest(http.MethodGet, hs.front.URL+"/bmc/dev1/?kvmtoken=abc&x=1", nil)
	req.Header.Set("Cookie", "__Host-session=s; __Host-csrf=c; freya_kvm=k; other=o")
	for k, v := range map[string]string{
		"Authorization": "Bearer portal-token", "Proxy-Authorization": "Basic x", "Forwarded": "for=1.2.3.4",
		"X-Forwarded-For": "1.2.3.4", "X-Forwarded-Host": "evil", "X-Forwarded-Proto": "http", "X-Real-IP": "1.2.3.4",
		"X-Freya-Identity": "admin", "X-Gateway-Client": "spoof", "X-Gateway-Module": "auth", "X-CSP-Nonce": "n",
		"X-Request-Id": "spoofed-id",
	} {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "console-ok" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}

	in := be.lastReq()
	if in.URL.Path != "/bmc/dev1/" || in.URL.RawQuery != "kvmtoken=abc&x=1" {
		t.Fatalf("forwarded %s?%s", in.URL.Path, in.URL.RawQuery)
	}
	if got := in.Header.Values("Cookie"); len(got) != 1 || got[0] != "freya_kvm=k" {
		t.Fatalf("cookies reaching the module: %q", got)
	}
	for _, k := range []string{"Authorization", "Proxy-Authorization", "Forwarded", "X-Forwarded-For", "X-Real-IP", "X-Freya-Identity", "X-Gateway-Client", "X-CSP-Nonce"} {
		if v := in.Header.Get(k); v != "" {
			t.Errorf("%s reached the module: %q", k, v)
		}
	}
	if id := in.Header.Get("X-Request-Id"); id == "" || id == "spoofed-id" {
		t.Errorf("request id %q", id)
	}
	host := strings.TrimPrefix(consoleO, "https://")
	if in.Header.Get("X-Forwarded-Proto") != "https" || in.Header.Get("X-Forwarded-Host") != host || in.Header.Get("X-Gateway-Module") != fwdModule {
		t.Errorf("forwarding headers %v", in.Header)
	}

	h := resp.Header
	if got := h.Values("Set-Cookie"); len(got) != 1 || !strings.HasPrefix(got[0], "freya_kvm=new;") {
		t.Fatalf("Set-Cookie relayed to the browser: %q", got)
	}
	csp := h.Get("Content-Security-Policy")
	for _, want := range []string{"frame-ancestors " + portal + ";", "'unsafe-inline'", "'unsafe-eval'", "wss://" + host, "object-src 'none'", "default-src 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("console CSP %q lacks %q", csp, want)
		}
	}
	if len(h.Values("Content-Security-Policy")) != 1 || h.Get("Content-Security-Policy-Report-Only") != "" {
		t.Errorf("module CSP leaked: %v", h.Values("Content-Security-Policy"))
	}
	if h.Get("X-Frame-Options") != "" || h.Get("Cross-Origin-Embedder-Policy") != "" || h.Get("Expires") != "" || h.Get("Pragma") != "" {
		t.Errorf("module headers leaked: %v", h)
	}
	for k, v := range map[string]string{
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
		"Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Resource-Policy": "same-origin",
		"Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
	} {
		if got := h.Values(k); len(got) != 1 || got[0] != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	hs.waitRecord(t, forward{fwdModule, http.StatusOK})
}

func TestCookieHeaderDroppedWhenNothingAllowed(t *testing.T) {
	be := newBackend(t, func(w http.ResponseWriter, _ *http.Request) {})
	hs := newHarness(t, regWith(be.srv.URL))
	req, _ := http.NewRequest(http.MethodGet, hs.front.URL+"/bmc/dev1/app.js", nil)
	req.Header.Set("Cookie", "__Host-session=s; __Host-csrf=c")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, ok := be.lastReq().Header["Cookie"]; ok {
		t.Fatalf("Cookie header reached the module: %q", be.lastReq().Header.Values("Cookie"))
	}
}

func TestOnlyConsolePaths(t *testing.T) {
	be := newBackend(t, func(w http.ResponseWriter, _ *http.Request) {})
	hs := newHarness(t, regWith(be.srv.URL))
	for _, p := range []string{
		"/", "/api/ipam/v1/devices", "/gateway/v1/me", "/m/ipam/remoteEntry.js", "/bmcx", "/bmc", "/BMC/dev1/",
		"/bmc/../api/ipam/v1/devices", "/bmc//x", "/bmc/%2e%2e/api/", "/bmc/x%00y", "/bmc/a\\b",
		"/bmc/" + strings.Repeat("a", 2100),
	} {
		rec := httptest.NewRecorder()
		hs.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://portal.example.org:8444"+p, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%q: status %d, want 404", p, rec.Code)
		}
		if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors "+portal) || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%q: console headers missing on 404: %v", p, rec.Header())
		}
	}
	if be.hits.Load() != 0 {
		t.Fatalf("module contacted %d times for non-console paths", be.hits.Load())
	}
}

func TestLongestPrefixWins(t *testing.T) {
	be := newBackend(t, func(w http.ResponseWriter, _ *http.Request) {})
	reg := regWith(be.srv.URL)
	hs := newHarness(t, reg, func(o *Options) { o.Routes = map[string]string{"/bmc/": "nobody", "/bmc/x/": fwdModule} })
	resp, err := http.Get(hs.front.URL + "/bmc/x/y")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || be.hits.Load() != 1 {
		t.Fatalf("status %d hits %d", resp.StatusCode, be.hits.Load())
	}
	resp, _ = http.Get(hs.front.URL + "/bmc/z")
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unregistered module: %d", resp.StatusCode)
	}
}

func TestUnavailableModule(t *testing.T) {
	be := newBackend(t, func(w http.ResponseWriter, _ *http.Request) {})
	cases := map[string]*fakeReg{
		"not registered": {state: map[string]registry.State{}, id: map[string]string{}, backends: map[string][]registry.Instance{}},
		"disabled":       func() *fakeReg { r := regWith(be.srv.URL); r.state[fwdModule] = "disabled"; return r }(),
		"no backend":     regWith(),
		"bad identity":   func() *fakeReg { r := regWith(be.srv.URL); r.id[fwdModule] = "not-spiffe"; return r }(),
		"plain target":   regWith("http://127.0.0.1:1"),
		"bad target":     regWith("https://%zz"),
		"backend down":   regWith("https://127.0.0.1:1"),
	}
	for name, reg := range cases {
		hs := newHarness(t, reg)
		resp, err := http.Get(hs.front.URL + "/bmc/dev1/")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), "temporarily_unavailable") {
			t.Errorf("%s: %d %q", name, resp.StatusCode, body)
		}
	}
	if be.hits.Load() != 0 {
		t.Fatal("module contacted")
	}
	// A transport that cannot be built is unavailable too.
	hs := newHarness(t, regWith(be.srv.URL), func(o *Options) {
		o.Transport = func(string, fidentity.SPIFFEID) (http.RoundTripper, error) { return nil, errors.New("no svid") }
	})
	resp, _ := http.Get(hs.front.URL + "/bmc/dev1/")
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("transport error: %d", resp.StatusCode)
	}
}

func TestRoundRobinAndCachedBackends(t *testing.T) {
	a := newBackend(t, func(w http.ResponseWriter, _ *http.Request) {})
	b := newBackend(t, func(w http.ResponseWriter, _ *http.Request) {})
	hs := newHarness(t, regWith(a.srv.URL, b.srv.URL))
	for range 4 {
		resp, err := http.Get(hs.front.URL + "/bmc/dev1/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if a.hits.Load() != 2 || b.hits.Load() != 2 {
		t.Fatalf("hits a=%d b=%d", a.hits.Load(), b.hits.Load())
	}
	if hs.tf.calls.Load() != 2 {
		t.Fatalf("transport built %d times, want once per backend", hs.tf.calls.Load())
	}
}

func TestTimeoutAndBodyLimit(t *testing.T) {
	release := make(chan struct{})
	be := newBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bmc/dev1/slow" {
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return
		}
		if _, err := io.ReadAll(r.Body); err != nil {
			return
		}
		_, _ = io.WriteString(w, "read")
	})
	defer close(release)
	hs := newHarness(t, regWith(be.srv.URL), func(o *Options) { o.RequestTimeout = 100 * time.Millisecond })
	resp, err := http.Get(hs.front.URL + "/bmc/dev1/slow")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("slow module: %d", resp.StatusCode)
	}
	resp, err = http.Post(hs.front.URL+"/bmc/dev1/upload", "application/octet-stream", strings.NewReader(strings.Repeat("x", 2<<10)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d", resp.StatusCode)
	}
	resp, _ = http.Post(hs.front.URL+"/bmc/dev1/upload", "application/octet-stream", strings.NewReader("small"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("small body: %d", resp.StatusCode)
	}
}

func TestConcurrencyCap(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	be := newBackend(t, func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
	})
	hs := newHarness(t, regWith(be.srv.URL), func(o *Options) { o.MaxConcurrent = 1 })
	done := make(chan int, 1)
	go func() {
		resp, err := http.Get(hs.front.URL + "/bmc/dev1/hold")
		if err != nil {
			done <- 0
			return
		}
		resp.Body.Close()
		done <- resp.StatusCode
	}()
	<-entered
	resp, err := http.Get(hs.front.URL + "/bmc/dev1/second")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	close(release)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("over the cap: %d", resp.StatusCode)
	}
	if st := <-done; st != http.StatusOK {
		t.Fatalf("held request: %d", st)
	}
}

// wsBackend answers an upgrade with 101 and echoes bytes until closed.
func wsBackend(t *testing.T, seen *atomic.Value) *backend {
	return newBackend(t, func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.Header.Values("Cookie"))
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "upgrade required", http.StatusBadRequest)
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = rw.Flush()
		_, _ = io.Copy(conn, rw)
	})
}

func dialUpgrade(t *testing.T, front string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(front, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(conn, "GET /bmc/dev1/__kvmws HTTP/1.1\r\nHost: portal.example.org:8444\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nCookie: __Host-session=s; freya_kvm=k\r\nOrigin: "+consoleO+"\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	return conn, br, resp
}

func TestWebSocketRelayed(t *testing.T) {
	var seen atomic.Value
	be := wsBackend(t, &seen)
	hs := newHarness(t, regWith(be.srv.URL))
	conn, br, resp := dialUpgrade(t, hs.front.URL)
	defer conn.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors "+portal) {
		t.Fatalf("console headers on 101: %v", resp.Header)
	}
	if c, _ := seen.Load().([]string); len(c) != 1 || c[0] != "freya_kvm=k" {
		t.Fatalf("cookies at the module: %q", c)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	for _, msg := range []string{"frame-1", "frame-2"} {
		if _, err := io.WriteString(conn, msg); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(br, buf); err != nil || string(buf) != msg {
			t.Fatalf("echo %q %v", buf, err)
		}
	}
	conn.Close()
	hs.waitRecord(t, forward{fwdModule, http.StatusSwitchingProtocols})
}

func TestOnlyWebSocketUpgrades(t *testing.T) {
	be := newBackend(t, func(w http.ResponseWriter, _ *http.Request) {})
	hs := newHarness(t, regWith(be.srv.URL))
	req := httptest.NewRequest(http.MethodGet, "https://portal.example.org:8444/bmc/dev1/", nil)
	req.Header.Set("Upgrade", "h2c")
	req.Header.Set("Connection", "Upgrade")
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || be.hits.Load() != 0 {
		t.Fatalf("h2c upgrade: %d, module hits %d", rec.Code, be.hits.Load())
	}
}

func TestWebSocketEndsAtSessionMax(t *testing.T) {
	var seen atomic.Value
	be := wsBackend(t, &seen)
	hs := newHarness(t, regWith(be.srv.URL), func(o *Options) { o.SessionMax = 200 * time.Millisecond })
	conn, br, resp := dialUpgrade(t, hs.front.URL)
	defer conn.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status %d", resp.StatusCode)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := io.Copy(io.Discard, br); err != nil {
		t.Fatalf("stream did not end cleanly: %v", err)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("session_max not enforced")
	}
}

func TestNewHandlerValidation(t *testing.T) {
	ok := Options{Routes: map[string]string{"/bmc/": "ipam"}, PortalOrigin: portal, ConsoleOrigin: consoleO, Registry: regWith(), Transport: (&transports{}).factory}
	for name, f := range map[string]func(o *Options){
		"no routes":         func(o *Options) { o.Routes = nil },
		"no registry":       func(o *Options) { o.Registry = nil },
		"no transport":      func(o *Options) { o.Transport = nil },
		"no portal origin":  func(o *Options) { o.PortalOrigin = "" },
		"bad console":       func(o *Options) { o.ConsoleOrigin = "http://x" },
		"console with path": func(o *Options) { o.ConsoleOrigin = "https://x/p" },
		"bad portal":        func(o *Options) { o.PortalOrigin = "https://x; script-src *" },
	} {
		o := ok
		f(&o)
		if _, err := NewHandler(o); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	h, err := NewHandler(ok)
	if err != nil {
		t.Fatal(err)
	}
	if h.o.RequestTimeout != 30*time.Second || h.o.SessionMax != time.Hour || h.o.BodyBytes != 1<<20 || cap(h.sem) != 64 {
		t.Fatalf("defaults %+v cap %d", h.o, cap(h.sem))
	}
}
