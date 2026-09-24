//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"sort"
	"sync"
	"testing"
	"time"

	ktransport "github.com/go-kratos/kratos/v3/transport"
	gatewayv1 "github.com/go-tangra/go-tangra-portal/sdk/v4/api/proto/gateway/v1"
	"github.com/go-tangra/go-tangra-portal/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra-portal/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-portal/v4/internal/proxy/httpproxy"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"
	fidentity "github.com/go-tangra/go-tangra/v4/identity"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
	thttp "github.com/go-tangra/go-tangra/v4/transport/http"
	"github.com/go-tangra/go-tangra/v4/transport/tlsconf"
)

// startServer binds and starts a Kratos transport for a benchmark.
func startServer(tb testing.TB, s ktransport.Server) func() {
	tb.Helper()
	if ep, ok := s.(ktransport.Endpointer); ok {
		if _, err := ep.Endpoint(); err != nil {
			tb.Fatalf("bind: %v", err)
		}
	}
	go func() { _ = s.Start(context.Background()) }()
	time.Sleep(50 * time.Millisecond)
	return func() { _ = s.Stop(context.Background()) }
}

// BenchmarkForward measures the gateway's forwarding overhead (SC-003):
// public route through the edge → dispatcher → pinned mTLS proxy → module,
// at 1,000 concurrent clients, reporting the p95 of the added latency
// against a direct call to the module. No containers are needed.
func BenchmarkForward(b *testing.B) {
	ca := testutil.MustCA("example.org")
	modRT := testrt.NewTB(b, ca, "orders")
	mod, _ := thttp.NewServer(modRT, thttp.WithAddress("127.0.0.1:0"))
	mod.HandleFunc("/api/orders/ping", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	stopMod := startServer(b, mod)
	defer stopMod()
	modEP, _ := mod.Endpoint()

	gwRT := testrt.NewTB(b, ca, "gateway")
	gwRT.Lim.MaxConcurrentStreams = 4096
	ctx := context.Background()
	ms := memstore.New()
	_ = ms.InsertAllow(ctx, store.AllowEntry{ID: "a", SpiffeID: "spiffe://example.org/svc/orders", Prefixes: []string{"/api/orders"}, Names: []string{"orders"}})
	reg, _ := registry.New(registry.Options{KV: registry.NewMemory(), Allow: ms, Marks: ms})
	if _, err := reg.Register(ctx, "spiffe://example.org/svc/orders", &gatewayv1.RegisterRequest{InstanceId: "i1", Backend: &gatewayv1.Backend{HttpUrl: "https://" + modEP.Host},
		Manifest: &gatewayv1.Manifest{Module: "orders", DisplayName: "Orders", Version: "1.0.0", Prefixes: []string{"/api/orders"},
			Routes: []*gatewayv1.Route{{Method: "GET", Path: "/api/orders/ping", Public: true}}, Remote: &gatewayv1.Remote{Entry: "/m/orders/mf-manifest.json", Exposes: []string{"./routes"}}}}); err != nil {
		b.Fatal(err)
	}
	srv, err := httpapi.New(gwRT, edge.Config{Addr: "127.0.0.1:0", Env: "test", RateLimit: edge.RateLimit{PerSecond: 1e9, Burst: 1e9}})
	if err != nil {
		b.Fatal(err)
	}
	srv.SetForwarder(&httpapi.Dispatcher{Reg: reg, NotOwned: srv.NotOwned, Proxies: func(module string, id fidentity.SPIFFEID, target string) (httpapi.Backend, error) {
		return httpproxy.New(gwRT, httpproxy.Options{Module: module, Identity: id, Target: target})
	}})
	stopGW := startServer(b, srv)
	defer stopGW()
	gwEP, _ := srv.Edge().Endpoint()

	orders, _ := fidentity.NewSPIFFEID("example.org", "orders")
	directTLS, err := tlsconf.ClientConfig(gwRT.Provider(), orders, tlsconf.Options{TrustDomain: "example.org"})
	if err != nil {
		b.Fatal(err)
	}
	direct := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: directTLS, MaxIdleConnsPerHost: 2000, ForceAttemptHTTP2: true}}
	via := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}, MaxIdleConnsPerHost: 2000, ForceAttemptHTTP2: true}} //nolint:gosec // dev cert
	get := func(c *http.Client, url string) time.Duration {
		start := time.Now()
		resp, err := c.Get(url)
		if err != nil {
			b.Error(err)
			return 0
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return time.Since(start)
	}
	// Warm up connections.
	for i := 0; i < 50; i++ {
		get(via, "https://"+gwEP.Host+"/api/orders/ping")
		get(direct, "https://"+modEP.Host+"/api/orders/ping")
	}
	const concurrency = 1000
	run := func(c *http.Client, url string, n int) []time.Duration {
		var mu sync.Mutex
		var out []time.Duration
		var wg sync.WaitGroup
		sem := make(chan struct{}, concurrency)
		for i := 0; i < n; i++ {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				d := get(c, url)
				<-sem
				mu.Lock()
				out = append(out, d)
				mu.Unlock()
			}()
		}
		wg.Wait()
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		return out
	}
	p95 := func(d []time.Duration) time.Duration {
		if len(d) == 0 {
			return 0
		}
		return d[len(d)*95/100]
	}
	b.ResetTimer()
	viaLat := run(via, "https://"+gwEP.Host+"/api/orders/ping", b.N)
	b.StopTimer()
	directLat := run(direct, "https://"+modEP.Host+"/api/orders/ping", b.N)
	overhead := p95(viaLat) - p95(directLat)
	if overhead < 0 {
		overhead = 0
	}
	b.ReportMetric(float64(overhead.Microseconds())/1000, "p95_ms")
	b.ReportMetric(float64(p95(viaLat).Microseconds())/1000, "p95_via_ms")
	b.ReportMetric(float64(p95(directLat).Microseconds())/1000, "p95_direct_ms")
}
