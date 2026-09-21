package httpapi

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-freya/freya/internal/testrt"
	"github.com/go-freya/freya/internal/testutil"
	"github.com/go-freya/freya/transport/edge"
)

// Limits at the edge come from configuration: per-route buckets, header and
// body caps; every refusal is uniform and carries Retry-After where relevant.
func TestEdgeLimits(t *testing.T) {
	rt := testrt.New(t, testutil.MustCA("example.org"), "gateway")
	rt.Lim.MaxRequestBytes = 128
	s, err := New(rt, edge.Config{Addr: "127.0.0.1:0", Env: "test", RateLimit: edge.RateLimit{PerSecond: 100, Burst: 100, Routes: map[string]edge.RateLimit{"/api/orders/expensive": {PerSecond: 1, Burst: 2}}}}, WithShell(shellFS))
	if err != nil {
		t.Fatal(err)
	}
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
	// Per-route bucket: burst 2 then 429 with Retry-After.
	codes := []int{}
	var last *http.Response
	for i := 0; i < 4; i++ {
		resp, err := client.Get(base + "/api/orders/expensive")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		codes = append(codes, resp.StatusCode)
		last = resp
	}
	if codes[0] != 204 || codes[1] != 204 || codes[3] != 429 || last.Header.Get("Retry-After") == "" {
		t.Fatalf("%v %v", codes, last.Header)
	}
	// Other routes keep their own budget.
	if resp, _ := client.Get(base + "/api/orders/cheap"); resp.StatusCode != 204 {
		t.Fatalf("cheap → %d", resp.StatusCode)
	}
	// Oversized headers → 431 from the server before any handler.
	req, _ := http.NewRequest(http.MethodGet, base+"/api/orders/cheap", nil)
	req.Header.Set("X-Big", strings.Repeat("a", 20000))
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
			t.Fatalf("big headers → %d", resp.StatusCode)
		}
	}
	// TLS 1.2 is refused by the edge.
	old := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}}} //nolint:gosec // probe
	if _, err := old.Get(base + "/api/orders/cheap"); err == nil {
		t.Fatal("TLS 1.2 accepted")
	}
	// Plaintext is refused.
	plain := &http.Client{Timeout: 2 * time.Second}
	if resp, err := plain.Get("http://" + ep.Host + "/api/orders/cheap"); err == nil && resp.StatusCode == 204 {
		t.Fatal("plaintext served")
	}
}
