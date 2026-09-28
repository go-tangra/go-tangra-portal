package console

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"
	fidentity "github.com/go-tangra/go-tangra/v4/identity"
	thttp "github.com/go-tangra/go-tangra/v4/transport/http"
)

// The console relays a WebSocket over the real mesh: the gateway's pinned
// mTLS client (whose ALPN offers only h2) to a module's framework HTTP server.
// Go's transport dials upgrades over HTTP/1.1, which the module serves and
// lets its handler hijack — exactly what ipam's /bmc/{id}/__kvmws needs.
func TestWebSocketOverTheMesh(t *testing.T) {
	ca := testutil.MustCA("example.org")
	modRT := testrt.New(t, ca, "ipam")
	srv, err := thttp.NewServer(modRT, thttp.WithAddress("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	var cookies atomic.Value
	srv.HandlePrefix("/bmc/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookies.Store(r.Header.Values("Cookie"))
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			_, _ = io.WriteString(w, "asset over "+r.Proto)
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Time{})
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = rw.Flush()
		_, _ = io.Copy(conn, rw)
	}))
	t.Cleanup(testrt.StartServer(t, srv))
	ep, _ := srv.Endpoint()

	id, _ := fidentity.NewSPIFFEID("example.org", "ipam")
	reg := &fakeReg{state: map[string]registry.State{fwdModule: registry.StateActive}, id: map[string]string{fwdModule: id.String()},
		backends: map[string][]registry.Instance{fwdModule: {{ID: "a", Backend: registry.Backend{HTTPURL: "https://" + ep.Host}}}}}
	gw := testrt.New(t, ca, "gateway")
	hs := newHarness(t, reg, func(o *Options) {
		o.Transport = func(_ string, id fidentity.SPIFFEID) (http.RoundTripper, error) {
			c, err := thttp.NewClient(gw, id)
			if err != nil {
				return nil, err
			}
			return c.Transport, nil
		}
	})

	resp, err := http.Get(hs.front.URL + "/bmc/dev1/app.js")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(string(body), "asset over HTTP/") {
		t.Fatalf("asset: %d %q", resp.StatusCode, body)
	}

	conn, br, up := dialUpgrade(t, hs.front.URL)
	defer conn.Close()
	if up.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade over the mesh: %d", up.StatusCode)
	}
	if c, _ := cookies.Load().([]string); len(c) != 1 || c[0] != "freya_kvm=k" {
		t.Fatalf("cookies at the module: %q", c)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "kvm-frame"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("kvm-frame"))
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "kvm-frame" {
		t.Fatalf("echo over the mesh %q %v", buf, err)
	}
}
