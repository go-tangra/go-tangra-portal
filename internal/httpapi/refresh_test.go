package httpapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	fidentity "github.com/go-freya/freya/identity"
	"github.com/go-freya/freya/services/gateway/internal/identity"
)

// headerBackend echoes a fixed response header (the auth module's refresh hint)
// and reports whether the inbound request still carried it.
type headerBackend struct {
	target string
	set    string
	sawIn  bool
}

func (h *headerBackend) Target() string { return h.target }
func (h *headerBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, _ = io.ReadAll(r.Body)
	if r.Header.Get(IdentityRefreshHeader) != "" {
		h.sawIn = true
	}
	if h.set != "" {
		w.Header().Set(IdentityRefreshHeader, h.set)
	}
	w.WriteHeader(200)
	_, _ = io.WriteString(w, "ok")
}

// TestIdentityRefreshRelay: a refresh hint on a response from the auth module
// drops the cached identity of the cookie; the header never reaches the
// browser, is dropped inbound, and is ignored from any other module.
func TestIdentityRefreshRelay(t *testing.T) {
	d, _, _, _ := newDispatcher(t)
	var dropped []string
	d.AuthModule = "orders" // the module whose responses may carry the hint
	d.OnIdentityRefresh = func(_ context.Context, cookie string) { dropped = append(dropped, cookie) }
	hb := &headerBackend{set: "1"}
	d.Proxies = func(module string, _ fidentity.SPIFFEID, target string) (Backend, error) {
		hb.target = target
		return hb, nil
	}
	r := httptest.NewRequest("GET", "https://platform/api/orders/ping", nil)
	r.AddCookie(&http.Cookie{Name: identity.SessionCookie, Value: "cookie-1"})
	r.Header.Set(IdentityRefreshHeader, "1") // forged by the browser: dropped inbound
	w := httptest.NewRecorder()
	d.ServeHTTP(w, r)
	if w.Code != 200 || len(dropped) != 1 || dropped[0] != "cookie-1" {
		t.Fatalf("%d dropped=%v", w.Code, dropped)
	}
	if w.Header().Get(IdentityRefreshHeader) != "" {
		t.Fatal("hint must be stripped from the browser response")
	}
	if hb.sawIn {
		t.Fatal("inbound header must be dropped before forwarding")
	}
	// No hint, no drop; a hint from a non-auth module is ignored.
	hb.set = ""
	d.ServeHTTP(httptest.NewRecorder(), r)
	if len(dropped) != 1 {
		t.Fatal("no hint must not drop")
	}
	hb.set = "1"
	d.AuthModule = "somebody-else"
	d.ServeHTTP(httptest.NewRecorder(), r)
	if len(dropped) != 1 {
		t.Fatal("hint from a non-auth module must be ignored")
	}
	// No cookie: nothing to drop, even with the hint.
	d.AuthModule = "orders"
	r2 := httptest.NewRequest("GET", "https://platform/api/orders/ping", nil)
	d.ServeHTTP(httptest.NewRecorder(), r2)
	if len(dropped) != 1 {
		t.Fatal("no cookie must not drop")
	}
}
