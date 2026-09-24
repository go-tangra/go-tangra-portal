package contract

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-portal/v4/api/openapi"
	"github.com/go-tangra/go-tangra-portal/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"
)

const specOpenAPI = "../../../../specs/003-application-gateway/contracts/gateway-api.openapi.yaml"

func TestOpenAPIParsesAndEveryRouteIsMounted(t *testing.T) {
	doc, err := httpapi.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	if spec, err := os.ReadFile(specOpenAPI); err == nil && !bytes.Equal(bytes.TrimSpace(spec), bytes.TrimSpace(openapi.Gateway)) {
		t.Fatal("api/openapi/gateway.yaml drifted from the specification contract")
	}
	rt := testrt.New(t, testutil.MustCA("example.org"), "gateway")
	s, err := httpapi.NewHandler(rt)
	if err != nil {
		t.Fatal(err)
	}
	routes := httpapi.DeclaredRoutes(doc)
	if len(routes) == 0 {
		t.Fatal("no routes")
	}
	for _, rt := range routes {
		p := strings.NewReplacer("{module}", "orders", "{asset}", "mf-manifest.json", "{id}", "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55").Replace(rt.Path)
		r := httptest.NewRequest(rt.Method, "https://localhost"+p, nil)
		if rt.Method != http.MethodGet {
			r.Header.Set("X-CSRF-Token", "x")
			r.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code == 404 || w.Code == 405 {
			t.Errorf("%s not mounted: %d", rt, w.Code)
		}
	}
}
