package contract

import (
	"encoding/json"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/pkg/authmanifest"
	"github.com/go-tangra/go-tangra-portal/v4/internal/manifest"
	"github.com/go-tangra/go-tangra-portal/v4/internal/route"
)

// The auth module's manifest must satisfy the published schema and rules.
func TestAuthManifestIsValid(t *testing.T) {
	m, err := authmanifest.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	pm, err := m.Proto()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := manifest.FromProto(pm)
	if err != nil {
		t.Fatalf("auth manifest refused: %v", err)
	}
	raw, _ := json.Marshal(parsed)
	if _, err := manifest.Parse(raw); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Prefixes) != 4 || parsed.Remote.Entry != "/m/auth/mf-manifest.json" {
		t.Fatalf("%+v", parsed)
	}
}

func TestAuthManifestRoutesResolve(t *testing.T) {
	m, _ := authmanifest.Manifest()
	pm, _ := m.Proto()
	parsed, err := manifest.FromProto(pm)
	if err != nil {
		t.Fatal(err)
	}
	tb, err := route.Build([]route.Module{{Name: "auth", State: "active", Manifest: parsed}})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/api/v1/tenants/resolve", "/api/v1/session", "/console", "/console/admin/users", "/.well-known/jwks.json"} {
		if _, ok := tb.Match("GET", p); !ok {
			t.Errorf("%s not matched", p)
		}
	}
}
