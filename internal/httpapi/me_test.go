package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-portal/v4/internal/identity"
	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"
)

type fixedIdentity struct{ id identity.Identity }

func (f fixedIdentity) Resolve(context.Context, *http.Request) (identity.Identity, error) {
	return f.id, nil
}

// TestMeCarriesProfile: /gateway/v1/me exposes display name and avatar from
// the session identity (feature 004), never a phone number.
func TestMeCarriesProfile(t *testing.T) {
	s, err := NewHandler(testrt.New(t, testutil.MustCA("example.org"), "gateway"))
	if err != nil {
		t.Fatal(err)
	}
	s.RegisterMe(fixedIdentity{id: identity.Identity{UserID: "u1", TenantID: "t1", SessionID: "s1", Roles: []string{"member", "auditor"}, Source: "session",
		ExpiresAt: time.Now().Add(time.Hour), DisplayName: "Dana Kovač", AvatarURL: "/api/v1/users/u1/avatar/abc"}})
	w := do(s, "GET", "/gateway/v1/me", "", nil)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var me map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &me)
	if me["display_name"] != "Dana Kovač" || me["avatar_url"] != "/api/v1/users/u1/avatar/abc" || len(me["roles"].([]any)) != 2 {
		t.Fatalf("%v", me)
	}
	if _, ok := me["phone"]; ok {
		t.Fatal("phone must never be exposed")
	}
}
