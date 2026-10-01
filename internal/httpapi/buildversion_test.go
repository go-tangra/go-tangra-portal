package httpapi

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	gatewayv1 "github.com/go-tangra/go-tangra-portal/sdk/v4/api/proto/gateway/v1"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
)

// reRegister adds (or replaces) an instance of a registered module with the
// module's current manifest and the given build version.
func reRegister(t *testing.T, reg *registry.Registry, module, instance, build string) {
	t.Helper()
	cur, ok := reg.Get(module)
	if !ok {
		t.Fatalf("%s not registered", module)
	}
	m := cur.Manifest
	pm := &gatewayv1.Manifest{Module: m.Module, DisplayName: m.DisplayName, Version: m.Version, Prefixes: m.Prefixes,
		Remote: &gatewayv1.Remote{Entry: m.Remote.Entry, Exposes: m.Remote.Exposes}}
	for _, r := range m.Routes {
		pm.Routes = append(pm.Routes, &gatewayv1.Route{Method: r.Method, Path: r.Path, Permission: r.Permission, Public: r.Public})
	}
	for _, p := range m.Permissions {
		pm.Permissions = append(pm.Permissions, &gatewayv1.Permission{Resource: p.Resource, Action: p.Action})
	}
	for _, a := range m.Abilities {
		pm.Abilities = append(pm.Abilities, &gatewayv1.Ability{Action: a.Action, Subject: a.Subject, Requires: a.Requires})
	}
	for _, n := range m.Nav {
		pm.Nav = append(pm.Nav, &gatewayv1.NavEntry{Title: n.Title, Path: n.Path, Icon: n.Icon, Order: int32(n.Order), Requires: n.Requires})
	}
	if _, err := reg.Register(context.Background(), cur.Identity, &gatewayv1.RegisterRequest{InstanceId: instance, BuildVersion: build,
		Backend: &gatewayv1.Backend{HttpUrl: "https://" + module}, Manifest: pm}); err != nil {
		t.Fatalf("re-register %s/%s: %v", module, instance, err)
	}
}

func modulesByName(t *testing.T, s *Server) map[string]ModuleView {
	t.Helper()
	w := do(s, "GET", "/gateway/v1/me/modules", "", map[string]string{"Authorization": "Bearer ok"})
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var mods []ModuleView
	if err := json.Unmarshal(w.Body.Bytes(), &mods); err != nil {
		t.Fatal(err)
	}
	out := map[string]ModuleView{}
	for _, m := range mods {
		out[m.Module] = m
	}
	return out
}

func TestModulesReportBuildVersion(t *testing.T) {
	s, reg, _, _ := shellServer(t)
	// Modules that do not report a build version (older SDK) expose none,
	// never the manifest contract version in its place.
	mods := modulesByName(t, s)
	if o := mods["orders"]; o.Version != "1.0.0" || o.BuildVersion != "" || o.BuildVersions == nil || len(o.BuildVersions) != 0 {
		t.Fatalf("unreported build version: %+v", o)
	}
	reRegister(t, reg, "orders", "i1", "v4.10.1")
	reRegister(t, reg, "orders", "i2", "4.10.2")
	reRegister(t, reg, "billing", "i1", "4.3.1")
	mods = modulesByName(t, s)
	if o := mods["orders"]; o.Version != "1.0.0" || o.BuildVersion != "4.10.2" || !reflect.DeepEqual(o.BuildVersions, []string{"4.10.1", "4.10.2"}) {
		t.Fatalf("rollout: %+v", o)
	}
	if b := mods["billing"]; b.BuildVersion != "4.3.1" {
		t.Fatalf("billing: %+v", b)
	}
}

func TestOpsRegistrationsReportBuildVersions(t *testing.T) {
	s, reg, _, _ := opsServer(t)
	reRegister(t, reg, "orders", "i1", "4.6.2")
	w := do(s, "GET", "/gateway/v1/ops/registrations", "", map[string]string{"Authorization": "Bearer operator"})
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var page struct {
		Items []RegistrationView `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || !reflect.DeepEqual(page.Items[0].BuildVersions, []string{"4.6.2"}) || page.Items[0].Manifest["version"] != "1.0.0" {
		t.Fatalf("%+v", page.Items)
	}
}
