package registry

import (
	"reflect"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
)

func TestCleanBuildVersion(t *testing.T) {
	cases := map[string]string{
		"4.10.2":                 "4.10.2",
		" v4.10.2 ":              "4.10.2",
		"4.10.2-rc.1+abc":        "4.10.2-rc.1+abc",
		"dev":                    "dev",
		"v":                      "v",
		"":                       "",
		"4.1.0 <script>":         "",
		"4.1.0\n":                "4.1.0",
		string(make([]byte, 65)): "",
	}
	for in, want := range cases {
		if got := CleanBuildVersion(in); got != want {
			t.Errorf("CleanBuildVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildVersionIsPerInstanceAndNotADrift(t *testing.T) {
	h := newHarness(t)
	r1 := req("orders", "1.0.0", "i1", []string{"/api/orders"})
	r1.BuildVersion = "v4.10.1"
	if _, err := h.reg.Register(h.ctx, idOrders, r1); err != nil {
		t.Fatal(err)
	}
	// Same manifest, newer release on a second instance: accepted, no drift,
	// manifest (contract) version unchanged.
	r2 := req("orders", "1.0.0", "i2", []string{"/api/orders"})
	r2.BuildVersion = "4.10.2"
	if _, err := h.reg.Register(h.ctx, idOrders, r2); err != nil {
		t.Fatalf("a new build with the same manifest must not drift: %v", err)
	}
	got, _ := h.reg.Get("orders")
	if got.Manifest.Version != "1.0.0" || got.Instances["i1"].BuildVersion != "4.10.1" || got.Instances["i2"].BuildVersion != "4.10.2" {
		t.Fatalf("%+v", got)
	}
	if bv := got.BuildVersions(); !reflect.DeepEqual(bv, []string{"4.10.1", "4.10.2"}) {
		t.Fatalf("rollout versions %v", bv)
	}
	// The old instance restarts on the new release; an instance without a
	// build version (older SDK) contributes nothing.
	r1.BuildVersion = "4.10.2"
	if _, err := h.reg.Register(h.ctx, idOrders, r1); err != nil {
		t.Fatal(err)
	}
	if _, err := h.reg.Register(h.ctx, idOrders, req("orders", "1.0.0", "i3", []string{"/api/orders"})); err != nil {
		t.Fatal(err)
	}
	got, _ = h.reg.Get("orders")
	if bv := got.BuildVersions(); !reflect.DeepEqual(bv, []string{"4.10.2"}) {
		t.Fatalf("converged versions %v", bv)
	}
	// It survives the KV round trip (another gateway instance loads it).
	other, err := New(Options{KV: h.kv, Allow: h.ms, Marks: h.ms, Now: h.clk.now, Origin: "gw-b"})
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Load(h.ctx); err != nil {
		t.Fatal(err)
	}
	if o, _ := other.Get("orders"); !reflect.DeepEqual(o.BuildVersions(), []string{"4.10.2"}) {
		t.Fatalf("persisted versions %v", o.BuildVersions())
	}
	h.aw.Close()
	found := false
	for _, r := range h.ms.Audit() {
		if r.EventType == string(audit.RegistrationAccepted) && strings.Contains(string(r.Details), `"build_version":"4.10.2"`) {
			found = true
		}
	}
	if !found {
		t.Fatal("registration audit must carry the build version")
	}
}

func TestBuildVersionsOrder(t *testing.T) {
	reg := Registration{Instances: map[string]Instance{
		"a": {BuildVersion: "4.10.0"}, "b": {BuildVersion: "4.9.12"}, "c": {BuildVersion: "4.10.0"}, "d": {},
	}}
	if got := reg.BuildVersions(); !reflect.DeepEqual(got, []string{"4.9.12", "4.10.0"}) {
		t.Fatalf("%v", got)
	}
	if got := (Registration{}).BuildVersions(); got != nil {
		t.Fatalf("%v", got)
	}
}
