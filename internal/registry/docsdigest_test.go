package registry

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
)

const (
	docsA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	docsB = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752"
)

func TestValidDocsDigest(t *testing.T) {
	cases := map[string]bool{
		"":                           true,
		docsA:                        true,
		strings.ToUpper(docsA):       false,
		docsA[:63]:                   false,
		docsA + "0":                  false,
		"z" + docsA[1:]:              false,
		" " + docsA[1:]:              false,
		"sha256:" + docsA[7:]:        false,
		string(make([]byte, 64)):     false,
		strings.Repeat("0", 64):      true,
		strings.Repeat("f", 64):      true,
		strings.Repeat("ab", 32)[1:]: false,
	}
	for in, want := range cases {
		if got := ValidDocsDigest(in); got != want {
			t.Errorf("ValidDocsDigest(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestMalformedDocsDigestIsRefused(t *testing.T) {
	h := newHarness(t)
	r := req("orders", "1.0.0", "i1", []string{"/api/orders"})
	r.DocsDigest = strings.ToUpper(docsA)
	_, err := h.reg.Register(h.ctx, idOrders, r)
	if code(err) != codes.InvalidArgument || reason(err) != ReasonDocsDigestInvalid {
		t.Fatalf("got %v", err)
	}
	if _, ok := h.reg.Get("orders"); ok {
		t.Fatal("refused registration was recorded")
	}
	if n := h.auditCount(t, audit.RegistrationRefused, ReasonDocsDigestInvalid); n != 1 {
		t.Fatalf("refusal audit records %d", n)
	}
}

// A documentation change alone (same manifest, new docs_digest) is not a
// manifest drift: the re-registration is accepted, the new digest is stored
// and an "updated" event is announced.
func TestDocsDigestChangeIsNotADrift(t *testing.T) {
	h := newHarness(t)
	r1 := req("orders", "1.0.0", "i1", []string{"/api/orders"})
	r1.DocsDigest = docsA
	if _, err := h.reg.Register(h.ctx, idOrders, r1); err != nil {
		t.Fatal(err)
	}
	before, _ := h.reg.Get("orders")
	if before.Instances["i1"].DocsDigest != docsA || !reflect.DeepEqual(before.DocsDigests(), []string{docsA}) {
		t.Fatalf("%+v", before)
	}
	events, stop := h.reg.Watch(h.reg.Version())
	defer stop()

	// The same instance restarts with edited documentation; the manifest
	// (and its version) is unchanged.
	r1.DocsDigest = docsB
	lease, err := h.reg.Register(h.ctx, idOrders, r1)
	if err != nil {
		t.Fatalf("a docs change with the same manifest must not drift: %v", err)
	}
	if _, err := h.reg.Renew(h.ctx, idOrders, lease.ID); err != nil {
		t.Fatalf("renewal after a docs change: %v", err)
	}
	after, _ := h.reg.Get("orders")
	if after.Hash != before.Hash || after.Manifest.Version != "1.0.0" {
		t.Fatalf("manifest changed: %s/%s → %s/%s", before.Hash, before.Manifest.Version, after.Hash, after.Manifest.Version)
	}
	if after.Instances["i1"].DocsDigest != docsB || !reflect.DeepEqual(after.DocsDigests(), []string{docsB}) {
		t.Fatalf("new digest not stored: %+v", after.Instances)
	}
	select {
	case ev := <-events:
		if ev.Kind != EventUpdated || ev.Module != "orders" {
			t.Fatalf("event %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no event for the re-registration")
	}

	// A rollout: a second instance still on the old docs; an instance
	// without documentation contributes nothing.
	r2 := req("orders", "1.0.0", "i2", []string{"/api/orders"})
	r2.DocsDigest = docsA
	if _, err := h.reg.Register(h.ctx, idOrders, r2); err != nil {
		t.Fatal(err)
	}
	if _, err := h.reg.Register(h.ctx, idOrders, req("orders", "1.0.0", "i3", []string{"/api/orders"})); err != nil {
		t.Fatal(err)
	}
	got, _ := h.reg.Get("orders")
	if dd := got.DocsDigests(); !reflect.DeepEqual(dd, []string{docsB, docsA}) {
		t.Fatalf("rollout digests %v", dd)
	}

	// It survives the KV round trip (another gateway instance loads it).
	other, err := New(Options{KV: h.kv, Allow: h.ms, Marks: h.ms, Now: h.clk.now, Origin: "gw-b"})
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Load(h.ctx); err != nil {
		t.Fatal(err)
	}
	if o, _ := other.Get("orders"); o.Instances["i1"].DocsDigest != docsB || o.Instances["i2"].DocsDigest != docsA || o.Instances["i3"].DocsDigest != "" {
		t.Fatalf("persisted digests %+v", o.Instances)
	}
	h.aw.Close()
	found := false
	for _, r := range h.ms.Audit() {
		if r.EventType == string(audit.RegistrationAccepted) && strings.Contains(string(r.Details), `"docs_digest":"`+docsB+`"`) {
			found = true
		}
	}
	if !found {
		t.Fatal("registration audit must carry the docs digest")
	}
}
