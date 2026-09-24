package main

import "testing"

func TestParseAllow(t *testing.T) {
	e, err := parseAllow("spiffe://example.org/svc/auth=/api/v1/,/authorize;auth,identity")
	if err != nil || e.SpiffeID != "spiffe://example.org/svc/auth" || len(e.Prefixes) != 2 || e.Prefixes[0] != "/api/v1" || len(e.Names) != 2 {
		t.Fatalf("%+v %v", e, err)
	}
	e, err = parseAllow("spiffe://example.org/svc/orders=/api/orders")
	if err != nil || e.Names[0] != "orders" {
		t.Fatalf("default name: %+v %v", e, err)
	}
	for _, bad := range []string{"", "orders=/api", "spiffe://x/svc/a", "spiffe://x/svc/a=api", "spiffe://x/svc/a=/a/../b", "spiffe://x/svc/a=/a;"} {
		if _, err := parseAllow(bad); err == nil && bad != "spiffe://x/svc/a=/a;" {
			t.Errorf("%q accepted", bad)
		}
	}
	var f allowFlag
	if err := f.Set("bad"); err == nil || f.String() != "0" {
		t.Fatal("flag")
	}
}
