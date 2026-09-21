package fuzz

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	gatewayv1 "github.com/go-freya/freya/services/gateway/api/proto/gateway/v1"
	"github.com/go-freya/freya/services/gateway/internal/memstore"
	"github.com/go-freya/freya/services/gateway/internal/registry"
	"github.com/go-freya/freya/services/gateway/internal/store"
)

func FuzzRegisterRequest(f *testing.F) {
	valid, _ := proto.Marshal(&gatewayv1.RegisterRequest{InstanceId: "i1", Backend: &gatewayv1.Backend{HttpUrl: "https://127.0.0.1:1"},
		Manifest: &gatewayv1.Manifest{Module: "orders", DisplayName: "Orders", Version: "1.0.0", Prefixes: []string{"/api/orders"},
			Routes: []*gatewayv1.Route{{Method: "GET", Path: "/api/orders", Public: true}}, Remote: &gatewayv1.Remote{Entry: "/m/orders/mf-manifest.json", Exposes: []string{"./routes"}}}})
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff})
	f.Fuzz(func(t *testing.T, raw []byte) {
		var req gatewayv1.RegisterRequest
		if err := proto.Unmarshal(raw, &req); err != nil {
			return
		}
		ctx := context.Background()
		ms := memstore.New()
		_ = ms.InsertAllow(ctx, store.AllowEntry{ID: "a", SpiffeID: "spiffe://example.org/svc/orders", Prefixes: []string{"/api/orders"}, Names: []string{"orders"}})
		reg, err := registry.New(registry.Options{KV: registry.NewMemory(), Allow: ms, Marks: ms})
		if err != nil {
			t.Fatal(err)
		}
		lease, err := reg.Register(ctx, "spiffe://example.org/svc/orders", &req)
		if err != nil {
			return
		}
		got, ok := reg.Get(lease.Module)
		if !ok || got.Manifest.Module != "orders" || len(got.Manifest.Prefixes) == 0 {
			t.Fatalf("registered something other than a valid orders manifest: %+v", got)
		}
		for _, r := range got.Manifest.Routes {
			if r.Public == (r.Permission != "") {
				t.Fatalf("unprotected route registered: %+v", r)
			}
		}
	})
}
