package grpcapi

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	inventoryv1 "github.com/go-tangra/go-tangra-inventory/sdk/v4/api/proto/inventory/v1"
	fwcat "github.com/go-tangra/go-tangra/v4/catalogue"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	catsvc "github.com/go-tangra/go-tangra-portal/v4/internal/catalogue"
	"github.com/go-tangra/go-tangra-portal/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

const (
	renderJTI    = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	renderHost   = "0190f7c2-6a3e-7c1a-9b2e-000000000001"
	renderTenant = "0190f7c2-6a3e-7c1a-9b2e-0000000000aa"
	renderJoin   = "0190f7c2-6a3e-7c1a-9b2e-0000000000j1"
)

type mint struct {
	got []*authv1.MintEnrollmentTokenRequest
}

func (m *mint) MintEnrollmentToken(_ context.Context, in *authv1.MintEnrollmentTokenRequest, _ ...grpc.CallOption) (*authv1.MintEnrollmentTokenResponse, error) {
	m.got = append(m.got, in)
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return &authv1.MintEnrollmentTokenResponse{Token: enc(`{"alg":"EdDSA"}`) + "." + enc(`{"jti":"`+renderJTI+`"}`) + ".sig",
		ExpiresAt: timestamppb.New(time.Now().Add(time.Duration(in.GetTtlSeconds()) * time.Second))}, nil
}

type bundleStream struct {
	grpc.ServerStream
	ctx context.Context
	got []*inventoryv1.ModuleBundleChunk
}

func (s *bundleStream) Context() context.Context { return s.ctx }

// Send copies like gRPC's serialisation: the server zeroes the bundle after.
func (s *bundleStream) Send(c *inventoryv1.ModuleBundleChunk) error {
	s.got = append(s.got, proto.Clone(c).(*inventoryv1.ModuleBundleChunk))
	return nil
}

type renderEnv struct {
	srv  *ModuleBundleServer
	ms   *memstore.Store
	aw   *audit.Writer
	mint *mint
}

func newRenderEnv(t *testing.T) *renderEnv {
	t.Helper()
	ms := memstore.New()
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	bundle, err := fwcat.PackBundle(fstest.MapFS{"config.yaml": {Data: []byte("host: ${MODULE_ADVERTISE_HOST}\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	d := fwcat.Descriptor{Schema: 1, Module: "sms-gw", DisplayName: "SMS", Image: "ghcr.io/go-tangra/go-tangra-sms-gw",
		Routes: fwcat.Routes{Prefixes: []string{"/api/sms-gw"}, Names: []string{"sms-gw"}}, Bundle: fwcat.BundleSpec{Dir: "deploy/bundle", Templates: []string{"config.yaml"}},
		HostInputs: []fwcat.HostInput{{Key: "MODULE_ADVERTISE_HOST", Label: "host", Pattern: `^[a-z0-9.-]+$`}}}
	e, err := fwcat.BuildEntry(d, "4.3.0", "go-tangra/go-tangra-sms-gw", nil, bundle)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := e.Marshal()
	_ = ms.InsertEntry(context.Background(), store.CatalogueEntry{Module: "sms-gw", Version: "4.3.0", Entry: raw, Bundle: bundle})
	now := time.Now().UTC()
	_ = ms.InsertJoin(context.Background(), store.CatalogueJoin{ID: renderJoin, Module: "sms-gw", Version: "4.3.0", MintedBy: "op1", CreatedAt: now,
		ExpiresAt: now.Add(6 * time.Hour), Channel: store.JoinAgent, TenantID: renderTenant, HostID: renderHost, Inputs: map[string]string{"MODULE_ADVERTISE_HOST": "pbx1.example.org"}})
	m := &mint{}
	core := map[string]string{"TRUST_DOMAIN": "example.org", "GATEWAY_ISSUER": "https://p.example.org", "LCM_ENROLL_URL": "https://p.example.org/enroll",
		"AUTH_GRPC": "p:1", "GATEWAY_GRPC": "p:2", "LCM_GRPC": "p:3", "MESH_TENANT_ID": "00000000-0000-0000-0000-000000000001"}
	srv := &ModuleBundleServer{Caller: "spiffe://example.org/svc/inventory", Joins: ms, Events: aw,
		Builder: &catsvc.Builder{TrustDomain: "example.org", Core: core, Bundle: ms.EntryBundle, Mint: m,
			MeshCA: func(context.Context) ([]byte, error) {
				return []byte("-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n"), nil
			}}}
	return &renderEnv{srv: srv, ms: ms, aw: aw, mint: m}
}

func renderReq() *inventoryv1.RenderModuleBundleRequest {
	return &inventoryv1.RenderModuleBundleRequest{TenantId: renderTenant, DeliveryId: renderJoin, HostId: renderHost, ItemId: "item-1"}
}

// The inventory fetches an agent join: rendered then, token minted then,
// streamed as header + chunks, JTI recorded, audited without material.
func TestRenderModuleBundle(t *testing.T) {
	e := newRenderEnv(t)
	st := &bundleStream{ctx: peerCtx("inventory")}
	if err := e.srv.RenderModuleBundle(renderReq(), st); err != nil {
		t.Fatal(err)
	}
	h := st.got[0].GetHeader()
	var zipped []byte
	for _, c := range st.got[1:] {
		if c.GetChunk().GetOffset() != int64(len(zipped)) {
			t.Fatal("offsets not contiguous")
		}
		zipped = append(zipped, c.GetChunk().GetData()...)
	}
	sum := sha256.Sum256(zipped)
	if h == nil || h.GetModule() != "sms-gw" || h.GetVersion() != "4.3.0" || h.GetSize() != int64(len(zipped)) || h.GetSha256() != hex.EncodeToString(sum[:]) ||
		h.GetDeliveryId() != renderJoin || h.GetItemId() != "" {
		t.Fatalf("%+v", h)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipped), int64(len(zipped)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if f.Name == "sms-gw/config.yaml" {
			rc, _ := f.Open()
			b, _ := io.ReadAll(rc)
			if string(b) != "host: pbx1.example.org\n" {
				t.Fatalf("%q", b)
			}
		}
	}
	// The token lives until the join expires (≈ 6 h), names only the module.
	if len(e.mint.got) != 1 || e.mint.got[0].GetSpiffePaths()[0] != "spiffe://example.org/svc/sms-gw" || e.mint.got[0].GetTtlSeconds() > 6*3600 || e.mint.got[0].GetTtlSeconds() < 6*3600-60 {
		t.Fatalf("%+v", e.mint.got)
	}
	if j := e.ms.Joins[renderJoin]; j.JTI != renderJTI || j.Renders != 1 {
		t.Fatalf("%+v", j)
	}
	e.aw.Close()
	var ok bool
	for _, r := range e.ms.Audit() {
		if strings.Contains(string(r.Details), "sig") || strings.Contains(string(r.Details), "GEN_") {
			t.Fatal("material in audit")
		}
		ok = ok || (r.EventType == string(audit.ModuleBundleRendered) && r.Outcome == "ok")
	}
	if !ok {
		t.Fatal("render not audited")
	}
}

func TestRenderModuleBundleRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		ctx  context.Context
		prep func(e *renderEnv, r *inventoryv1.RenderModuleBundleRequest)
		want codes.Code
	}{
		"no peer":       {context.Background(), nil, codes.Unauthenticated},
		"other service": {peerCtx("deployer"), nil, codes.PermissionDenied},
		"unknown join":  {peerCtx("inventory"), func(_ *renderEnv, r *inventoryv1.RenderModuleBundleRequest) { r.DeliveryId = "nope" }, codes.NotFound},
		"other host":    {peerCtx("inventory"), func(_ *renderEnv, r *inventoryv1.RenderModuleBundleRequest) { r.HostId = "other" }, codes.NotFound},
		"other tenant":  {peerCtx("inventory"), func(_ *renderEnv, r *inventoryv1.RenderModuleBundleRequest) { r.TenantId = "other" }, codes.NotFound},
		"download join": {peerCtx("inventory"), func(e *renderEnv, _ *inventoryv1.RenderModuleBundleRequest) {
			j := e.ms.Joins[renderJoin]
			j.Channel = store.JoinDownload
			e.ms.Joins[renderJoin] = j
		}, codes.NotFound},
		"expired": {peerCtx("inventory"), func(e *renderEnv, _ *inventoryv1.RenderModuleBundleRequest) {
			j := e.ms.Joins[renderJoin]
			j.ExpiresAt = time.Now().Add(-time.Minute)
			e.ms.Joins[renderJoin] = j
		}, codes.NotFound},
		"budget spent": {peerCtx("inventory"), func(e *renderEnv, _ *inventoryv1.RenderModuleBundleRequest) {
			j := e.ms.Joins[renderJoin]
			j.Renders = store.MaxJoinRenders
			e.ms.Joins[renderJoin] = j
		}, codes.NotFound},
	} {
		t.Run(name, func(t *testing.T) {
			e := newRenderEnv(t)
			r := renderReq()
			if tc.prep != nil {
				tc.prep(e, r)
			}
			st := &bundleStream{ctx: tc.ctx}
			if err := e.srv.RenderModuleBundle(r, st); status.Code(err) != tc.want {
				t.Fatalf("%v", err)
			}
			if len(st.got) != 0 || len(e.mint.got) != 0 {
				t.Fatal("a refused render sent data or minted a token")
			}
		})
	}
}

// Five renders at most, then NotFound.
func TestRenderModuleBundleBudget(t *testing.T) {
	e := newRenderEnv(t)
	for i := 0; i < store.MaxJoinRenders; i++ {
		if err := e.srv.RenderModuleBundle(renderReq(), &bundleStream{ctx: peerCtx("inventory")}); err != nil {
			t.Fatalf("render %d: %v", i+1, err)
		}
	}
	if err := e.srv.RenderModuleBundle(renderReq(), &bundleStream{ctx: peerCtx("inventory")}); status.Code(err) != codes.NotFound {
		t.Fatalf("sixth render: %v", err)
	}
}
