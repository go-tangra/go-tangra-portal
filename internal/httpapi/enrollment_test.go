package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	"github.com/go-tangra/go-tangra-portal/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
)

// fakeEnroll records mint requests; err fails them. token overrides the
// minted token; consumed lists the JTIs TokenStatus reports as used.
type fakeEnroll struct {
	got      []*authv1.MintEnrollmentTokenRequest
	err      error
	token    string
	consumed map[string]time.Time
}

func (f *fakeEnroll) TokenStatus(_ context.Context, in *authv1.TokenStatusRequest, _ ...grpc.CallOption) (*authv1.TokenStatusResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	if at, ok := f.consumed[in.GetJti()]; ok {
		return &authv1.TokenStatusResponse{Consumed: true, ConsumedAt: timestamppb.New(at)}, nil
	}
	return &authv1.TokenStatusResponse{}, nil
}

func (f *fakeEnroll) MintEnrollmentToken(_ context.Context, in *authv1.MintEnrollmentTokenRequest, _ ...grpc.CallOption) (*authv1.MintEnrollmentTokenResponse, error) {
	f.got = append(f.got, in)
	if f.err != nil {
		return nil, f.err
	}
	if f.token != "" {
		return &authv1.MintEnrollmentTokenResponse{Token: f.token, ExpiresAt: timestamppb.New(time.Now().Add(time.Duration(in.GetTtlSeconds()) * time.Second))}, nil
	}
	return &authv1.MintEnrollmentTokenResponse{Token: "eyJ.enrol.token", ExpiresAt: timestamppb.New(time.Date(2026, 10, 7, 12, 30, 0, 0, time.UTC))}, nil
}

func (f *fakeEnroll) VerifyEnrollmentToken(context.Context, *authv1.VerifyEnrollmentTokenRequest, ...grpc.CallOption) (*authv1.VerifyEnrollmentTokenResponse, error) {
	return nil, errors.New("not used")
}

func enrollServer(t *testing.T, f *fakeEnroll) (*Server, *memstore.Store, *audit.Writer) {
	t.Helper()
	ms := memstore.New()
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	reg, _ := registry.New(registry.Options{KV: registry.NewMemory(), Allow: ms, Marks: ms, Audit: aw})
	s := newTestServer(t)
	s.RegisterOps(OpsDeps{Reg: reg, Ops: &registry.Ops{Reg: reg, Marks: ms, Allow: ms, Audit: aw}, Identity: opsIdentity{}, Audit: ms, Roles: []string{"operator"},
		Enroll: f, TrustDomain: "example.org", Events: aw})
	return s, ms, aw
}

var opHdr = map[string]string{"Authorization": "Bearer operator", "X-CSRF-Token": "x"}

// An operator mints a token for service names or ids of this trust domain:
// auth gets full SPIFFE ids, the mesh tenant and the TTL; the token comes back
// once (no-store); the mint is audited without the token.
func TestMintEnrollmentToken(t *testing.T) {
	f := &fakeEnroll{}
	s, ms, aw := enrollServer(t, f)
	w := do(s, "POST", "/gateway/v1/ops/enrollment-tokens", `{"services":["sms-gw"," spiffe://example.org/svc/notification ","sms-gw"],"ttl_seconds":1800}`, opHdr)
	if w.Code != 201 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var out EnrollmentToken
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Token != "eyJ.enrol.token" || out.ExpiresAt != "2026-10-07T12:30:00Z" || out.TenantID != MeshTenantID ||
		strings.Join(out.SpiffeIDs, ",") != "spiffe://example.org/svc/sms-gw,spiffe://example.org/svc/notification" {
		t.Fatalf("%+v", out)
	}
	if len(f.got) != 1 || f.got[0].GetTenantId() != MeshTenantID || f.got[0].GetTtlSeconds() != 1800 || len(f.got[0].GetSpiffePaths()) != 2 {
		t.Fatalf("mint request %+v", f.got)
	}
	// Defaults: mesh tenant, 10 minutes; an explicit tenant passes through.
	if w := do(s, "POST", "/gateway/v1/ops/enrollment-tokens", `{"services":["lcm"],"tenant_id":"0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"}`, opHdr); w.Code != 201 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if f.got[1].GetTtlSeconds() != 600 || f.got[1].GetTenantId() != "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55" {
		t.Fatalf("%+v", f.got[1])
	}
	aw.Close()
	rows, _ := ms.QueryAudit(context.Background(), "", string(audit.EnrollmentTokenMinted), time.Time{}, time.Now().Add(time.Hour), time.Time{}, 10)
	if len(rows) != 2 {
		t.Fatalf("audit rows %d", len(rows))
	}
	for _, r := range rows {
		raw, _ := json.Marshal(r)
		if strings.Contains(string(raw), "eyJ.enrol.token") {
			t.Fatal("the token must never be audited")
		}
	}
}

// Only operators, and only well-formed requests for this trust domain; auth
// failures map to validation_failed / temporarily_unavailable.
func TestMintEnrollmentTokenRefusals(t *testing.T) {
	f := &fakeEnroll{}
	s, _, _ := enrollServer(t, f)
	body := `{"services":["sms-gw"]}`
	if w := do(s, "POST", "/gateway/v1/ops/enrollment-tokens", body, map[string]string{"X-CSRF-Token": "x"}); w.Code != 401 {
		t.Fatalf("anonymous → %d", w.Code)
	}
	if w := do(s, "POST", "/gateway/v1/ops/enrollment-tokens", body, map[string]string{"Authorization": "Bearer member", "X-CSRF-Token": "x"}); w.Code != 403 {
		t.Fatalf("member → %d", w.Code)
	}
	for _, tc := range []struct{ body, param string }{
		{`{"services":[]}`, "services"},
		{`{"services":["Bad_Name"]}`, "services"},
		{`{"services":["spiffe://other.org/svc/sms-gw"]}`, "services"},
		{`{"services":["spiffe://example.org/ns/x/sa/y"]}`, "services"},
		{`{"services":["a","b","c","d","e","f","g","h","i","j","k"]}`, "services"},
		{`{"services":["sms-gw"],"tenant_id":"not-a-uuid"}`, "tenant_id"},
		{`{"services":["sms-gw"],"ttl_seconds":3600}`, "ttl_seconds"},
		{`{"services":["sms-gw"],"ttl_seconds":30}`, "ttl_seconds"},
	} {
		w := do(s, "POST", "/gateway/v1/ops/enrollment-tokens", tc.body, opHdr)
		if w.Code != 400 || !strings.Contains(w.Body.String(), `"validation_failed"`) {
			t.Errorf("%s → %d %s", tc.body, w.Code, w.Body)
			continue
		}
		// The OpenAPI validator may refuse first (no detail); ours names the field.
		if strings.Contains(w.Body.String(), `"param"`) && !strings.Contains(w.Body.String(), `"param":"`+tc.param+`"`) {
			t.Errorf("%s → %s (want param %s)", tc.body, w.Body, tc.param)
		}
	}
	if len(f.got) != 0 {
		t.Fatal("refused requests must never reach auth")
	}
	f.err = status.Error(codes.InvalidArgument, "bad")
	if w := do(s, "POST", "/gateway/v1/ops/enrollment-tokens", body, opHdr); w.Code != 400 {
		t.Fatalf("auth InvalidArgument → %d", w.Code)
	}
	f.err = status.Error(codes.Unavailable, "down")
	if w := do(s, "POST", "/gateway/v1/ops/enrollment-tokens", body, opHdr); w.Code != 503 || strings.Contains(w.Body.String(), "token") {
		t.Fatalf("auth unavailable → %d %s", w.Code, w.Body)
	}
}

func TestSpiffeIDs(t *testing.T) {
	ids, ok := spiffeIDs("example.org", []string{"sms-gw", "spiffe://example.org/svc/sms-gw", "lcm"})
	if !ok || strings.Join(ids, ",") != "spiffe://example.org/svc/sms-gw,spiffe://example.org/svc/lcm" {
		t.Fatalf("%v %v", ids, ok)
	}
	for _, bad := range [][]string{{}, {""}, {"-x"}, {"x-"}, {"UPPER"}, {"spiffe://example.org/svc/"}, {"spiffe://example.org.evil/svc/x"}} {
		if _, ok := spiffeIDs("example.org", bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}
