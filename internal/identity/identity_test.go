package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	"github.com/go-tangra/go-tangra-portal/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
)

const issuer = "https://platform.example.org"

type signer struct {
	priv ed25519.PrivateKey
	keys authclient.StaticKeys
}

func newSigner(t *testing.T) signer {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return signer{priv: priv, keys: authclient.StaticKeys{"k1": pub}}
}

func (s signer) token(t *testing.T, sub, tid, sid string, aud string, life time.Duration) string {
	t.Helper()
	now := time.Now()
	c := authclient.Claims{RegisteredClaims: jwt.RegisteredClaims{Issuer: issuer, Subject: sub, IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(life)), ID: "j-" + sid},
		TenantID: tid, SessionID: sid, Roles: []string{"member"}, AMR: []string{"pwd"}}
	if aud != "" {
		c.Audience = jwt.ClaimStrings{aud}
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
	tok.Header["kid"] = "k1"
	signed, err := tok.SignedString(s.priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

type fakeSessions struct {
	calls int
	err   error
	resp  *authv1.ExchangeResponse
}

func (f *fakeSessions) Exchange(_ context.Context, in *authv1.ExchangeRequest, _ ...grpc.CallOption) (*authv1.ExchangeResponse, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if in.GetCookieSecret() != "good" {
		return nil, status.Error(codes.Unauthenticated, "no_session")
	}
	if in.GetAudience() != Audience {
		return nil, status.Error(codes.InvalidArgument, "audience")
	}
	return f.resp, nil
}

type revs struct{ entries []authclient.Revocation }

func (r *revs) Since(context.Context, string) ([]authclient.Revocation, string, error) {
	return r.entries, "c", nil
}

func setup(t *testing.T) (*Resolver, *fakeSessions, signer, *revs, *memstore.Store, *audit.Writer) {
	t.Helper()
	sg := newSigner(t)
	rv := &revs{}
	v := authclient.New(authclient.Config{Issuer: issuer}, sg.keys, rv)
	if err := v.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	ms := memstore.New()
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	tok := sg.token(t, "u1", "t1", "s1", Audience, 15*time.Minute)
	fs := &fakeSessions{resp: &authv1.ExchangeResponse{Identity: &authv1.SessionIdentity{UserId: "u1", TenantId: "t1", SessionId: "s1", Roles: []string{"admin"}, Amr: []string{"pwd", "otp"}, Operator: true, DisplayName: "Dana K", AvatarUrl: "/api/v1/users/u1/avatar/abc"},
		AccessToken: tok, ExpiresAt: timestamppb.New(time.Now().Add(15 * time.Minute))}}
	r, err := New(Options{Sessions: fs, Verifier: v, KV: registry.NewMemory(), Audit: aw})
	if err != nil {
		t.Fatal(err)
	}
	return r, fs, sg, rv, ms, aw
}

func TestBearerResolution(t *testing.T) {
	r, _, sg, rv, ms, aw := setup(t)
	ctx := context.Background()
	req := httptest.NewRequest("GET", "https://x/", nil)
	if _, err := r.Resolve(ctx, req); !errors.Is(err, ErrAnonymous) {
		t.Fatalf("anonymous: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+sg.token(t, "u2", "t2", "s2", "", 5*time.Minute))
	id, err := r.Resolve(ctx, req)
	if err != nil || id.UserID != "u2" || id.Source != "bearer" || id.Token == "" || id.Roles[0] != "member" {
		t.Fatalf("%+v %v", id, err)
	}
	if id, err := r.ResolveToken(ctx, sg.token(t, "u2", "t2", "s2", Audience, time.Minute)); err != nil || id.SessionID != "s2" {
		t.Fatalf("%+v %v", id, err)
	}
	cases := map[string]string{
		"other audience": sg.token(t, "u2", "t2", "s2", "orders-service", time.Minute),
		"expired":        sg.token(t, "u2", "t2", "s2", "", -time.Minute),
		"garbage":        "not.a.jwt",
		"empty":          "",
		"huge":           strings.Repeat("a", 9000),
	}
	for name, tok := range cases {
		if _, err := r.ResolveToken(ctx, tok); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Wrong issuer.
	other := newSigner(t)
	if _, err := r.ResolveToken(ctx, other.token(t, "u", "t", "s", "", time.Minute)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("foreign key accepted")
	}
	// Revocation on the feed.
	rv.entries = []authclient.Revocation{{TS: time.Now().Add(time.Second), Kind: "session", SubjectID: "s2", TenantID: "t2"}}
	tok := sg.token(t, "u2", "t2", "s2", "", time.Minute)
	v := authclient.New(authclient.Config{Issuer: issuer}, sg.keys, rv)
	_ = v.Start(ctx, nil)
	r2, _ := New(Options{Sessions: &fakeSessions{}, Verifier: v, KV: registry.NewMemory()})
	if _, err := r2.ResolveToken(ctx, tok); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked accepted: %v", err)
	}
	// Stale revocation feed → fail closed as unavailable.
	stale := authclient.New(authclient.Config{Issuer: issuer, MaxStale: time.Nanosecond}, sg.keys, rv)
	_ = stale.Start(ctx, nil)
	time.Sleep(time.Millisecond)
	r3, _ := New(Options{Sessions: &fakeSessions{}, Verifier: stale, KV: registry.NewMemory()})
	if _, err := r3.ResolveToken(ctx, tok); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("stale feed: %v", err)
	}
	aw.Close()
	if n := countAudit(ms, "identity_refused"); n < len(cases)+1 {
		t.Fatalf("audits %d", n)
	}
}

func TestSessionExchangeAndCache(t *testing.T) {
	r, fs, sg, rv, _, _ := setup(t)
	ctx := context.Background()
	req := httptest.NewRequest("GET", "https://x/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: "good"})
	id, err := r.Resolve(ctx, req)
	if err != nil || id.UserID != "u1" || !id.Operator || id.Source != "session" || id.Token == "" || len(id.AMR) != 2 {
		t.Fatalf("%+v %v", id, err)
	}
	if id.DisplayName != "Dana K" || id.AvatarURL != "/api/v1/users/u1/avatar/abc" {
		t.Fatalf("profile attributes must come through Exchange: %+v", id)
	}
	if _, err := r.Resolve(ctx, req); err != nil || fs.calls != 1 {
		t.Fatalf("cache miss: calls=%d err=%v", fs.calls, err)
	}
	// Sign-out relay invalidates; the next call exchanges again.
	r.Invalidate(ctx, "good")
	r.Invalidate(ctx, "")
	if _, err := r.Resolve(ctx, req); err != nil || fs.calls != 2 {
		t.Fatalf("after invalidate: calls=%d", fs.calls)
	}
	// A revocation invalidates the cached identity offline.
	rv.entries = []authclient.Revocation{{TS: time.Now().Add(time.Second), Kind: "user", SubjectID: "u1", TenantID: "t1"}}
	v := authclient.New(authclient.Config{Issuer: issuer}, sg.keys, rv)
	_ = v.Start(ctx, nil)
	kv := registry.NewMemory()
	r2, _ := New(Options{Sessions: fs, Verifier: v, KV: kv})
	fs.calls = 0
	if _, err := r2.ResolveSession(ctx, "good"); err != nil || fs.calls != 1 {
		t.Fatalf("%v", err)
	}
	if _, err := r2.ResolveSession(ctx, "good"); fs.calls != 2 || err != nil {
		t.Fatalf("revoked cache entry reused: calls=%d %v", fs.calls, err)
	}
	// Refusals and outages.
	if _, err := r.ResolveSession(ctx, "bad"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("no session: %v", err)
	}
	if _, err := r.ResolveSession(ctx, strings.Repeat("c", 600)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("oversized cookie")
	}
	fs.err = status.Error(codes.Unavailable, "down")
	r.Invalidate(ctx, "good")
	if _, err := r.ResolveSession(ctx, "good"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("outage must fail closed: %v", err)
	}
	fs.err = nil
	fs.resp = &authv1.ExchangeResponse{Identity: &authv1.SessionIdentity{UserId: "u1"}}
	if _, err := r.ResolveSession(ctx, "good"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("malformed exchange: %v", err)
	}
	// A short-lived token bounds the cache TTL to the token lifetime.
	kv2 := registry.NewMemory()
	short := &fakeSessions{resp: &authv1.ExchangeResponse{Identity: &authv1.SessionIdentity{UserId: "u1", TenantId: "t1", SessionId: "s1"}, AccessToken: sg.token(t, "u1", "t1", "s1", Audience, 500*time.Millisecond), ExpiresAt: timestamppb.New(time.Now().Add(500 * time.Millisecond))}}
	r4, _ := New(Options{Sessions: short, Verifier: r.o.Verifier, KV: kv2})
	if _, err := r4.ResolveSession(ctx, "good"); err != nil {
		t.Fatal(err)
	}
	if keys, _ := kv2.Keys(ctx, "ident:"); len(keys) != 1 {
		t.Fatal("not cached")
	}
	time.Sleep(600 * time.Millisecond)
	if keys, _ := kv2.Keys(ctx, "ident:"); len(keys) != 0 {
		t.Fatal("cache outlived the token")
	}
	// Corrupt cache entries are ignored.
	_ = kv.Set(ctx, cacheKey("good"), "{", 0)
	fs.resp = &authv1.ExchangeResponse{Identity: &authv1.SessionIdentity{UserId: "u1", TenantId: "t1", SessionId: "s1"}, AccessToken: sg.token(t, "u1", "t1", "s1", Audience, time.Minute), ExpiresAt: timestamppb.New(time.Now().Add(time.Minute))}
	if _, err := r2.ResolveSession(ctx, "good"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{}); err == nil {
		t.Fatal("options")
	}
	if !IsSignOut("POST", "/api/v1/signout/") || IsSignOut("GET", "/api/v1/signout") {
		t.Fatal("signout")
	}
	if got, ok := FromContext(WithIdentity(ctx, id)); !ok || got.UserID != "u1" {
		t.Fatal("ctx")
	}
	if _, ok := FromContext(ctx); ok {
		t.Fatal("ctx empty")
	}
}

func countAudit(ms *memstore.Store, typ string) int {
	n := 0
	for _, r := range ms.Audit() {
		if r.EventType == typ {
			n++
		}
	}
	return n
}
