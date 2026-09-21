// Package identity resolves who is calling the gateway: a browser session
// (exchanged for a platform access token through auth.v1.Sessions/Exchange
// and cached briefly) or a bearer token verified offline with pkg/authclient.
// Every refusal is audited as identity_refused; outages fail closed.
package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
	"github.com/go-freya/freya/services/auth/pkg/authclient"
	"github.com/go-freya/freya/services/gateway/internal/audit"
)

// SessionCookie is the platform session cookie relayed from the auth module.
const SessionCookie = "__Host-session"

// Audience the gateway accepts on bearer tokens (besides an absent audience).
const Audience = "gateway"

// Identity is a resolved caller.
type Identity struct {
	UserID    string    `json:"user_id"`
	TenantID  string    `json:"tenant_id"`
	SessionID string    `json:"session_id,omitempty"`
	Roles     []string  `json:"roles"`
	AMR       []string  `json:"amr,omitempty"`
	Operator  bool      `json:"operator,omitempty"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Source    string    `json:"source"` // session | bearer
	// Profile attributes from the auth module (feature 004); empty for bearer
	// callers. Never a phone number.
	DisplayName string `json:"display_name,omitempty"`
	AvatarURL   string `json:"avatar_url,omitempty"`
}

// Errors.
var (
	ErrAnonymous       = errors.New("identity: no credential")
	ErrUnauthenticated = errors.New("identity: unauthenticated")
	ErrUnavailable     = errors.New("identity: auth unavailable")
)

// Sessions exchanges cookies for tokens (auth.v1.SessionsClient).
type Sessions interface {
	Exchange(ctx context.Context, in *authv1.ExchangeRequest, opts ...grpc.CallOption) (*authv1.ExchangeResponse, error)
}

// Verifier verifies bearer tokens offline (*authclient.Verifier).
type Verifier interface {
	Verify(ctx context.Context, token string) (authclient.Identity, error)
}

// KV caches exchanged identities.
type KV interface {
	Get(ctx context.Context, key string) (string, bool, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Del(ctx context.Context, keys ...string) error
}

// Options configure the resolver.
type Options struct {
	Sessions Sessions
	Verifier Verifier
	KV       KV
	Audit    *audit.Writer
	CacheTTL time.Duration // default 60s
	Now      func() time.Time
}

// Resolver resolves identities.
type Resolver struct{ o Options }

// New builds a resolver.
func New(o Options) (*Resolver, error) {
	if o.Sessions == nil || o.Verifier == nil || o.KV == nil {
		return nil, errors.New("identity: sessions client, verifier and kv are required")
	}
	if o.CacheTTL <= 0 {
		o.CacheTTL = 60 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Resolver{o: o}, nil
}

// Resolve reads the request credential: a bearer token wins over a cookie.
func (r *Resolver) Resolve(ctx context.Context, req *http.Request) (Identity, error) {
	if tok := authclient.BearerToken(req.Header.Get("Authorization")); tok != "" {
		return r.ResolveToken(ctx, tok)
	}
	if c, err := req.Cookie(SessionCookie); err == nil && c.Value != "" {
		return r.ResolveSession(ctx, c.Value)
	}
	return Identity{}, ErrAnonymous
}

// ResolveToken verifies a bearer token (audience gateway or absent).
func (r *Resolver) ResolveToken(ctx context.Context, token string) (Identity, error) {
	if token == "" || len(token) > 8192 {
		return r.refuse("bearer", "malformed_token", ErrUnauthenticated)
	}
	id, err := r.o.Verifier.Verify(ctx, token)
	if err != nil {
		switch {
		case errors.Is(err, authclient.ErrStale):
			return r.refuseDetail("bearer", "revocation_feed_stale", ErrUnavailable, err)
		case errors.Is(err, authclient.ErrRevoked):
			return r.refuse("bearer", "revoked", ErrUnauthenticated)
		default:
			return r.refuseDetail("bearer", "invalid_token", ErrUnauthenticated, err)
		}
	}
	if id.Audience != "" && id.Audience != Audience {
		return r.refuse("bearer", "audience", ErrUnauthenticated)
	}
	return Identity{UserID: id.UserID, TenantID: id.TenantID, SessionID: id.SessionID, Roles: nonNil(id.Roles), AMR: id.AMR, Token: token, ExpiresAt: id.ExpiresAt, Source: "bearer"}, nil
}

// ResolveSession exchanges a session cookie (cached under its hash).
func (r *Resolver) ResolveSession(ctx context.Context, cookie string) (Identity, error) {
	if cookie == "" || len(cookie) > 512 {
		return r.refuse("session", "malformed_cookie", ErrUnauthenticated)
	}
	key := cacheKey(cookie)
	if raw, ok, err := r.o.KV.Get(ctx, key); err == nil && ok {
		var id Identity
		if json.Unmarshal([]byte(raw), &id) == nil && r.o.Now().Before(id.ExpiresAt) {
			// The cached token is re-verified offline: revocations on the feed
			// and expiry invalidate the entry without a round trip.
			if _, err := r.o.Verifier.Verify(ctx, id.Token); err == nil {
				return id, nil
			}
			_ = r.o.KV.Del(ctx, key)
		}
	}
	resp, err := r.o.Sessions.Exchange(ctx, &authv1.ExchangeRequest{CookieSecret: cookie, Audience: Audience})
	if err != nil {
		if status.Code(err) == codes.Unauthenticated {
			return r.refuse("session", "no_session", ErrUnauthenticated)
		}
		return r.refuse("session", "exchange_unavailable", ErrUnavailable)
	}
	si := resp.GetIdentity()
	id := Identity{UserID: si.GetUserId(), TenantID: si.GetTenantId(), SessionID: si.GetSessionId(), Roles: nonNil(si.GetRoles()), AMR: si.GetAmr(), Operator: si.GetOperator(),
		Token: resp.GetAccessToken(), ExpiresAt: resp.GetExpiresAt().AsTime(), Source: "session", DisplayName: si.GetDisplayName(), AvatarURL: si.GetAvatarUrl()}
	if id.UserID == "" || id.TenantID == "" || id.Token == "" {
		return r.refuse("session", "exchange_malformed", ErrUnavailable)
	}
	ttl := r.o.CacheTTL
	if left := id.ExpiresAt.Sub(r.o.Now()); left < ttl {
		ttl = left
	}
	if ttl > 0 {
		if raw, err := json.Marshal(id); err == nil {
			_ = r.o.KV.Set(ctx, key, string(raw), ttl)
		}
	}
	return id, nil
}

// Invalidate drops the cached identity of a cookie (sign-out relay).
func (r *Resolver) Invalidate(ctx context.Context, cookie string) {
	if cookie != "" {
		_ = r.o.KV.Del(ctx, cacheKey(cookie))
	}
}

func (r *Resolver) refuse(source, reason string, err error) (Identity, error) {
	return r.refuseDetail(source, reason, err, nil)
}

// refuseDetail audits a refusal with the verifier's diagnostic (never the credential).
func (r *Resolver) refuseDetail(source, reason string, err, cause error) (Identity, error) {
	if r.o.Audit != nil {
		outcome := "refused"
		if errors.Is(err, ErrUnavailable) {
			outcome = "failed"
		}
		details := map[string]any{"source": source}
		if cause != nil {
			details["detail"] = cause.Error()
		}
		_ = r.o.Audit.Emit(audit.Event{Type: audit.IdentityRefused, ActorKind: "user", Outcome: outcome, Reason: reason, Details: details})
	}
	return Identity{}, err
}

func cacheKey(cookie string) string {
	sum := sha256.Sum256([]byte(cookie))
	return "ident:" + hex.EncodeToString(sum[:])
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// IsSignOut reports whether a forwarded request is the auth module's sign-out
// (the relay invalidates the cached identity afterwards).
func IsSignOut(method, path string) bool {
	return method == http.MethodPost && strings.TrimSuffix(path, "/") == "/api/v1/signout"
}

type ctxKey struct{}

// WithIdentity stores the identity in ctx; FromContext reads it.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the resolved identity, if any.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}
