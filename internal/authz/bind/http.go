// Package bind connects identity resolution and permission decisions to the
// HTTP dispatcher and the gRPC passthrough (kept apart from authz so the
// shell API can import authz without a cycle).
package bind

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	fidentity "github.com/go-freya/freya/identity"
	"github.com/go-freya/freya/services/auth/pkg/authclient"
	"github.com/go-freya/freya/services/gateway/internal/authz"
	"github.com/go-freya/freya/services/gateway/internal/httpapi"
	"github.com/go-freya/freya/services/gateway/internal/identity"
	"github.com/go-freya/freya/services/gateway/internal/proxy/grpcproxy"
	"github.com/go-freya/freya/services/gateway/internal/proxy/httpproxy"
	"github.com/go-freya/freya/services/gateway/internal/registry"
	"github.com/go-freya/freya/services/gateway/internal/route"
)

// Resolver resolves callers (identity.Resolver).
type Resolver interface {
	Resolve(ctx context.Context, r *http.Request) (identity.Identity, error)
	ResolveToken(ctx context.Context, token string) (identity.Identity, error)
	ResolveSession(ctx context.Context, cookie string) (identity.Identity, error)
}

// HTTPAuthorizer decides protected HTTP routes: identity → permission →
// forwarding context carrying the platform token.
type HTTPAuthorizer struct {
	Identity Resolver
	Decider  *authz.Decider
}

// Authorize implements httpapi.Authorizer.
func (a *HTTPAuthorizer) Authorize(r *http.Request, rt route.Route) (context.Context, *httpapi.Error) {
	id, err := a.Identity.Resolve(r.Context(), r)
	if err != nil {
		return nil, refusal(err)
	}
	ok, err := a.Decider.Allowed(r.Context(), rt.Module, id.TenantID, id.UserID, rt.Permission)
	if err != nil {
		return nil, httpapi.ErrUnavailable
	}
	if !ok {
		return nil, httpapi.ErrForbidden
	}
	ctx := identity.WithIdentity(r.Context(), id)
	return httpproxy.WithToken(ctx, id.Token), nil
}

func refusal(err error) *httpapi.Error {
	switch {
	case errors.Is(err, identity.ErrAnonymous), errors.Is(err, identity.ErrUnauthenticated):
		return httpapi.ErrUnauthenticated
	case errors.Is(err, identity.ErrUnavailable):
		return httpapi.ErrUnavailable
	}
	return httpapi.ErrUnavailable
}

// Director decides gRPC calls for the passthrough proxy.
type Director struct {
	Reg      *registry.Registry
	Identity Resolver
	Decider  *authz.Decider
	// StreamMax bounds streaming methods without a declared cap; UnaryTimeout bounds unary calls.
	StreamMax    time.Duration
	UnaryTimeout time.Duration
	rr           atomic.Uint32
}

// Direct implements grpcproxy.Director.
func (d *Director) Direct(ctx context.Context, full string, md metadata.MD) (grpcproxy.Route, error) {
	m, ok := d.Reg.Table().MatchMethod(full)
	if !ok {
		return grpcproxy.Route{}, status.Error(codes.NotFound, "not_found")
	}
	if m.State != string(registry.StateActive) {
		return grpcproxy.Route{}, status.Error(codes.Unavailable, "temporarily_unavailable")
	}
	r := grpcproxy.Route{Module: m.Module}
	if !m.Public {
		id, err := d.resolve(ctx, md)
		if err != nil {
			return grpcproxy.Route{}, err
		}
		ok, err := d.Decider.Allowed(ctx, m.Module, id.TenantID, id.UserID, m.Permission)
		if err != nil {
			return grpcproxy.Route{}, status.Error(codes.Unavailable, "temporarily_unavailable")
		}
		if !ok {
			return grpcproxy.Route{}, status.Error(codes.PermissionDenied, "forbidden")
		}
		r.Token = id.Token
		r.ClientKey = id.TenantID + "/" + id.UserID
		r.Subjects = []string{"session:" + id.SessionID, "user:" + id.UserID, "tenant:" + id.TenantID}
	}
	spiffe, instances := d.Reg.Backends(m.Module)
	if len(instances) == 0 {
		return grpcproxy.Route{}, status.Error(codes.Unavailable, "temporarily_unavailable")
	}
	sid, err := fidentity.ParseSPIFFEID(spiffe)
	if err != nil {
		return grpcproxy.Route{}, status.Error(codes.Unavailable, "temporarily_unavailable")
	}
	in := instances[int(d.rr.Add(1)-1)%len(instances)]
	if in.Backend.GRPCTarget == "" {
		return grpcproxy.Route{}, status.Error(codes.Unavailable, "temporarily_unavailable")
	}
	r.Identity, r.Target, r.Instance = sid, in.Backend.GRPCTarget, in.ID
	switch {
	case m.Streaming && m.MaxStream > 0:
		r.MaxDuration = m.MaxStream
	case m.Streaming:
		r.MaxDuration = d.StreamMax
	default:
		r.MaxDuration = d.UnaryTimeout
	}
	return r, nil
}

func (d *Director) resolve(ctx context.Context, md metadata.MD) (identity.Identity, error) {
	if vals := md.Get("authorization"); len(vals) > 0 {
		id, err := d.Identity.ResolveToken(ctx, authclient.BearerToken(vals[0]))
		return id, grpcRefusal(err)
	}
	for _, c := range md.Get("cookie") {
		for _, part := range splitCookies(c) {
			if name, val, ok := cutCookie(part); ok && name == identity.SessionCookie {
				id, err := d.Identity.ResolveSession(ctx, val)
				return id, grpcRefusal(err)
			}
		}
	}
	return identity.Identity{}, status.Error(codes.Unauthenticated, "unauthenticated")
}

func grpcRefusal(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, identity.ErrUnavailable):
		return status.Error(codes.Unavailable, "temporarily_unavailable")
	default:
		return status.Error(codes.Unauthenticated, "unauthenticated")
	}
}

func splitCookies(header string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(header); i++ {
		if i == len(header) || header[i] == ';' {
			part := header[start:i]
			for len(part) > 0 && part[0] == ' ' {
				part = part[1:]
			}
			if part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	return out
}

func cutCookie(part string) (string, string, bool) {
	for i := 0; i < len(part); i++ {
		if part[i] == '=' {
			return part[:i], part[i+1:], true
		}
	}
	return "", "", false
}
