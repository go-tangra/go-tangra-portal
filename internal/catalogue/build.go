package catalogue

import (
	"context"
	"errors"
	"fmt"
	"time"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	fwcat "github.com/go-tangra/go-tangra/v4/catalogue"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MaxRenderedBytes caps a rendered join bundle (spec 037 SR-006).
const MaxRenderedBytes = 12 << 20

// ErrTokenRefused: auth refused to mint the join token (lifetime, scope).
var ErrTokenRefused = errors.New("catalogue: auth refused the join token")

// Minter mints enrolment tokens (auth.v1.Enrollment).
type Minter interface {
	MintEnrollmentToken(ctx context.Context, in *authv1.MintEnrollmentTokenRequest, opts ...grpc.CallOption) (*authv1.MintEnrollmentTokenResponse, error)
}

// Builder mints a join token and renders a module's verified bundle with it:
// the step shared by the download (036) and agent delivery (037).
type Builder struct {
	TrustDomain string
	Core        map[string]string
	MeshCA      func(ctx context.Context) ([]byte, error)
	Bundle      func(ctx context.Context, module, version string) ([]byte, error)
	Mint        Minter
}

// Built is a rendered join bundle and its token's jti and expiry.
type Built struct {
	Zip       []byte
	JTI       string
	ExpiresAt time.Time
}

// Build renders the entry's bundle with inputs (already CheckInputs'd) and a
// fresh token valid for ttl.
func (b *Builder) Build(ctx context.Context, e fwcat.Entry, inputs map[string]string, ttl time.Duration, now time.Time) (Built, error) {
	bundle, err := b.Bundle(ctx, e.Module, e.Version)
	if err != nil {
		return Built{}, err
	}
	if err := e.CheckBundle(bundle); err != nil {
		return Built{}, fmt.Errorf("stored bundle does not match its entry: %w", err)
	}
	ca, err := b.MeshCA(ctx)
	if err != nil {
		return Built{}, fmt.Errorf("mesh CA: %w", err)
	}
	mctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	minted, err := b.Mint.MintEnrollmentToken(mctx, &authv1.MintEnrollmentTokenRequest{TenantId: b.Core["MESH_TENANT_ID"],
		SpiffePaths: []string{"spiffe://" + b.TrustDomain + "/svc/" + e.Module}, TtlSeconds: int64(ttl.Seconds())})
	if err != nil {
		if status.Code(err) == codes.InvalidArgument {
			return Built{}, fmt.Errorf("%w: %v", ErrTokenRefused, err)
		}
		return Built{}, err
	}
	jti, err := TokenJTI(minted.GetToken())
	if err != nil {
		return Built{}, err
	}
	zipped, err := RenderJoin(JoinRequest{Entry: e, Bundle: bundle, Core: b.Core, Inputs: inputs, Token: minted.GetToken(), MeshCA: ca, Now: now})
	if err != nil {
		return Built{}, err
	}
	if len(zipped) > MaxRenderedBytes {
		return Built{}, fmt.Errorf("%w: rendered bundle exceeds %d bytes", ErrRender, MaxRenderedBytes)
	}
	expires := now.Add(ttl)
	if minted.GetExpiresAt() != nil {
		expires = minted.GetExpiresAt().AsTime().UTC()
	}
	return Built{Zip: zipped, JTI: jti, ExpiresAt: expires}, nil
}
