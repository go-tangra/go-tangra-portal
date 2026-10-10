package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	inventoryv1 "github.com/go-tangra/go-tangra-inventory/sdk/v4/api/proto/inventory/v1"
	fwcat "github.com/go-tangra/go-tangra/v4/catalogue"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	catsvc "github.com/go-tangra/go-tangra-portal/v4/internal/catalogue"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
)

// bundleChunk is the size of one streamed part (≤ 1 MiB by contract).
const bundleChunk = 1 << 20

// JoinRenders are the join records an agent delivery is rendered from.
type JoinRenders interface {
	ClaimJoinRender(ctx context.Context, id string) (store.CatalogueJoin, error)
	SetJoinJTI(ctx context.Context, id, jti string) error
	Entry(ctx context.Context, module, version string) (store.CatalogueEntry, error)
}

// ModuleBundleServer serves inventory.v1.ModuleBundleSource (spec 037): when
// an inventory agent fetches its delivery item, the inventory asks for the
// bundle, which is rendered (and its token minted) only then.
type ModuleBundleServer struct {
	inventoryv1.UnimplementedModuleBundleSourceServer
	// Caller is the only SPIFFE id allowed to render (the inventory).
	Caller  string
	Joins   JoinRenders
	Builder *catsvc.Builder
	Events  *audit.Writer
	Logger  *slog.Logger
	Now     func() time.Time
}

// RegisterModuleBundle mounts ModuleBundleSource; nil installs the
// Unimplemented stub so the method exists (and is policed) from the start.
func RegisterModuleBundle(s grpc.ServiceRegistrar, h inventoryv1.ModuleBundleSourceServer) {
	if h == nil {
		h = inventoryv1.UnimplementedModuleBundleSourceServer{}
	}
	inventoryv1.RegisterModuleBundleSourceServer(s, h)
}

var errNoJoin = status.Error(codes.NotFound, "no such delivery")

// RenderModuleBundle implements inventory.v1.ModuleBundleSource. Every
// mismatch is NotFound so the caller learns nothing about other joins.
func (s *ModuleBundleServer) RenderModuleBundle(req *inventoryv1.RenderModuleBundleRequest, stream grpc.ServerStreamingServer[inventoryv1.ModuleBundleChunk]) error {
	ctx := stream.Context()
	caller, err := peerID(ctx)
	if err != nil {
		return err
	}
	if s.Caller == "" || caller != s.Caller {
		s.refuse(ctx, req, "caller_not_allowed", caller)
		return status.Error(codes.PermissionDenied, "caller may not render module bundles")
	}
	j, err := s.Joins.ClaimJoinRender(ctx, req.GetDeliveryId())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.refuse(ctx, req, "unknown_or_spent", caller)
			return errNoJoin
		}
		return status.Error(codes.Unavailable, "store unavailable")
	}
	if j.TenantID != req.GetTenantId() || j.HostID != req.GetHostId() {
		s.refuse(ctx, req, "host_mismatch", caller)
		return errNoJoin
	}
	row, err := s.Joins.Entry(ctx, j.Module, j.Version)
	if err != nil {
		s.refuse(ctx, req, "entry_gone", caller)
		return errNoJoin
	}
	entry, err := fwcat.ParseEntry(row.Entry)
	if err != nil {
		return status.Error(codes.Unavailable, "entry unreadable")
	}
	inputs, err := catsvc.CheckInputs(entry, j.Inputs)
	if err != nil {
		s.refuse(ctx, req, "inputs_invalid", caller)
		return errNoJoin
	}
	now := s.now()
	ttl := j.ExpiresAt.Sub(now).Truncate(time.Second)
	if ttl < time.Minute {
		s.refuse(ctx, req, "expired", caller)
		return errNoJoin
	}
	built, err := s.Builder.Build(ctx, entry, inputs, ttl, now)
	if err != nil {
		s.log().ErrorContext(ctx, "module bundle render failed", "module", j.Module, "join", j.ID, "err", err)
		return status.Error(codes.Unavailable, "bundle not rendered")
	}
	defer clear(built.Zip)
	if err := s.Joins.SetJoinJTI(ctx, j.ID, built.JTI); err != nil {
		return status.Error(codes.Unavailable, "store unavailable")
	}
	sum := sha256.Sum256(built.Zip)
	if s.Events != nil {
		_ = s.Events.Emit(audit.Event{Type: audit.ModuleBundleRendered, Module: j.Module, ActorKind: "service", ActorID: caller, TenantID: j.TenantID,
			SubjectKind: "join", SubjectID: j.ID, Outcome: "ok", Details: map[string]any{"version": j.Version, "host_id": j.HostID,
				"item_id": req.GetItemId(), "jti": built.JTI, "render": j.Renders}})
	}
	if err := stream.Send(&inventoryv1.ModuleBundleChunk{Part: &inventoryv1.ModuleBundleChunk_Header{Header: &inventoryv1.ModuleBundleHeader{
		Module: j.Module, Version: j.Version, Size: int64(len(built.Zip)), Sha256: hex.EncodeToString(sum[:]), DeliveryId: j.ID}}}); err != nil {
		return err
	}
	for off := 0; off < len(built.Zip); off += bundleChunk {
		end := min(off+bundleChunk, len(built.Zip))
		if err := stream.Send(&inventoryv1.ModuleBundleChunk{Part: &inventoryv1.ModuleBundleChunk_Chunk{Chunk: &inventoryv1.ArtifactChunk{
			Offset: int64(off), Data: built.Zip[off:end]}}}); err != nil {
			return err
		}
	}
	return nil
}

func (s *ModuleBundleServer) refuse(ctx context.Context, req *inventoryv1.RenderModuleBundleRequest, reason, caller string) {
	s.log().WarnContext(ctx, "module bundle render refused", "reason", reason, "caller", caller, "join", req.GetDeliveryId())
	if s.Events != nil {
		_ = s.Events.Emit(audit.Event{Type: audit.ModuleBundleRendered, ActorKind: "service", ActorID: caller, SubjectKind: "join",
			SubjectID: req.GetDeliveryId(), Outcome: "refused", Reason: reason, Details: map[string]any{"host_id": req.GetHostId(), "item_id": req.GetItemId()}})
	}
}

func (s *ModuleBundleServer) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *ModuleBundleServer) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}
