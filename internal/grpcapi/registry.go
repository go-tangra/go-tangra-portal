package grpcapi

import (
	"context"
	"errors"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	gatewayv1 "github.com/go-tangra/go-tangra-portal/sdk/v4/api/proto/gateway/v1"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra/v4/authn"
)

// RegistryServer serves gateway.v1.Registry on top of the registry. The
// registrant identity is always the verified mTLS peer, never a field.
type RegistryServer struct {
	gatewayv1.UnimplementedRegistryServer
	Reg *registry.Registry
}

func peerID(ctx context.Context) (string, error) {
	p, ok := authn.FromContext(ctx)
	if !ok || p.ID.IsZero() {
		return "", status.Error(codes.Unauthenticated, "peer identity required")
	}
	return p.ID.String(), nil
}

func toStatus(err error) error {
	var e *registry.Error
	if errors.As(err, &e) {
		return status.Error(e.Code, e.Reason)
	}
	return status.Error(codes.Unavailable, registry.ReasonUnavailable)
}

func toLease(l registry.Lease) *gatewayv1.Lease {
	return &gatewayv1.Lease{LeaseId: l.ID, Module: l.Module, Ttl: durationpb.New(l.TTL), RenewEvery: durationpb.New(l.Renew), RegistryVersion: l.Version}
}

// Register implements gateway.v1.Registry.
func (s *RegistryServer) Register(ctx context.Context, req *gatewayv1.RegisterRequest) (*gatewayv1.Lease, error) {
	id, err := peerID(ctx)
	if err != nil {
		return nil, err
	}
	l, err := s.Reg.Register(ctx, id, req)
	if err != nil {
		return nil, toStatus(err)
	}
	return toLease(l), nil
}

// Renew implements gateway.v1.Registry.
func (s *RegistryServer) Renew(ctx context.Context, req *gatewayv1.RenewRequest) (*gatewayv1.Lease, error) {
	id, err := peerID(ctx)
	if err != nil {
		return nil, err
	}
	l, err := s.Reg.Renew(ctx, id, req.GetLeaseId())
	if err != nil {
		return nil, toStatus(err)
	}
	return toLease(l), nil
}

// Deregister implements gateway.v1.Registry.
func (s *RegistryServer) Deregister(ctx context.Context, req *gatewayv1.DeregisterRequest) (*gatewayv1.DeregisterResponse, error) {
	id, err := peerID(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.Reg.Deregister(ctx, id, req.GetLeaseId()); err != nil {
		return nil, toStatus(err)
	}
	return &gatewayv1.DeregisterResponse{}, nil
}

// Watch streams registry events after the cursor (a registry version).
func (s *RegistryServer) Watch(req *gatewayv1.WatchRequest, stream gatewayv1.Registry_WatchServer) error {
	if _, err := peerID(stream.Context()); err != nil {
		return err
	}
	var cursor uint64
	if c := req.GetCursor(); c != "" {
		n, err := strconv.ParseUint(c, 10, 64)
		if err != nil {
			return status.Error(codes.InvalidArgument, "cursor")
		}
		cursor = n
	}
	ch, stop := s.Reg.Watch(cursor)
	defer stop()
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case ev, ok := <-ch:
			if !ok {
				return status.Error(codes.Aborted, "watch overflow; re-watch from the last cursor")
			}
			if err := stream.Send(&gatewayv1.RegistryEvent{Ts: timestamppb.New(ev.TS), Kind: ev.Kind, Module: ev.Module, RegistryVersion: ev.Version, Cursor: strconv.FormatUint(ev.Version, 10)}); err != nil {
				return err
			}
		}
	}
}
