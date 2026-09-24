package echov1

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/go-tangra/go-tangra/v4/authn"
)

// Server is the test implementation of Echo: it reflects selected inbound
// metadata and the verified peer into responses.
type Server struct {
	UnimplementedEchoServer
	// Delay between streamed messages (nanoseconds).
	Delay atomic.Int64
}

// MetadataSummary renders the peer and selected metadata keys.
func MetadataSummary(ctx context.Context) string {
	md, _ := metadata.FromIncomingContext(ctx)
	p, _ := authn.FromContext(ctx)
	parts := []string{"peer=" + p.ServiceName}
	for _, k := range []string{"authorization", "x-request-id", "x-gateway-module", "x-custom", "cookie", "x-forwarded-for", "x-freya-secret"} {
		if v := md.Get(k); len(v) > 0 {
			parts = append(parts, k+"="+v[0])
		}
	}
	return strings.Join(parts, ";")
}

// Unary implements Echo.
func (e *Server) Unary(ctx context.Context, m *Msg) (*Msg, error) {
	_ = grpc.SetHeader(ctx, metadata.Pairs("x-echo-header", "h1"))
	_ = grpc.SetTrailer(ctx, metadata.Pairs("x-echo-trailer", "t1"))
	if m.Text == "fail" {
		return nil, status.Error(codes.FailedPrecondition, "module says no")
	}
	return &Msg{Text: m.Text + "|" + MetadataSummary(ctx), Count: m.Count + 1}, nil
}

// ServerStream implements Echo.
func (e *Server) ServerStream(m *Msg, s Echo_ServerStreamServer) error {
	for i := int32(0); i < m.Count; i++ {
		if err := s.Send(&Msg{Text: m.Text, Count: i}); err != nil {
			return err
		}
		if d := time.Duration(e.Delay.Load()); d > 0 {
			select {
			case <-time.After(d):
			case <-s.Context().Done():
				return s.Context().Err()
			}
		}
	}
	return nil
}

// ClientStream implements Echo.
func (e *Server) ClientStream(s Echo_ClientStreamServer) error {
	var n int32
	var last string
	for {
		m, err := s.Recv()
		if errors.Is(err, io.EOF) {
			return s.SendAndClose(&Msg{Text: last, Count: n})
		}
		if err != nil {
			return err
		}
		n++
		last = m.Text
	}
}

// Bidi implements Echo.
func (e *Server) Bidi(s Echo_BidiServer) error {
	for {
		m, err := s.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := s.Send(&Msg{Text: strings.ToUpper(m.Text), Count: m.Count}); err != nil {
			return err
		}
	}
}
