package grpcproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/go-tangra/go-tangra-portal/v4/internal/proxy/grpcproxy/echov1"
	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"
	"github.com/go-tangra/go-tangra/v4/identity"
	tgrpc "github.com/go-tangra/go-tangra/v4/transport/grpc"
)

type director struct {
	mu     sync.Mutex
	route  Route
	err    error
	called []string
}

func (d *director) Direct(_ context.Context, full string, md metadata.MD) (Route, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.called = append(d.called, full)
	if d.err != nil {
		return Route{}, d.err
	}
	r := d.route
	if md.Get("x-client") != nil {
		r.ClientKey = md.Get("x-client")[0]
	}
	return r, nil
}

type env struct {
	proxy  *Proxy
	dir    *director
	client echov1.EchoClient
	echo   *echov1.Server
	target string
	obs    []error
	mu     sync.Mutex
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ca := testutil.MustCA("example.org")
	modRT := testrt.New(t, ca, "orders")
	gs, _ := tgrpc.NewServer(modRT, tgrpc.WithAddress("127.0.0.1:0"))
	echo := &echov1.Server{}
	echov1.RegisterEchoServer(gs, echo)
	stop := testrt.StartServer(t, gs)
	t.Cleanup(stop)
	ep, _ := gs.Endpoint()
	gw := testrt.New(t, ca, "gateway")
	orders, _ := identity.NewSPIFFEID("example.org", "orders")
	e := &env{echo: echo, target: ep.Host}
	e.dir = &director{route: Route{Module: "orders", Identity: orders, Target: ep.Host, Token: "platform-token", MaxDuration: 5 * time.Second, Subjects: []string{"session:s1", "user:u1"}}}
	p, err := New(gw, Options{Director: e.dir, StreamsPerClient: 2, Observe: func(_ Route, err error) { e.mu.Lock(); e.obs = append(e.obs, err); e.mu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	e.proxy = p
	lis := bufconn.Listen(1 << 20)
	go func() { _ = p.Server().Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(); p.Close() })
	e.client = echov1.NewEchoClient(conn)
	return e
}

func TestPassthroughAllCallKinds(t *testing.T) {
	e := newEnv(t)
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer client-token", "cookie", "__Host-session=x", "x-forwarded-for", "1.2.3.4", "x-freya-secret", "z", "x-custom", "keep-me")
	var hdr, trl metadata.MD
	resp, err := e.client.Unary(ctx, &echov1.Msg{Text: "hi", Count: 1}, grpc.Header(&hdr), grpc.Trailer(&trl))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp.Text, "hi|peer=gateway;authorization=Bearer platform-token;x-request-id=") || !strings.Contains(resp.Text, "x-gateway-module=orders") || !strings.Contains(resp.Text, "x-custom=keep-me") ||
		strings.Contains(resp.Text, "cookie=") || strings.Contains(resp.Text, "x-forwarded-for") || strings.Contains(resp.Text, "x-freya-secret") || resp.Count != 2 {
		t.Fatalf("%q", resp.Text)
	}
	if hdr.Get("x-echo-header") == nil || trl.Get("x-echo-trailer") == nil {
		t.Fatalf("headers %v trailers %v", hdr, trl)
	}
	// Module errors pass through unchanged.
	if _, err := e.client.Unary(ctx, &echov1.Msg{Text: "fail"}); status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != "module says no" {
		t.Fatalf("%v", err)
	}
	// Server streaming.
	ss, err := e.client.ServerStream(ctx, &echov1.Msg{Text: "s", Count: 3})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		m, err := ss.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || m.Count != int32(n) {
			t.Fatalf("%v %v", m, err)
		}
		n++
	}
	if n != 3 {
		t.Fatal(n)
	}
	// Client streaming.
	cs, _ := e.client.ClientStream(ctx)
	for i := 0; i < 4; i++ {
		_ = cs.Send(&echov1.Msg{Text: "c"})
	}
	if m, err := cs.CloseAndRecv(); err != nil || m.Count != 4 || m.Text != "c" {
		t.Fatalf("%v %v", m, err)
	}
	// Bidi.
	bs, _ := e.client.Bidi(ctx)
	for i := 0; i < 3; i++ {
		_ = bs.Send(&echov1.Msg{Text: "b", Count: int32(i)})
		m, err := bs.Recv()
		if err != nil || m.Text != "B" || m.Count != int32(i) {
			t.Fatalf("%v %v", m, err)
		}
	}
	_ = bs.CloseSend()
	if _, err := bs.Recv(); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	e.mu.Lock()
	obs := len(e.obs)
	e.mu.Unlock()
	if obs < 5 {
		t.Fatalf("observed %d", obs)
	}
	// Public method: no token → no authorization metadata forwarded.
	e.dir.mu.Lock()
	e.dir.route.Token = ""
	e.dir.mu.Unlock()
	if resp, err := e.client.Unary(ctx, &echov1.Msg{Text: "pub"}); err != nil || strings.Contains(resp.Text, "authorization=") {
		t.Fatalf("%v %v", resp, err)
	}
}

func TestRefusalsLimitsAndCancellation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// Director refusals are returned verbatim.
	e.dir.mu.Lock()
	e.dir.err = status.Error(codes.PermissionDenied, "forbidden")
	e.dir.mu.Unlock()
	if _, err := e.client.Unary(ctx, &echov1.Msg{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("%v", err)
	}
	e.dir.mu.Lock()
	e.dir.err = nil
	e.dir.mu.Unlock()
	// Per-client stream cap (2): the third concurrent stream is refused.
	e.echo.Delay.Store(int64(200 * time.Millisecond))
	cctx := metadata.AppendToOutgoingContext(ctx, "x-client", "c1")
	s1, _ := e.client.ServerStream(cctx, &echov1.Msg{Text: "s", Count: 5})
	s2, _ := e.client.ServerStream(cctx, &echov1.Msg{Text: "s", Count: 5})
	_, _ = s1.Recv()
	_, _ = s2.Recv()
	if e.proxy.Active("c1") != 2 {
		t.Fatalf("active %d", e.proxy.Active("c1"))
	}
	s3, _ := e.client.ServerStream(cctx, &echov1.Msg{Text: "s", Count: 1})
	if _, err := s3.Recv(); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("cap: %v", err)
	}
	// Revocation cancels tracked streams with PermissionDenied.
	if n := e.proxy.CancelSubject("user:u1", "revoked"); n != 2 {
		t.Fatalf("cancelled %d", n)
	}
	for _, s := range []echov1.Echo_ServerStreamClient{s1, s2} {
		var err error
		for err == nil {
			_, err = s.Recv()
		}
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("revoked stream ended with %v", err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for e.proxy.Active("c1") != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if e.proxy.Active("c1") != 0 || e.proxy.CancelSubject("user:u1", "x") != 0 {
		t.Fatal("accounting after cancellation")
	}
	// Lifetime cap: a stream longer than MaxDuration ends with DeadlineExceeded.
	e.dir.mu.Lock()
	e.dir.route.MaxDuration = 150 * time.Millisecond
	e.dir.mu.Unlock()
	s4, _ := e.client.ServerStream(ctx, &echov1.Msg{Text: "s", Count: 50})
	var err error
	for err == nil {
		_, err = s4.Recv()
	}
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("lifetime cap: %v", err)
	}
	e.echo.Delay.Store(0)
	// Wrong pinned identity / dead target → temporarily_unavailable.
	e.dir.mu.Lock()
	e.dir.route.MaxDuration = time.Second
	billing, _ := identity.NewSPIFFEID("example.org", "billing")
	e.dir.route.Identity = billing
	e.dir.mu.Unlock()
	if _, err := e.client.Unary(ctx, &echov1.Msg{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("pinning: %v", err)
	}
	e.dir.mu.Lock()
	orders, _ := identity.NewSPIFFEID("example.org", "orders")
	e.dir.route.Identity = orders
	e.dir.route.Target = "127.0.0.1:1"
	e.dir.mu.Unlock()
	if _, err := e.client.Unary(ctx, &echov1.Msg{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("dead target: %v", err)
	}
	e.proxy.Forget("127.0.0.1:1")
	e.dir.mu.Lock()
	e.dir.route.Target = e.target
	foreign, _ := identity.NewSPIFFEID("other.org", "orders")
	e.dir.route.Identity = foreign
	e.dir.mu.Unlock()
	if _, err := e.client.Unary(ctx, &echov1.Msg{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("foreign domain: %v", err)
	}
	if _, err := New(nil, Options{}); err == nil {
		t.Fatal("options")
	}
	// Direct Open API and codec guards.
	e.dir.mu.Lock()
	e.dir.route.Identity = orders
	e.dir.mu.Unlock()
	st, err := e.proxy.Open(ctx, "/echo.v1.Echo/Unary", metadata.MD{})
	if err != nil {
		t.Fatal(err)
	}
	st.Done(nil)
	st.Done(nil)
	if _, err := (rawCodec{}).Marshal("x"); err == nil {
		t.Fatal("codec")
	}
	if err := (rawCodec{}).Unmarshal(nil, "x"); err == nil || (rawCodec{}).Name() != "proto" {
		t.Fatal("codec")
	}
	e.proxy.Close()
	if _, err := e.proxy.conn(orders, e.target); !errors.Is(err, ErrClosed) {
		t.Fatal("closed")
	}
}
