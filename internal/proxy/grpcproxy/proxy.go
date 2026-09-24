// Package grpcproxy forwards gRPC calls to modules without decoding them: a
// grpc-go server with an UnknownServiceHandler and a raw codec on the public
// side, per-module client connections pinned to the registrant identity on
// the channel side. The permission is decided once at stream start; streams
// are bounded per client and in lifetime, and can be cancelled when a
// session, user or tenant is revoked (FR-025).
package grpcproxy

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/go-tangra/go-tangra/v4/identity"
	"github.com/go-tangra/go-tangra/v4/observe"
	"github.com/go-tangra/go-tangra/v4/transport"
	"github.com/go-tangra/go-tangra/v4/transport/tlsconf"
)

// Route is where and how one call is forwarded (decided by the Director).
type Route struct {
	Module      string
	Identity    identity.SPIFFEID // module identity (pinned)
	Target      string            // host:port of the module's Freya gRPC server
	Token       string            // platform access token forwarded as the bearer credential ("" for public methods)
	MaxDuration time.Duration     // stream lifetime cap
	ClientKey   string            // per-client stream accounting ("" = no cap)
	Subjects    []string          // cancellation keys, e.g. "session:<id>", "user:<id>", "tenant:<id>"
	Instance    string
}

// Director resolves a full method and the inbound metadata to a Route; it
// returns a gRPC status error to refuse the call.
type Director interface {
	Direct(ctx context.Context, fullMethod string, md metadata.MD) (Route, error)
}

// Options tune the proxy.
type Options struct {
	Director         Director
	StreamsPerClient int           // default 32
	DefaultMax       time.Duration // default 10m
	MaxMessageBytes  int           // default 4 MiB
	// Observe receives the outcome of every forwarded call (health, metrics).
	Observe func(route Route, err error)
}

// Proxy is the passthrough.
type Proxy struct {
	rt      transport.Runtime
	o       Options
	srv     *grpc.Server
	mu      sync.Mutex
	conns   map[string]*grpc.ClientConn // identity|target
	active  map[string]int              // client key → open streams
	cancels map[string]map[*call]struct{}
	closed  bool
}

type call struct {
	cancel context.CancelFunc
	reason *string
	mu     sync.Mutex
}

// ErrClosed is returned after Close.
var ErrClosed = errors.New("grpcproxy: closed")

// New builds the proxy and its public-side server.
func New(rt transport.Runtime, o Options) (*Proxy, error) {
	if rt == nil || o.Director == nil {
		return nil, errors.New("grpcproxy: runtime and director are required")
	}
	if o.StreamsPerClient <= 0 {
		o.StreamsPerClient = 32
	}
	if o.DefaultMax <= 0 {
		o.DefaultMax = 10 * time.Minute
	}
	if o.MaxMessageBytes <= 0 {
		o.MaxMessageBytes = 4 << 20
	}
	p := &Proxy{rt: rt, o: o, conns: map[string]*grpc.ClientConn{}, active: map[string]int{}, cancels: map[string]map[*call]struct{}{}}
	p.srv = grpc.NewServer(
		grpc.ForceServerCodec(rawCodec{}),
		grpc.UnknownServiceHandler(p.handle),
		grpc.MaxRecvMsgSize(o.MaxMessageBytes),
		grpc.MaxSendMsgSize(o.MaxMessageBytes),
		grpc.MaxConcurrentStreams(uint32(o.StreamsPerClient*8)), // #nosec G115 -- bounded option
	)
	return p, nil
}

// Server is the public-side gRPC server (mount its ServeHTTP on the edge).
func (p *Proxy) Server() *grpc.Server { return p.srv }

// metadata never forwarded from clients (credentials and forwarding metadata are gateway-owned).
var droppedMD = []string{"authorization", "cookie", "x-request-id", "x-gateway-module", "x-gateway-client", "forwarded", "x-real-ip", ":authority", "content-type", "user-agent", "te"}

func outboundMD(in metadata.MD, r Route, cid string) metadata.MD {
	out := metadata.MD{}
	for k, v := range in {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "grpc-") || strings.HasPrefix(lk, "x-forwarded-") || strings.HasPrefix(lk, "x-freya-") || strings.HasPrefix(lk, "x-gateway-") || contains(droppedMD, lk) {
			continue
		}
		out[lk] = v
	}
	if r.Token != "" {
		out.Set("authorization", "Bearer "+r.Token)
	}
	out.Set("x-request-id", cid)
	out.Set("x-gateway-module", r.Module)
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Stream is an open forwarded call; Done must be called when it ends.
type Stream struct {
	grpc.ClientStream
	Route Route
	p     *Proxy
	c     *call
	once  sync.Once
}

// Revoked reports whether the stream was cancelled by CancelSubject.
func (s *Stream) Revoked() bool { return s.c.revoked() }

// Done releases accounting and reports the outcome.
func (s *Stream) Done(err error) {
	s.once.Do(func() {
		s.p.untrack(s.Route.Subjects, s.c)
		s.p.release(s.Route.ClientKey)
		s.c.cancel()
		if s.p.o.Observe != nil {
			s.p.o.Observe(s.Route, err)
		}
	})
}

// Open starts a forwarded stream: direct, account, connect.
func (p *Proxy) Open(ctx context.Context, fullMethod string, md metadata.MD) (*Stream, error) {
	r, err := p.o.Director.Direct(ctx, fullMethod, md)
	if err != nil {
		return nil, err
	}
	if !p.acquire(r.ClientKey) {
		return nil, status.Error(codes.ResourceExhausted, "rate_limited")
	}
	maxDur := r.MaxDuration
	if maxDur <= 0 {
		maxDur = p.o.DefaultMax
	}
	octx, cancel := context.WithTimeout(ctx, maxDur)
	cid := observe.CorrelationID(ctx)
	if cid == "" {
		cid = observe.NewCorrelationID()
	}
	octx = metadata.NewOutgoingContext(octx, outboundMD(md, r, cid))
	c := &call{cancel: cancel}
	p.track(r.Subjects, c)
	st := &Stream{Route: r, p: p, c: c}
	conn, err := p.conn(r.Identity, r.Target)
	if err != nil {
		st.Done(err)
		return nil, status.Error(codes.Unavailable, "temporarily_unavailable")
	}
	cs, err := conn.NewStream(octx, &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}, fullMethod, grpc.ForceCodec(rawCodec{}))
	if err != nil {
		st.Done(err)
		return nil, status.Error(codes.Unavailable, "temporarily_unavailable")
	}
	st.ClientStream = cs
	return st, nil
}

// revoked reports whether a cancellation reason was recorded for the call.
func (c *call) revoked() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reason != nil
}

// handle proxies one public-side stream.
func (p *Proxy) handle(_ any, ss grpc.ServerStream) error {
	full, ok := grpc.MethodFromServerStream(ss)
	if !ok {
		return status.Error(codes.NotFound, "not_found")
	}
	md, _ := metadata.FromIncomingContext(ss.Context())
	st, err := p.Open(ss.Context(), full, md)
	if err != nil {
		return err
	}
	err = pipe(ss, st)
	if st.Revoked() && (status.Code(err) == codes.Canceled || status.Code(err) == codes.DeadlineExceeded || status.Code(err) == codes.Unavailable) {
		err = status.Error(codes.PermissionDenied, "forbidden")
	}
	st.Done(err)
	return err
}

// pipe copies frames both ways until the module ends the call.
func pipe(ss grpc.ServerStream, cs grpc.ClientStream) error {
	s2c := make(chan error, 1)
	c2s := make(chan error, 1)
	go func() {
		for {
			var f Frame
			if err := ss.RecvMsg(&f); err != nil {
				if errors.Is(err, io.EOF) {
					_ = cs.CloseSend()
					s2c <- nil
					return
				}
				s2c <- err
				return
			}
			if err := cs.SendMsg(&f); err != nil {
				s2c <- err
				return
			}
		}
	}()
	go func() {
		headerSent := false
		for {
			var f Frame
			if err := cs.RecvMsg(&f); err != nil {
				c2s <- err
				return
			}
			if !headerSent {
				if h, err := cs.Header(); err == nil {
					_ = ss.SendHeader(h)
				}
				headerSent = true
			}
			if err := ss.SendMsg(&f); err != nil {
				c2s <- err
				return
			}
		}
	}()
	for {
		select {
		case err := <-s2c:
			if err != nil {
				// Client side failed: cancel the module side by returning.
				return status.Error(codes.Canceled, "client stream ended")
			}
			// Client finished sending; wait for the module to finish.
		case err := <-c2s:
			ss.SetTrailer(cs.Trailer())
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func (p *Proxy) acquire(key string) bool {
	if key == "" {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active[key] >= p.o.StreamsPerClient {
		return false
	}
	p.active[key]++
	return true
}

func (p *Proxy) release(key string) {
	if key == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active[key] <= 1 {
		next := make(map[string]int, len(p.active))
		for k, v := range p.active {
			if k != key {
				next[k] = v
			}
		}
		p.active = next
		return
	}
	p.active[key]--
}

func (p *Proxy) track(subjects []string, c *call) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range subjects {
		if p.cancels[s] == nil {
			p.cancels[s] = map[*call]struct{}{}
		}
		p.cancels[s][c] = struct{}{}
	}
}

func (p *Proxy) untrack(subjects []string, c *call) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range subjects {
		set := p.cancels[s]
		if set == nil {
			continue
		}
		next := map[*call]struct{}{}
		for k := range set {
			if k != c {
				next[k] = struct{}{}
			}
		}
		if len(next) == 0 {
			all := map[string]map[*call]struct{}{}
			for k, v := range p.cancels {
				if k != s {
					all[k] = v
				}
			}
			p.cancels = all
		} else {
			p.cancels[s] = next
		}
	}
}

// CancelSubject terminates every stream tracked under a subject key
// ("session:<id>", "user:<id>", "tenant:<id>"); returns how many.
func (p *Proxy) CancelSubject(key, reason string) int {
	p.mu.Lock()
	set := p.cancels[key]
	calls := make([]*call, 0, len(set))
	for c := range set {
		calls = append(calls, c)
	}
	p.mu.Unlock()
	for _, c := range calls {
		c.mu.Lock()
		r := reason
		c.reason = &r
		c.mu.Unlock()
		c.cancel()
	}
	return len(calls)
}

// Active reports open streams for a client key.
func (p *Proxy) Active(key string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.active[key]
}

// conn returns the pinned connection to a module instance, dialing on first use.
func (p *Proxy) conn(id identity.SPIFFEID, target string) (*grpc.ClientConn, error) {
	key := id.String() + "|" + target
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrClosed
	}
	if c, ok := p.conns[key]; ok {
		return c, nil
	}
	if !transport.LocalIdentityValid(p.rt) {
		return nil, transport.ErrLocalIdentityUnavailable
	}
	cfg, err := tlsconf.ClientConfig(p.rt.Provider(), id, transport.TLSOptions(p.rt))
	if err != nil {
		return nil, err
	}
	c, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(credentials.NewTLS(cfg)),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{}), grpc.MaxCallRecvMsgSize(p.o.MaxMessageBytes), grpc.MaxCallSendMsgSize(p.o.MaxMessageBytes)),
	)
	if err != nil {
		return nil, err
	}
	p.conns[key] = c
	return c, nil
}

// Forget closes cached connections to a target (instance withdrawn).
func (p *Proxy) Forget(target string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	next := map[string]*grpc.ClientConn{}
	for k, c := range p.conns {
		if strings.HasSuffix(k, "|"+target) {
			_ = c.Close()
			continue
		}
		next[k] = c
	}
	p.conns = next
}

// Close stops the server and every connection.
func (p *Proxy) Close() {
	p.mu.Lock()
	p.closed = true
	conns := p.conns
	p.conns = map[string]*grpc.ClientConn{}
	p.mu.Unlock()
	p.srv.Stop()
	for _, c := range conns {
		_ = c.Close()
	}
}
