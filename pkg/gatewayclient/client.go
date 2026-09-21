// Package gatewayclient registers a module with the application gateway and
// keeps its lease alive. It expects a Freya client connection to the gateway
// (mTLS, the module's identity is the registrant identity).
package gatewayclient

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	gatewayv1 "github.com/go-freya/freya/services/gateway/api/proto/gateway/v1"
)

// Options configure the registration loop.
type Options struct {
	Manifest   Manifest
	InstanceID string // stable per process; generated when empty
	HTTPURL    string // https://host:port of the module's Freya HTTP server
	GRPCTarget string // host:port of the module's Freya gRPC server
	Logger     *slog.Logger
	// MaxBackoff bounds the re-registration delay (default 30s).
	MaxBackoff time.Duration
	// OnState is called on every transition (registered, lost, refused).
	OnState func(State)
}

// State is the lease state visible to the module.
type State struct {
	Registered bool
	LeaseID    string
	Module     string
	Version    uint64
	Err        error
}

// ErrRefused is wrapped when the gateway permanently refuses the manifest
// (identity not allowed, prefixes not granted, invalid manifest): the loop
// keeps retrying at the maximum backoff but reports the refusal.
var ErrRefused = errors.New("gatewayclient: registration refused")

// Client drives Register → Renew → Deregister.
type Client struct {
	reg  gatewayv1.RegistryClient
	opts Options
	mu   sync.Mutex
	st   State
	rand func() float64
	now  func() time.Time
}

// New wraps a connection to the gateway.
func New(conn grpc.ClientConnInterface, o Options) (*Client, error) {
	if conn == nil {
		return nil, errors.New("gatewayclient: connection is required")
	}
	if o.Manifest.Module == "" {
		return nil, errors.New("gatewayclient: manifest module is required")
	}
	if o.HTTPURL == "" && o.GRPCTarget == "" {
		return nil, errors.New("gatewayclient: a backend address is required")
	}
	if o.InstanceID == "" {
		o.InstanceID = newInstanceID()
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = 30 * time.Second
	}
	return &Client{reg: gatewayv1.NewRegistryClient(conn), opts: o, rand: jitter, now: time.Now}, nil
}

// State returns the current lease state.
func (c *Client) State() State { c.mu.Lock(); defer c.mu.Unlock(); return c.st }

func (c *Client) set(st State) {
	c.mu.Lock()
	c.st = st
	c.mu.Unlock()
	if c.opts.OnState != nil {
		c.opts.OnState(st)
	}
}

// Run registers and renews until ctx is cancelled, then deregisters. It only
// returns an error when the manifest cannot be encoded.
func (c *Client) Run(ctx context.Context) error {
	pm, err := c.opts.Manifest.Proto()
	if err != nil {
		return err
	}
	req := &gatewayv1.RegisterRequest{Manifest: pm, InstanceId: c.opts.InstanceID, Backend: &gatewayv1.Backend{HttpUrl: c.opts.HTTPURL, GrpcTarget: c.opts.GRPCTarget}}
	backoff := time.Second
	for {
		lease, err := c.reg.Register(ctx, req)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			st := State{Err: err}
			if permanent(err) {
				st.Err = fmt.Errorf("%w: %v", ErrRefused, err)
				backoff = c.opts.MaxBackoff
			}
			c.set(st)
			c.opts.Logger.Warn("gateway registration failed", "module", c.opts.Manifest.Module, "err", err, "retry_in", backoff)
			if !c.sleep(ctx, backoff) {
				return nil
			}
			backoff = min(backoff*2, c.opts.MaxBackoff)
			continue
		}
		backoff = time.Second
		c.set(State{Registered: true, LeaseID: lease.GetLeaseId(), Module: lease.GetModule(), Version: lease.GetRegistryVersion()})
		c.opts.Logger.Info("registered with gateway", "module", lease.GetModule(), "lease", lease.GetLeaseId())
		if !c.renewLoop(ctx, lease) {
			// ctx cancelled: withdraw immediately.
			dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, _ = c.reg.Deregister(dctx, &gatewayv1.DeregisterRequest{LeaseId: lease.GetLeaseId()})
			cancel()
			c.set(State{})
			return nil
		}
		// Lease lost: fall through to re-register after a short pause.
		if !c.sleep(ctx, backoff) {
			return nil
		}
	}
}

// renewLoop renews every renew_every (±10 % jitter); returns false when ctx
// ended, true when the lease was lost and a new registration is needed.
func (c *Client) renewLoop(ctx context.Context, lease *gatewayv1.Lease) bool {
	every := lease.GetRenewEvery().AsDuration()
	if every <= 0 {
		every = 10 * time.Second
	}
	failures := 0
	for {
		wait := time.Duration(float64(every) * (0.9 + 0.2*c.rand()))
		if !c.sleep(ctx, wait) {
			return false
		}
		rctx, cancel := context.WithTimeout(ctx, every)
		renewed, err := c.reg.Renew(rctx, &gatewayv1.RenewRequest{LeaseId: lease.GetLeaseId()})
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return false
			}
			failures++
			c.opts.Logger.Warn("gateway lease renewal failed", "module", c.opts.Manifest.Module, "err", err, "failures", failures)
			// A refused renewal (drained, revoked, unknown lease) or the TTL
			// running out means the registration is gone.
			if permanent(err) || status.Code(err) == codes.NotFound || time.Duration(failures)*every >= lease.GetTtl().AsDuration() {
				c.set(State{Err: err})
				return true
			}
			continue
		}
		failures = 0
		if renewed.GetLeaseId() != "" {
			lease = renewed
		}
		c.set(State{Registered: true, LeaseID: lease.GetLeaseId(), Module: lease.GetModule(), Version: renewed.GetRegistryVersion()})
	}
}

func (c *Client) sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func permanent(err error) bool {
	switch status.Code(err) {
	case codes.PermissionDenied, codes.InvalidArgument, codes.FailedPrecondition, codes.Unauthenticated:
		return true
	}
	return false
}

func jitter() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0.5
	}
	return float64(binary.LittleEndian.Uint64(b[:])>>11) / float64(1<<53)
}

func newInstanceID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("inst-%d", time.Now().UnixNano()%math.MaxInt32)
	}
	return fmt.Sprintf("%x", b)
}
