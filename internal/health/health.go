// Package health probes module instances over the Freya channel and drives
// the registry's health view: N consecutive failures mark an instance
// unhealthy, a cool-down passes, a successful probe recovers it.
package health

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-freya/freya/identity"
	"github.com/go-freya/freya/services/gateway/internal/registry"
	"github.com/go-freya/freya/transport"
	thttp "github.com/go-freya/freya/transport/http"
	"github.com/go-freya/freya/transport/tlsconf"
)

// Prober checks one instance; a nil error means reachable and authenticated.
type Prober func(ctx context.Context, identity string, in registry.Instance) error

// Registry is what the checker needs from the registry.
type Registry interface {
	Registrations() []registry.Registration
	State(module string) registry.State
	SetHealth(ctx context.Context, module, instance string, healthy bool)
}

// Options tune the checker.
type Options struct {
	Registry  Registry
	Probe     Prober
	Interval  time.Duration // default 5s
	Timeout   time.Duration // per probe, default 2s
	Threshold int           // consecutive failures before unhealthy, default 3
	Cooldown  time.Duration // before re-probing an unhealthy instance, default 10s
	Now       func() time.Time
	Logger    *slog.Logger
}

// Checker runs the probes and keeps one Circuit per instance.
type Checker struct {
	o  Options
	mu sync.Mutex
	st map[string]*Circuit // module/instance
}

// New builds a checker.
func New(o Options) *Checker {
	if o.Interval <= 0 {
		o.Interval = 5 * time.Second
	}
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Second
	}
	if o.Threshold <= 0 {
		o.Threshold = 3
	}
	if o.Cooldown <= 0 {
		o.Cooldown = 10 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Checker{o: o, st: map[string]*Circuit{}}
}

// Run probes on every interval until ctx ends.
func (c *Checker) Run(ctx context.Context) {
	t := time.NewTicker(c.o.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Tick(ctx)
		}
	}
}

// Tick probes every instance once (unhealthy ones only after their cool-down).
func (c *Checker) Tick(ctx context.Context) {
	now := c.o.Now()
	live := map[string]bool{}
	for _, reg := range c.o.Registry.Registrations() {
		if c.o.Registry.State(reg.Module) == registry.StateRevoked {
			continue
		}
		for _, in := range reg.Instances {
			key := reg.Module + "/" + in.ID
			live[key] = true
			c.mu.Lock()
			s := c.st[key]
			if s == nil {
				s = &Circuit{Threshold: c.o.Threshold, Cooldown: c.o.Cooldown}
				c.st[key] = s
			}
			probe := s.ShouldProbe(now)
			c.mu.Unlock()
			if !probe {
				continue
			}
			pctx, cancel := context.WithTimeout(ctx, c.o.Timeout)
			err := c.o.Probe(pctx, reg.Identity, in)
			cancel()
			c.Report(ctx, reg.Module, in.ID, err == nil)
		}
	}
	// Forget instances that left the registry.
	c.mu.Lock()
	next := make(map[string]*Circuit, len(c.st))
	for k, v := range c.st {
		if live[k] {
			next[k] = v
		}
	}
	c.st = next
	c.mu.Unlock()
}

// Report feeds an observation (from a probe or from real traffic).
func (c *Checker) Report(ctx context.Context, module, instance string, ok bool) {
	key := module + "/" + instance
	c.mu.Lock()
	s := c.st[key]
	if s == nil {
		s = &Circuit{Threshold: c.o.Threshold, Cooldown: c.o.Cooldown}
		c.st[key] = s
	}
	flipped := s.Observe(ok, c.o.Now())
	healthy := !s.open
	c.mu.Unlock()
	if flipped {
		c.o.Logger.Info("module instance health changed", "module", module, "instance", instance, "healthy", healthy)
		c.o.Registry.SetHealth(ctx, module, instance, healthy)
	}
}

// Healthy reports the checker's view of an instance (unknown = healthy).
func (c *Checker) Healthy(module, instance string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.st[module+"/"+instance]
	return s == nil || !s.Open()
}

// DefaultProber reaches the instance over the channel with the gateway's
// SVID and the module's pinned identity: an HTTP request to the backend root
// (any response counts) or, for gRPC-only backends, a TLS handshake.
func DefaultProber(rt transport.Runtime) Prober {
	return func(ctx context.Context, id string, in registry.Instance) error {
		expected, err := identity.ParseSPIFFEID(id)
		if err != nil {
			return err
		}
		if in.Backend.HTTPURL != "" {
			client, err := thttp.NewClient(rt, expected)
			if err != nil {
				return err
			}
			defer client.CloseIdleConnections()
			req, err := http.NewRequestWithContext(ctx, http.MethodHead, in.Backend.HTTPURL+"/", nil)
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			_ = resp.Body.Close()
			return nil
		}
		cfg, err := tlsconf.ClientConfig(rt.Provider(), expected, transport.TLSOptions(rt))
		if err != nil {
			return err
		}
		d := tls.Dialer{NetDialer: &net.Dialer{}, Config: cfg}
		conn, err := d.DialContext(ctx, "tcp", in.Backend.GRPCTarget)
		if err != nil {
			return err
		}
		return conn.Close()
	}
}
