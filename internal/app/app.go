// Package app wires the gateway: configuration → Freya runtime → store and
// audit → public edge listener (shell, gateway API, module traffic) and the
// private gateway.v1 registry on the Freya gRPC server. cmd/gatewaysvc and
// the integration harness both use it.
package app

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-freya/freya"
	fidentity "github.com/go-freya/freya/identity"
	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
	"github.com/go-freya/freya/services/auth/pkg/authclient"
	gatewayv1 "github.com/go-freya/freya/services/gateway/api/proto/gateway/v1"
	"github.com/go-freya/freya/services/gateway/internal/audit"
	"github.com/go-freya/freya/services/gateway/internal/authz"
	"github.com/go-freya/freya/services/gateway/internal/authz/bind"
	"github.com/go-freya/freya/services/gateway/internal/config"
	"github.com/go-freya/freya/services/gateway/internal/grpcapi"
	"github.com/go-freya/freya/services/gateway/internal/health"
	"github.com/go-freya/freya/services/gateway/internal/httpapi"
	"github.com/go-freya/freya/services/gateway/internal/identity"
	"github.com/go-freya/freya/services/gateway/internal/manifest"
	"github.com/go-freya/freya/services/gateway/internal/proxy/grpcproxy"
	"github.com/go-freya/freya/services/gateway/internal/proxy/grpcweb"
	"github.com/go-freya/freya/services/gateway/internal/proxy/httpproxy"
	"github.com/go-freya/freya/services/gateway/internal/registry"
	"github.com/go-freya/freya/services/gateway/internal/registry/registrydb"
	"github.com/go-freya/freya/services/gateway/internal/store"
	"github.com/go-freya/freya/services/gateway/internal/storeadapter"
	"github.com/go-freya/freya/services/gateway/internal/stream"
	"github.com/go-freya/freya/services/gateway/internal/stream/valkeykv"
	"github.com/go-freya/freya/services/lcm/pkg/lcmidentity"
	"github.com/go-freya/freya/transport/edge"
)

// Options override infrastructure (tests) and attach story handlers.
type Options struct {
	Logger   slog.Handler
	Shell    fs.FS                    // nil = no shell
	Audit    audit.Inserter           // nil = the store
	KV       registry.KV              // nil = Valkey from config
	Registry gatewayv1.RegistryServer // nil = the registry server
	// Verifier overrides the token verifier (tests); nil = keys and revocations from the auth module.
	Verifier identity.Verifier
	// AuthModule is the module whose Set-Cookie/Cookie are relayed (default "auth").
	AuthModule string
	HTTP       []httpapi.Option
	Freya      []freya.Option
	Migrate    bool
}

// App is the wired service.
type App struct {
	Cfg      config.Config
	Log      *slog.Logger
	Freya    *freya.App
	Store    *store.Store
	Audit    *audit.Writer
	HTTP     *httpapi.Server
	KV       registry.KV
	Reg      *registry.Registry
	Health   *health.Checker
	Dispatch *httpapi.Dispatcher
	Identity *identity.Resolver
	Decider  *authz.Decider
	GRPC     *grpcproxy.Proxy
	Revoke   *identity.RevocationWatcher
	Hub      *stream.Hub

	verifier *authclient.Verifier
	vready   atomic.Bool
	authz    authv1.AuthorizationClient
	closers  []func()
}

// Ready reports whether the gateway can serve every kind of caller: the Freya
// runtime is ready and the token verifier has synced keys and revocations.
func (a *App) Ready() bool {
	return a.Freya.Ready() && (a.verifier == nil || a.vready.Load())
}

// Build validates the configuration and wires everything; Run starts it.
func Build(ctx context.Context, cfg config.Config, o Options) (a *App, err error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	handler := o.Logger
	if handler == nil {
		handler = slog.NewJSONHandler(os.Stderr, nil)
	}
	log := slog.New(handler)
	for _, w := range cfg.Warnings() {
		log.Warn(w)
	}
	built := &App{Cfg: cfg, Log: log}
	defer func() {
		if err != nil {
			built.Close()
		}
	}()
	if o.Migrate {
		dsn := cfg.DB.MigrateDSN
		if dsn == "" {
			dsn = cfg.DB.DSN
		}
		if err := store.Migrate(ctx, dsn); err != nil {
			return nil, err
		}
	}
	if built.Store, err = store.Open(ctx, cfg.DB.DSN, cfg.DB.MaxConns); err != nil {
		return nil, err
	}
	built.closers = append(built.closers, built.Store.Close)
	ins := o.Audit
	if ins == nil {
		ins = built.Store
	}
	built.Audit = audit.NewWriter(ins, func(err error) { log.Error("audit write failed", "err", err) })
	built.closers = append(built.closers, built.Audit.Close)
	fopts := append([]freya.Option{freya.WithLogger(handler)}, o.Freya...)
	if cfg.Enroll.Enabled {
		raw, rerr := os.ReadFile(cfg.Enroll.TokenFile)
		if rerr != nil {
			return nil, fmt.Errorf("gateway: enroll token: %w", rerr)
		}
		prov, perr := lcmidentity.NewNet(ctx, lcmidentity.NetConfig{
			EnrollURL: cfg.Enroll.EnrollURL, LCMGRPCTarget: cfg.Enroll.LCMGRPCTarget,
			TenantID: cfg.Enroll.TenantID, TrustDomain: cfg.Config.TrustDomain, ServiceName: cfg.Config.ServiceName,
			EnrollmentToken: strings.TrimSpace(string(raw)), Insecure: cfg.Enroll.Insecure, StateFile: cfg.Enroll.StateFile,
		})
		if perr != nil {
			return nil, fmt.Errorf("gateway: enroll: %w", perr)
		}
		built.closers = append(built.closers, func() { _ = prov.Close() })
		fopts = append(fopts, freya.WithIdentityProvider(prov))
	}
	if built.Freya, err = freya.New(cfg.Config, fopts...); err != nil {
		return nil, err
	}
	built.closers = append(built.closers, built.Freya.Close)
	hopts := append([]httpapi.Option(nil), o.HTTP...)
	if o.Shell != nil {
		hopts = append(hopts, httpapi.WithShell(o.Shell))
	}
	ec := edge.Config{Addr: cfg.Edge.Addr, Env: cfg.Env, CertFile: cfg.Edge.CertFile, KeyFile: cfg.Edge.KeyFile,
		AllowedOrigins: cfg.Edge.AllowedOrigins, TrustedProxies: cfg.Edge.TrustedProxies, RateLimit: cfg.Edge.RateLimit}
	if built.HTTP, err = httpapi.New(built.Freya, ec, hopts...); err != nil {
		return nil, err
	}
	built.Freya.AddServer(built.HTTP)
	built.KV = o.KV
	if built.KV == nil {
		vc := registrydb.Config{Addresses: cfg.Valkey.Addresses, Username: cfg.Valkey.Username, Password: cfg.Valkey.Password, AllowPlaintext: cfg.Valkey.AllowPlaintext}
		if cfg.Valkey.CAFile != "" {
			if vc.CAPEM, err = os.ReadFile(cfg.Valkey.CAFile); err != nil {
				return nil, fmt.Errorf("valkey ca: %w", err)
			}
		}
		if built.KV, err = registrydb.New(vc); err != nil {
			return nil, err
		}
		built.closers = append(built.closers, built.KV.Close)
	}
	adapter := storeadapter.New(built.Store)
	// Platform realtime event bus: a Valkey-Streams hub any module publishes to
	// (shared key platform:events:<tenant>) and the gateway fans out to signed-in
	// browsers over one SSE endpoint. Separate Valkey client from the registry KV
	// because it speaks stream commands (XADD/XREAD/XRANGE).
	{
		sc := valkeykv.Config{Addresses: cfg.Valkey.Addresses, Username: cfg.Valkey.Username, Password: cfg.Valkey.Password, AllowPlaintext: cfg.Valkey.AllowPlaintext}
		if cfg.Valkey.CAFile != "" {
			if sc.CAPEM, err = os.ReadFile(cfg.Valkey.CAFile); err != nil {
				return nil, fmt.Errorf("valkey ca: %w", err)
			}
		}
		streamClient, serr := valkeykv.New(sc)
		if serr != nil {
			return nil, fmt.Errorf("event stream: %w", serr)
		}
		built.Hub = stream.NewHub(streamClient, stream.Config{}, log)
		built.closers = append(built.closers, built.Hub.Close)
	}
	if built.Reg, err = registry.New(registry.Options{KV: built.KV, Allow: adapter, Marks: adapter, Audit: built.Audit, TTL: cfg.Leases.TTL, Renew: cfg.Leases.Renew, Logger: log,
		OnAccepted: func(ctx context.Context, m manifest.Manifest) {
			if built.authz == nil {
				return
			}
			go func() {
				if err := built.registerPermissions(context.WithoutCancel(ctx), built.authz, m); err != nil {
					log.Warn("permission registration with auth failed", "module", m.Module, "err", err)
				}
			}()
		}}); err != nil {
		return nil, err
	}
	if err = built.Reg.Load(ctx); err != nil {
		return nil, err
	}
	built.Health = health.New(health.Options{Registry: built.Reg, Probe: health.DefaultProber(built.Freya), Logger: log})
	authModule := o.AuthModule
	if authModule == "" {
		authModule = "auth"
	}
	publicHost := strings.TrimPrefix(cfg.PublicOrigin, "https://")
	built.Dispatch = &httpapi.Dispatcher{Reg: built.Reg, Health: built.Health, Audit: built.Audit, Logger: log, NotOwned: built.HTTP.NotOwned, AuthModule: authModule,
		Limits: httpapi.Limits{BodyBytes: cfg.Forward.BodyBytes, ModuleTimeout: cfg.Forward.ModuleTimeout},
		Proxies: func(module string, id fidentity.SPIFFEID, target string) (httpapi.Backend, error) {
			return httpproxy.New(built.Freya, httpproxy.Options{Module: module, Identity: id, Target: target, PublicHost: publicHost, AllowCookies: module == authModule})
		}}
	built.HTTP.SetForwarder(built.Dispatch)

	// Identity and decisions come from the auth module over the channel.
	authConn, err := built.Freya.Client(ctx, cfg.Auth.Service)
	if err != nil {
		return nil, fmt.Errorf("auth module: %w", err)
	}
	var verifier identity.Verifier = o.Verifier
	if verifier == nil {
		built.verifier = authclient.New(authclient.Config{Issuer: cfg.Auth.Issuer, RevocationPoll: 5 * time.Second},
			authclient.GRPCKeys{Client: authv1.NewKeysClient(authConn)}, authclient.GRPCRevocations{Client: authv1.NewSessionsClient(authConn), Limit: 1000})
		verifier = built.verifier
	}
	if built.Identity, err = identity.New(identity.Options{Sessions: authv1.NewSessionsClient(authConn), Verifier: verifier, KV: built.KV, Audit: built.Audit}); err != nil {
		return nil, err
	}
	built.authz = authv1.NewAuthorizationClient(authConn)
	if built.Decider, err = authz.New(authz.Options{Client: built.authz, KV: built.KV, Audit: built.Audit}); err != nil {
		return nil, err
	}
	built.Dispatch.Auth = &bind.HTTPAuthorizer{Identity: built.Identity, Decider: built.Decider}
	built.Dispatch.OnSignOut = built.Identity.Invalidate
	built.Dispatch.OnIdentityRefresh = built.Identity.Invalidate
	director := &bind.Director{Reg: built.Reg, Identity: built.Identity, Decider: built.Decider, StreamMax: cfg.Forward.StreamMax, UnaryTimeout: cfg.Forward.ModuleTimeout}
	if built.GRPC, err = grpcproxy.New(built.Freya, grpcproxy.Options{Director: director, StreamsPerClient: cfg.Forward.StreamsPerClient, DefaultMax: cfg.Forward.StreamMax,
		Observe: func(r grpcproxy.Route, err error) {
			if r.Instance != "" {
				code := status.Code(err)
				built.Health.Report(context.Background(), r.Module, r.Instance, code != codes.Unavailable)
			}
		}}); err != nil {
		return nil, err
	}
	built.closers = append(built.closers, built.GRPC.Close)
	built.Dispatch.GRPC = built.GRPC.Server()
	built.Dispatch.GRPCWeb = &grpcweb.Bridge{Proxy: built.GRPC, MaxFrame: int(cfg.Forward.BodyBytes)}
	built.Dispatch.Traffic = httpapi.NewTraffic()
	built.HTTP.RegisterMe(built.Identity)
	built.HTTP.RegisterOps(httpapi.OpsDeps{Reg: built.Reg, Ops: &registry.Ops{Reg: built.Reg, Marks: adapter, Allow: adapter, Audit: built.Audit}, Identity: built.Identity, Audit: adapter, Traffic: built.Dispatch.Traffic, Roles: cfg.Operators.Roles})
	built.HTTP.RegisterShell(httpapi.ShellDeps{Reg: built.Reg, Identity: built.Identity, Decide: built.Decider, Proxies: built.Dispatch.Proxies, Hub: built.Hub, Instance: hostname()})
	built.Revoke = &identity.RevocationWatcher{Feed: authv1.NewSessionsClient(authConn), Poll: 5 * time.Second, Logger: log,
		OnRevoke: func(subject, reason string) { built.GRPC.CancelSubject(subject, reason) }}
	rs := o.Registry
	if rs == nil {
		rs = &grpcapi.RegistryServer{Reg: built.Reg}
	}
	grpcapi.Register(built.Freya.GRPC(), rs)
	return built, nil
}

// Run serves until ctx is cancelled: registry sweeps, health probes and the
// Freya application (gRPC registry + public edge).
func (a *App) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		if err := a.Reg.Run(ctx); err != nil {
			a.Log.Error("registry stopped", "err", err)
		}
	}()
	go a.Health.Run(ctx)
	go a.Revoke.Run(ctx)
	go a.permissionSyncLoop(ctx)
	if a.verifier != nil {
		go a.startVerifier(ctx)
	}
	return a.Freya.Run(ctx)
}

// startVerifier keeps trying until the auth module answers; until then every
// credential is refused as temporarily unavailable (fail closed).
func (a *App) startVerifier(ctx context.Context) {
	for ctx.Err() == nil {
		err := a.verifier.Start(ctx, func(err error) { a.Log.Warn("token verifier", "err", err) })
		if err == nil {
			a.vready.Store(true)
			a.Log.Info("token verifier ready")
			return
		}
		a.Log.Warn("token verifier not ready; retrying", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// Close releases resources in reverse order.
func (a *App) Close() {
	for i := len(a.closers) - 1; i >= 0; i-- {
		a.closers[i]()
	}
	a.closers = nil
}

// hostname returns this instance's host name for SSE "connected" comments.
func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "gateway"
	}
	return h
}
