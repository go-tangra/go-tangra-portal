// Package app wires the gateway: configuration → Freya runtime → store and
// audit → public edge listener (shell, gateway API, module traffic) and the
// private gateway.v1 registry on the Freya gRPC server. cmd/gatewaysvc and
// the integration harness both use it.
package app

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	inventoryv1 "github.com/go-tangra/go-tangra-inventory/sdk/v4/api/proto/inventory/v1"
	"github.com/go-tangra/go-tangra-lcm/sdk/v4/pkg/lcmidentity"
	gatewayv1 "github.com/go-tangra/go-tangra-portal/sdk/v4/api/proto/gateway/v1"
	"github.com/go-tangra/go-tangra-portal/v4/internal/audit"
	"github.com/go-tangra/go-tangra-portal/v4/internal/authz"
	"github.com/go-tangra/go-tangra-portal/v4/internal/authz/bind"
	"github.com/go-tangra/go-tangra-portal/v4/internal/catalogue"
	"github.com/go-tangra/go-tangra-portal/v4/internal/config"
	"github.com/go-tangra/go-tangra-portal/v4/internal/console"
	"github.com/go-tangra/go-tangra-portal/v4/internal/grpcapi"
	"github.com/go-tangra/go-tangra-portal/v4/internal/health"
	"github.com/go-tangra/go-tangra-portal/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra-portal/v4/internal/identity"
	"github.com/go-tangra/go-tangra-portal/v4/internal/known"
	"github.com/go-tangra/go-tangra-portal/v4/internal/manifest"
	"github.com/go-tangra/go-tangra-portal/v4/internal/proxy/grpcproxy"
	"github.com/go-tangra/go-tangra-portal/v4/internal/proxy/grpcweb"
	"github.com/go-tangra/go-tangra-portal/v4/internal/proxy/httpproxy"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry"
	"github.com/go-tangra/go-tangra-portal/v4/internal/registry/registrydb"
	"github.com/go-tangra/go-tangra-portal/v4/internal/store"
	"github.com/go-tangra/go-tangra-portal/v4/internal/storeadapter"
	"github.com/go-tangra/go-tangra-portal/v4/internal/stream"
	"github.com/go-tangra/go-tangra-portal/v4/internal/stream/valkeykv"
	"github.com/go-tangra/go-tangra/v4"
	fconfig "github.com/go-tangra/go-tangra/v4/config"
	fidentity "github.com/go-tangra/go-tangra/v4/identity"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
	thttp "github.com/go-tangra/go-tangra/v4/transport/http"
	"github.com/go-tangra/go-tangra/v4/transport/tlsconf"
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
	// Known records the modules the registry has seen (module catalogue).
	Known *known.Recorder
	// Catalogue reads and verifies module releases (catalogue sources).
	Catalogue *catalogue.Service
	Hub       *stream.Hub
	Console   *console.Server // nil unless console.enabled

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
	var meshProvider fidentity.Provider // the gateway's own identity (mesh CA for join bundles)
	if cfg.Enroll.Enabled {
		raw, rerr := os.ReadFile(cfg.Enroll.TokenFile)
		if rerr != nil {
			return nil, fmt.Errorf("gateway: enroll token: %w", rerr)
		}
		// First-enroll server verification: lcm's SVID against the mesh bundle
		// (enroll.ca_file) or public roots; insecure only outside production.
		var enrollTLS *tls.Config
		if !cfg.Enroll.Insecure {
			if enrollTLS, rerr = tlsconf.LoadEnrollClientConfig(cfg.Enroll.EnrollTLS, cfg.Config.TrustDomain); rerr != nil {
				return nil, fmt.Errorf("gateway: enroll tls: %w", rerr)
			}
		}
		prov, perr := lcmidentity.NewNet(ctx, lcmidentity.NetConfig{
			EnrollURL: cfg.Enroll.EnrollURL, LCMGRPCTarget: cfg.Enroll.LCMGRPCTarget,
			TenantID: cfg.Enroll.TenantID, TrustDomain: cfg.Config.TrustDomain, ServiceName: cfg.Config.ServiceName,
			EnrollmentToken: strings.TrimSpace(string(raw)), EnrollTLS: enrollTLS, Insecure: cfg.Enroll.Insecure,
			StateFile: cfg.Enroll.StateFile,
		})
		if perr != nil {
			return nil, fmt.Errorf("gateway: enroll: %w", perr)
		}
		built.closers = append(built.closers, func() { _ = prov.Close() })
		fopts = append(fopts, freya.WithIdentityProvider(prov))
		meshProvider = prov
	}
	if built.Freya, err = freya.New(cfg.Config, fopts...); err != nil {
		return nil, err
	}
	built.closers = append(built.closers, built.Freya.Close)
	hopts := append([]httpapi.Option(nil), o.HTTP...)
	if o.Shell != nil {
		hopts = append(hopts, httpapi.WithShell(o.Shell))
	}
	if built.HTTP, err = httpapi.New(built.Freya, edgeConfig(cfg), hopts...); err != nil {
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
	built.Dispatch.Traffic = httpapi.NewTraffic()
	// Console listener (feature 025): consoles on an origin of their own.
	if built.Console, err = newConsole(cfg, built.Freya.Limits(), built.Reg,
		func(_ string, id fidentity.SPIFFEID) (http.RoundTripper, error) {
			c, err := thttp.NewClient(built.Freya, id)
			if err != nil {
				return nil, err
			}
			return c.Transport, nil
		}, built.Dispatch.Traffic.Record, log); err != nil {
		return nil, err
	}
	if built.Console != nil {
		built.Freya.AddServer(built.Console)
		log.Info("console listener enabled", "addr", cfg.Console.Addr, "origin", cfg.Console.Origin())
	}

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
	built.HTTP.RegisterMe(built.Identity)
	token := ""
	if cfg.Catalogue.GitHubTokenEnv != "" {
		token = os.Getenv(cfg.Catalogue.GitHubTokenEnv)
	}
	built.Catalogue = &catalogue.Service{Store: adapter, GitHub: &catalogue.GitHub{API: cfg.Catalogue.GitHubAPI, Token: token},
		Verify: catalogue.LazyVerify(catalogue.LiveTrustedRoot), Audit: built.Audit, Logger: log, Interval: cfg.Catalogue.Poll}
	var join *httpapi.JoinDeps
	if j := cfg.Catalogue.Join; j.Configured() {
		join = &httpapi.JoinDeps{Store: adapter, MeshCA: meshCA(meshProvider, j.MeshCAFile), Core: map[string]string{
			"TRUST_DOMAIN": cfg.Config.TrustDomain, "GATEWAY_ISSUER": cfg.Auth.Issuer, "LCM_ENROLL_URL": cfg.JoinEnrollURL(),
			"AUTH_GRPC": j.AuthGRPC, "GATEWAY_GRPC": j.GatewayGRPC, "LCM_GRPC": j.LCMGRPC, "MESH_TENANT_ID": j.MeshTenantID}}
	}
	// Agent delivery (spec 037): the inventory hands bundles to enrolled
	// agents and is the only caller that may render them.
	var inventory inventoryv1.ModuleDeliveryServiceClient
	var bundles inventoryv1.ModuleBundleSourceServer
	if svc := cfg.Catalogue.AgentDelivery.InventoryService; svc != "" && join != nil {
		invConn, err := built.Freya.Client(ctx, svc)
		if err != nil {
			return nil, fmt.Errorf("inventory module: %w", err)
		}
		inventory = inventoryv1.NewModuleDeliveryServiceClient(invConn)
		bundles = &grpcapi.ModuleBundleServer{Caller: "spiffe://" + cfg.Config.TrustDomain + "/svc/" + svc, Joins: adapter, Events: built.Audit, Logger: log,
			Builder: &catalogue.Builder{TrustDomain: cfg.Config.TrustDomain, Core: join.Core, MeshCA: join.MeshCA, Bundle: adapter.EntryBundle,
				Mint: authv1.NewEnrollmentClient(authConn)}}
	}
	built.HTTP.RegisterOps(httpapi.OpsDeps{Reg: built.Reg, Ops: &registry.Ops{Reg: built.Reg, Marks: adapter, Allow: adapter, Audit: built.Audit}, Identity: built.Identity, Audit: adapter, Traffic: built.Dispatch.Traffic, Roles: cfg.Operators.Roles,
		Enroll: authv1.NewEnrollmentClient(authConn), TrustDomain: cfg.Config.TrustDomain, Events: built.Audit, AdminRoles: cfg.Operators.AdminRoles, Known: adapter,
		Sources: adapter, Refresher: built.Catalogue, Join: join, Inventory: inventory})
	built.Known = &known.Recorder{Reg: built.Reg, Store: adapter, Logger: log}
	if err := adapter.SeedAllowedOwners(ctx, cfg.Catalogue.AllowedOwners); err != nil {
		log.Warn("catalogue: allowed owners not seeded; retried at next start")
	}
	built.HTTP.RegisterShell(httpapi.ShellDeps{Reg: built.Reg, Identity: built.Identity, Decide: built.Decider, Proxies: built.Dispatch.Proxies, Hub: built.Hub, Instance: hostname()})
	built.Revoke = &identity.RevocationWatcher{Feed: authv1.NewSessionsClient(authConn), Poll: 5 * time.Second, Logger: log,
		OnRevoke: func(subject, reason string) { built.GRPC.CancelSubject(subject, reason) }}
	rs := o.Registry
	if rs == nil {
		rs = &grpcapi.RegistryServer{Reg: built.Reg}
	}
	grpcapi.Register(built.Freya.GRPC(), rs)
	grpcapi.RegisterModuleBundle(built.Freya.GRPC(), bundles)
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
	if a.Known != nil {
		go func() { _ = a.Known.Run(ctx) }()
	}
	if a.Catalogue != nil {
		go a.Catalogue.Run(ctx)
	}
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

// edgeConfig maps the gateway configuration onto the framework edge; the
// console origin (when enabled) joins the frame sources so the shell may
// embed consoles.
func edgeConfig(cfg config.Config) edge.Config {
	return edge.Config{Addr: cfg.Edge.Addr, Env: cfg.Env, CertFile: cfg.Edge.CertFile, KeyFile: cfg.Edge.KeyFile,
		AllowedOrigins: cfg.Edge.AllowedOrigins, TrustedProxies: cfg.Edge.TrustedProxies, RateLimit: cfg.Edge.RateLimit,
		FrameSources: cfg.FrameSources(), ConnectSources: cfg.Edge.ConnectSources}
}

// newConsole builds the console listener, or nil when it is disabled. It
// reuses the edge certificate and the module forwarding limits.
func newConsole(cfg config.Config, lim fconfig.Limits, reg console.Registry, tf console.TransportFactory,
	onForward func(module string, status int, d time.Duration), log *slog.Logger) (*console.Server, error) {
	if !cfg.Console.Enabled {
		return nil, nil
	}
	h, err := console.NewHandler(console.Options{
		Routes: cfg.Console.RouteMap(), Cookies: cfg.Console.CookieNames(),
		PortalOrigin: cfg.PublicOrigin, ConsoleOrigin: cfg.Console.PublicOrigin,
		Registry: reg, Transport: tf,
		RequestTimeout: cfg.Forward.ModuleTimeout, SessionMax: cfg.Console.SessionMax,
		BodyBytes: cfg.Forward.BodyBytes, MaxConcurrent: cfg.Console.MaxConcurrent,
		Logger: log, OnForward: onForward,
	})
	if err != nil {
		return nil, err
	}
	return console.NewServer(console.ServerOptions{Addr: cfg.Console.Addr, CertFile: cfg.Edge.CertFile, KeyFile: cfg.Edge.KeyFile,
		HandshakeTimeout: lim.HandshakeTimeout, IdleTimeout: lim.IdleTimeout, MaxHeaderBytes: lim.MaxHeaderBytes, Logger: log}, h)
}

// hostname returns this instance's host name for SSE "connected" comments.
func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "gateway"
	}
	return h
}

// meshCA returns the mesh trust bundle for join bundles: the gateway's own
// identity bundle, or mesh_ca_file for gateways with a file identity.
func meshCA(p fidentity.Provider, file string) func(context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		if file != "" {
			b, err := os.ReadFile(file) // #nosec G304 -- operator-configured path
			if err != nil {
				return nil, fmt.Errorf("catalogue.join.mesh_ca_file: %w", err)
			}
			return b, nil
		}
		if p == nil {
			return nil, errors.New("no mesh identity provider: set catalogue.join.mesh_ca_file")
		}
		_, bundle, err := p.Current(ctx)
		if err != nil || bundle == nil || len(bundle.Roots()) == 0 {
			return nil, errors.New("mesh trust bundle unavailable")
		}
		var out []byte
		for _, c := range bundle.Roots() {
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
		}
		return out, nil
	}
}
