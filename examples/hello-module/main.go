// Command hello-module is the smallest gateway-registered module: a Freya
// service with a public and a protected HTTP route and one gRPC method, which
// registers its manifest with the gateway and keeps the lease alive.
//
//	go run ./examples/hello-module -config deploy/hello.yaml
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-freya/freya"
	"github.com/go-freya/freya/authn"
	"github.com/go-freya/freya/config"
	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
	"github.com/go-freya/freya/services/auth/pkg/authclient"
	hellov1 "github.com/go-freya/freya/services/gateway/examples/hello-module/api/hello/v1"
	"github.com/go-freya/freya/services/gateway/pkg/gatewayclient"
)

type helloServer struct {
	hellov1.UnimplementedHelloServer
}

func (helloServer) Say(ctx context.Context, req *hellov1.SayRequest) (*hellov1.SayResponse, error) {
	id, ok := authclient.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	peer, _ := authn.FromContext(ctx)
	name := req.GetName()
	if name == "" {
		name = id.UserID
	}
	return &hellov1.SayResponse{Greeting: "hello, " + name, Caller: peer.ServiceName}, nil
}

func main() {
	path := flag.String("config", "deploy/hello.yaml", "config file")
	issuer := flag.String("issuer", "https://localhost:8443", "platform token issuer")
	flag.Parse()
	cfg, err := config.Load(*path)
	if err != nil {
		fail(err)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	app, err := freya.New(cfg, freya.WithLogger(slog.NewJSONHandler(os.Stdout, nil)))
	if err != nil {
		fail(err)
	}
	defer app.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Tokens forwarded by the gateway are verified against the auth module's keys.
	authConn, err := app.Client(ctx, "auth")
	if err != nil {
		fail(err)
	}
	verifier := authclient.New(authclient.Config{Issuer: *issuer}, authclient.GRPCKeys{Client: authv1.NewKeysClient(authConn)}, authclient.GRPCRevocations{Client: authv1.NewSessionsClient(authConn)})
	if err := verifier.Start(ctx, func(err error) { log.Warn("verifier", "err", err) }); err != nil {
		fail(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/hello", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"greeting": "hello, world", "request_id": r.Header.Get("X-Request-Id"), "via": r.Header.Get("X-Gateway-Module")})
	})
	protected := authclient.Middleware(verifier)
	mux.Handle("POST /api/hello", protected(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := authclient.FromContext(r.Context())
		var in struct{ Name string }
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in)
		if in.Name == "" {
			in.Name = id.UserID
		}
		writeJSON(w, map[string]string{"greeting": "hello, " + in.Name, "tenant": id.TenantID})
	})))
	if dist, ok := remoteDist(); ok {
		mux.Handle("GET /ui/", http.StripPrefix("/ui", remoteHandler(dist)))
	}
	app.HTTP().HandlePrefix("/", mux)
	app.GRPC().Use("/hello.v1.Hello/*", authclient.KratosMiddleware(verifier))
	hellov1.RegisterHelloServer(app.GRPC(), helloServer{})

	go func() {
		if err := app.Run(ctx); err != nil {
			log.Error("run", "err", err)
			stop()
		}
	}()
	waitReady(ctx, app)
	httpEP, _ := app.HTTP().Endpoint()
	grpcEP, _ := app.GRPC().Endpoint()
	gwConn, err := app.Client(ctx, "gateway")
	if err != nil {
		fail(err)
	}
	client, err := gatewayclient.New(gwConn, gatewayclient.Options{Manifest: helloManifest(), HTTPURL: "https://" + httpEP.Host, GRPCTarget: grpcEP.Host, Logger: log,
		OnState: func(s gatewayclient.State) {
			log.Info("gateway lease", "registered", s.Registered, "lease", s.LeaseID, "err", s.Err)
		}})
	if err != nil {
		fail(err)
	}
	if err := client.Run(ctx); err != nil {
		fail(err)
	}
}

func waitReady(ctx context.Context, app *freya.App) {
	for ctx.Err() == nil && !app.Ready() {
		time.Sleep(100 * time.Millisecond)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "hello-module:", err)
	os.Exit(1)
}
