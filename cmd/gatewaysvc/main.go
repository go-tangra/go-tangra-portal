// Command gatewaysvc runs the application gateway (default) or seeds the
// registrant allow-list: `gatewaysvc bootstrap -config deploy/dev.yaml
// -allow "spiffe://example.org/svc/auth=/api/v1,/authorize,/.well-known;auth"`.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-freya/freya/services/gateway/internal/app"
	"github.com/go-freya/freya/services/gateway/internal/config"
	"github.com/go-freya/freya/services/gateway/shell"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "bootstrap" {
		os.Exit(bootstrap(os.Args[2:]))
	}
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("gatewaysvc", flag.ContinueOnError)
	cfgPath := fs.String("config", "deploy/dev.yaml", "configuration file")
	noMigrate := fs.Bool("no-migrate", false, "do not apply database migrations on start")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	opts := app.Options{Migrate: !*noMigrate}
	if dist, ok := shell.Dist(); ok {
		opts.Shell = dist
	}
	a, err := app.Build(ctx, cfg, opts)
	if err != nil {
		return fail(err)
	}
	defer a.Close()
	if ep, err := a.HTTP.Edge().Endpoint(); err == nil {
		fmt.Fprintln(os.Stderr, "gatewaysvc: edge listening on", ep.String())
	}
	if ep, err := a.Freya.GRPC().Endpoint(); err == nil {
		fmt.Fprintln(os.Stderr, "gatewaysvc: registry listening on", ep.String())
	}
	if err := a.Run(ctx); err != nil {
		return fail(err)
	}
	return 0
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "gatewaysvc:", err)
	return 1
}
