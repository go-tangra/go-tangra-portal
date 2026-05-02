package main

import (
	"context"
	"fmt"
	"os"

	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/transport/grpc"
	"github.com/go-kratos/kratos/v2/transport/http"
	"github.com/tx7do/kratos-transport/transport/sse"

	conf "github.com/tx7do/kratos-bootstrap/api/gen/go/conf/v1"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	commonCert "github.com/go-tangra/go-tangra-common/cert"

	//_ "github.com/tx7do/kratos-bootstrap/config/apollo"
	//_ "github.com/tx7do/kratos-bootstrap/config/consul"
	//_ "github.com/tx7do/kratos-bootstrap/config/etcd"
	//_ "github.com/tx7do/kratos-bootstrap/config/kubernetes"
	//_ "github.com/tx7do/kratos-bootstrap/config/nacos"
	//_ "github.com/tx7do/kratos-bootstrap/config/polaris"

	//_ "github.com/tx7do/kratos-bootstrap/logger/aliyun"
	//_ "github.com/tx7do/kratos-bootstrap/logger/fluent"
	//_ "github.com/tx7do/kratos-bootstrap/logger/logrus"
	//_ "github.com/tx7do/kratos-bootstrap/logger/tencent"
	//_ "github.com/tx7do/kratos-bootstrap/logger/zap"
	//_ "github.com/tx7do/kratos-bootstrap/logger/zerolog"

	//_ "github.com/tx7do/kratos-bootstrap/registry/consul"
	//_ "github.com/tx7do/kratos-bootstrap/registry/etcd"
	//_ "github.com/tx7do/kratos-bootstrap/registry/eureka"
	//_ "github.com/tx7do/kratos-bootstrap/registry/kubernetes"
	//_ "github.com/tx7do/kratos-bootstrap/registry/nacos"
	//_ "github.com/tx7do/kratos-bootstrap/registry/polaris"
	//_ "github.com/tx7do/kratos-bootstrap/registry/servicecomb"
	//_ "github.com/tx7do/kratos-bootstrap/registry/zookeeper"

	//_ "github.com/tx7do/kratos-bootstrap/tracer"

	"github.com/go-tangra/go-tangra-portal/pkg/service"
)

var version = "1.0.0"

// go build -ldflags "-X main.version=x.y.z"

func newApp(
	ctx *bootstrap.Context,
	hs *http.Server,
	gs *grpc.Server,
	ss *sse.Server,
) *kratos.App {
	return bootstrap.NewApp(ctx,
		hs,
		gs,
		ss,
	)
}

func runApp() error {
	// registration-rework Phase 1 — admin-service self-bootstraps its
	// mTLS certs against LCM:9101 *before* the wire graph builds the
	// transcoder. The transcoder loads /app/certs/ca/ca.crt at
	// construction time; if those files don't exist yet it silently
	// falls back to insecure outbound connections, which then time out
	// because every module requires mTLS. Calling Ensure here, ahead
	// of bootstrap.RunApp, guarantees the files are on disk before any
	// downstream component (transcoder, mTLS server) initializes.
	bootLogger := log.NewStdLogger(os.Stdout)
	if _, err := commonCert.Ensure(context.Background(), commonCert.EnsureConfig{
		ModuleID: "admin",
		Logger:   bootLogger,
	}); err != nil {
		return fmt.Errorf("cert bootstrap: %w", err)
	}

	ctx := bootstrap.NewContext(
		context.Background(),
		&conf.AppInfo{
			Project: service.Project,
			AppId:   service.AdminService,
			Version: version,
		},
	)
	return bootstrap.RunApp(ctx, initApp)
}

func main() {
	if err := runApp(); err != nil {
		panic(err)
	}
}
