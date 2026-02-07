package service

import (
	"context"
	"fmt"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	v1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"

	"github.com/davecgh/go-spew/spew"
)

type SystemService struct {
	v1.UnimplementedSystemServiceServer

	log *log.Helper
}

func NewSystemService(ctx *bootstrap.Context) *SystemService {
	c, ok := ctx.GetCustomConfig("lcm")
	if !ok {
		fmt.Println("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX config not found")
	} else {
		spew.Dump(c)
	}
	return &SystemService{
		log: ctx.NewLoggerHelper("lcm/service/system"),
	}
}

func (s *SystemService) HealthCheck(ctx context.Context, req *v1.HealthCheckRequest) (*v1.HealthCheckResponse, error) {
	s.log.Info("Health check requested")

	return &v1.HealthCheckResponse{
		Status:  true,
		Message: "LCM service is healthy",
	}, nil
}
