package grpcapi

import (
	"testing"

	"google.golang.org/grpc"
)

func TestRegisterMountsRegistry(t *testing.T) {
	s := grpc.NewServer()
	Register(s, nil)
	info := s.GetServiceInfo()
	svc, ok := info["gateway.v1.Registry"]
	if !ok || len(svc.Methods) != 4 {
		t.Fatalf("%+v", info)
	}
}
