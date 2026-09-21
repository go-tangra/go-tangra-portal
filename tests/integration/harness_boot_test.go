//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
)

func TestHarnessBoots(t *testing.T) {
	e := Start(t)
	if code, body := e.JSON(http.MethodGet, "/gateway/v1/me", nil); code != 501 && code != 401 {
		t.Fatalf("me → %d %v", code, body)
	}
	if code, body := e.JSON(http.MethodGet, "/api/nowhere", nil); code != 404 || body["reason"] != "not_found" {
		t.Fatalf("unowned path → %d %v", code, body)
	}
	// The gateway reaches the auth module over mTLS and is allowed to call Exchange.
	conn, err := e.Gateway.Freya.Client(context.Background(), "auth")
	if err != nil {
		t.Fatal(err)
	}
	_, err = authv1.NewSessionsClient(conn).Exchange(context.Background(), &authv1.ExchangeRequest{CookieSecret: "garbage"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("exchange with a garbage cookie: %v", err)
	}
	// A test module boots with its own identity and serves over the Freya channel.
	m := e.StartModule("alpha", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), nil)
	if m.HTTPURL == "" || m.GRPCTarget == "" {
		t.Fatalf("%+v", m)
	}
	e.Allow("alpha", []string{"/api/alpha"}, []string{"alpha"})
}
