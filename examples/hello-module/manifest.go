package main

import (
	"time"

	"github.com/go-freya/freya/services/gateway/pkg/gatewayclient"
)

// helloManifest declares what the module exposes through the gateway: one
// public and one protected HTTP route, one protected gRPC method, the API
// permission both protected entries require, the CASL ability the shell
// derives from it and a navigation entry.
func helloManifest() gatewayclient.Manifest {
	return gatewayclient.Manifest{
		Module:      "hello",
		DisplayName: "Hello",
		Version:     "1.0.0",
		Prefixes:    []string{"/api/hello"},
		Routes: []gatewayclient.Route{
			{Method: "GET", Path: "/api/hello", Public: true, Timeout: 5 * time.Second},
			{Method: "POST", Path: "/api/hello", Permission: gatewayclient.Perm("hello", "say"), MaxBodyBytes: 4096},
		},
		Methods:     []gatewayclient.Method{{FullMethod: "/hello.v1.Hello/Say", Permission: gatewayclient.Perm("hello", "say")}},
		Permissions: []gatewayclient.Permission{{Resource: "hello", Action: "say", Description: "Send a greeting"}},
		Abilities:   []gatewayclient.Ability{{Action: []string{"create"}, Subject: []string{"Greeting"}, Requires: gatewayclient.Perm("hello", "say")}},
		Exposes:     []string{"./routes"},
		Nav:         []gatewayclient.NavEntry{{Title: "Hello", Path: "/hello", Icon: "mdi-hand-wave-outline", Order: 90, Requires: gatewayclient.Perm("hello", "say")}},
	}
}
