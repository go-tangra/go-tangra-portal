package contract

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	gatewayv1 "github.com/go-freya/freya/services/gateway/api/proto/gateway/v1"
	"github.com/go-freya/freya/services/gateway/internal/registry"
)

// TestGatewayV1Shapes pins the wire contract (contracts/gateway.v1.proto).
func TestGatewayV1Shapes(t *testing.T) {
	fd := gatewayv1.File_gateway_v1_gateway_proto
	sd := fd.Services().ByName("Registry")
	if sd == nil {
		t.Fatal("Registry missing")
	}
	for _, m := range []string{"Register", "Renew", "Deregister", "Watch"} {
		if sd.Methods().ByName(protoreflect.Name(m)) == nil {
			t.Errorf("Registry.%s missing", m)
		}
	}
	if !sd.Methods().ByName("Watch").IsStreamingServer() {
		t.Error("Watch must be server-streaming")
	}
	fields := map[string][]string{
		"RegisterRequest": {"manifest", "instance_id", "backend"},
		"Backend":         {"http_url", "grpc_target"},
		"Lease":           {"lease_id", "ttl", "renew_every", "module", "registry_version"},
		"Manifest":        {"module", "display_name", "version", "prefixes", "routes", "methods", "permissions", "abilities", "remote", "nav"},
		"Route":           {"method", "path", "permission", "public", "max_body_bytes", "timeout"},
		"Method":          {"full_method", "permission", "public", "streaming", "max_stream_duration"},
		"Ability":         {"action", "subject", "fields", "conditions", "inverted", "reason", "requires"},
		"Remote":          {"entry", "exposes", "integrity"},
		"RegistryEvent":   {"ts", "kind", "module", "registry_version", "cursor"},
	}
	for msg, names := range fields {
		md := fd.Messages().ByName(protoreflect.Name(msg))
		if md == nil {
			t.Fatalf("message %s missing", msg)
		}
		for _, f := range names {
			if md.Fields().ByName(protoreflect.Name(f)) == nil {
				t.Errorf("%s.%s missing", msg, f)
			}
		}
	}
	want := []string{"registered", "updated", "withdrawn", "drained", "revoked", "unhealthy", "recovered"}
	if len(registry.EventKinds) != len(want) {
		t.Fatalf("event kinds %v", registry.EventKinds)
	}
	for i, k := range want {
		if registry.EventKinds[i] != k || !registry.KnownEvent(k) {
			t.Fatalf("event kind %d: %s", i, registry.EventKinds[i])
		}
	}
	if registry.KnownEvent("exploded") {
		t.Fatal("unknown kind accepted")
	}
}
