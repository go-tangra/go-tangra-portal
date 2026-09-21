package gatewayclient

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"

	gatewayv1 "github.com/go-freya/freya/services/gateway/api/proto/gateway/v1"
)

// Manifest builds a gateway.v1.Manifest from typed values. Zero values are
// omitted; the gateway validates the result against the published schema.
type Manifest struct {
	Module      string
	DisplayName string
	Version     string
	Prefixes    []string
	Routes      []Route
	Methods     []Method
	Permissions []Permission
	Abilities   []Ability
	Exposes     []string // Module Federation exposes, e.g. "./routes", "./nav"
	Integrity   string   // optional SRI of the remote entry
	Nav         []NavEntry
}

// Route is an HTTP route; exactly one of Permission or Public must be set.
type Route struct {
	Method, Path string
	Permission   string
	Public       bool
	MaxBodyBytes uint64
	Timeout      time.Duration
	// ClientAddress asks the gateway to forward the client IP as
	// X-Gateway-Client-Addr on this route (never set on other routes).
	ClientAddress bool
}

// Method is a gRPC method; exactly one of Permission or Public must be set.
type Method struct {
	FullMethod        string
	Permission        string
	Public            bool
	Streaming         bool
	MaxStreamDuration time.Duration
}

// Permission is an API permission (resource:action) the module registers.
type Permission struct{ Resource, Action, Description string }

// Ability is a CASL rule bound to an API permission (Requires = "resource:action").
type Ability struct {
	Action, Subject []string
	Fields          []string
	Conditions      map[string]any
	Inverted        bool
	Reason          string
	Requires        string
}

// NavEntry is a navigation contribution.
type NavEntry struct {
	Title, Path, Icon string
	Order             int32
	Requires          string
}

// Perm formats a permission reference.
func Perm(resource, action string) string { return resource + ":" + action }

// Proto converts the manifest to its wire form.
func (m Manifest) Proto() (*gatewayv1.Manifest, error) {
	if m.Module == "" {
		return nil, fmt.Errorf("gatewayclient: module name is required")
	}
	out := &gatewayv1.Manifest{Module: m.Module, DisplayName: m.DisplayName, Version: m.Version, Prefixes: m.Prefixes,
		Remote: &gatewayv1.Remote{Entry: "/m/" + m.Module + "/mf-manifest.json", Exposes: m.Exposes, Integrity: m.Integrity}}
	for _, r := range m.Routes {
		pr := &gatewayv1.Route{Method: r.Method, Path: r.Path, Permission: r.Permission, Public: r.Public, MaxBodyBytes: r.MaxBodyBytes, ClientAddress: r.ClientAddress}
		if r.Timeout > 0 {
			pr.Timeout = durationpb.New(r.Timeout)
		}
		out.Routes = append(out.Routes, pr)
	}
	for _, mt := range m.Methods {
		pm := &gatewayv1.Method{FullMethod: mt.FullMethod, Permission: mt.Permission, Public: mt.Public, Streaming: mt.Streaming}
		if mt.MaxStreamDuration > 0 {
			pm.MaxStreamDuration = durationpb.New(mt.MaxStreamDuration)
		}
		out.Methods = append(out.Methods, pm)
	}
	for _, p := range m.Permissions {
		out.Permissions = append(out.Permissions, &gatewayv1.Permission{Resource: p.Resource, Action: p.Action, Description: p.Description})
	}
	for _, a := range m.Abilities {
		pa := &gatewayv1.Ability{Action: a.Action, Subject: a.Subject, Fields: a.Fields, Inverted: a.Inverted, Reason: a.Reason, Requires: a.Requires}
		if len(a.Conditions) > 0 {
			st, err := structpb.NewStruct(a.Conditions)
			if err != nil {
				return nil, fmt.Errorf("gatewayclient: ability conditions: %w", err)
			}
			pa.Conditions = st
		}
		out.Abilities = append(out.Abilities, pa)
	}
	for _, n := range m.Nav {
		out.Nav = append(out.Nav, &gatewayv1.NavEntry{Title: n.Title, Path: n.Path, Icon: n.Icon, Order: n.Order, Requires: n.Requires})
	}
	return out, nil
}
