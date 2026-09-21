//go:build integration

package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/go-freya/freya/services/gateway/internal/proxy/grpcproxy/echov1"
	"github.com/go-freya/freya/services/gateway/pkg/gatewayclient"
)

// alphaFull declares HTTP routes and gRPC methods, public and protected.
func alphaFull() gatewayclient.Manifest {
	return gatewayclient.Manifest{Module: "alpha", DisplayName: "Alpha", Version: "1.0.0", Prefixes: []string{"/api/alpha"},
		Routes: []gatewayclient.Route{
			{Method: "GET", Path: "/api/alpha/ping", Public: true},
			{Method: "GET", Path: "/api/alpha/secret", Permission: "alpha:read"},
			{Method: "POST", Path: "/api/alpha/items", Permission: "alpha:write", MaxBodyBytes: 64},
		},
		Methods: []gatewayclient.Method{
			{FullMethod: "/echo.v1.Echo/Unary", Permission: "alpha:read"},
			{FullMethod: "/echo.v1.Echo/ServerStream", Permission: "alpha:read", Streaming: true, MaxStreamDuration: time.Hour},
			{FullMethod: "/echo.v1.Echo/ClientStream", Public: true},
		},
		Permissions: []gatewayclient.Permission{{Resource: "alpha", Action: "read"}, {Resource: "alpha", Action: "write"}},
		Abilities:   []gatewayclient.Ability{{Action: []string{"read"}, Subject: []string{"AlphaItem"}, Requires: "alpha:read"}, {Action: []string{"create"}, Subject: []string{"AlphaItem"}, Requires: "alpha:write"}},
		Exposes:     []string{"./routes"},
		Nav:         []gatewayclient.NavEntry{{Title: "Alpha", Path: "/alpha", Order: 10, Requires: "alpha:read"}}}
}

// Platform boots the stack, bootstraps and signs the operator in, and
// starts alpha with an echo gRPC service.
type Platform struct {
	*Env
	TenantID string
	UserID   string
	Alpha    *Module
	Echo     *echov1.Server
}

func StartPlatform(t *testing.T) *Platform {
	t.Helper()
	e := Start(t)
	tid, accept := e.Bootstrap("ops@example.org")
	e.AcceptOperator(accept, "correct horse battery staple 42")
	if code, body := e.SignInAt("platform", "ops@example.org", "correct horse battery staple 42"); code != 200 {
		t.Fatalf("sign-in → %d %v", code, body)
	}
	code, me := e.JSON(http.MethodGet, "/gateway/v1/me", nil)
	if code != 200 || me["user_id"] == "" || me["source"] != "session" || me["operator"] != true {
		t.Fatalf("me → %d %v", code, me)
	}
	e.Allow("alpha", []string{"/api/alpha"}, []string{"alpha"})
	echo := &echov1.Server{}
	alpha := e.StartModule("alpha", echoHandler("alpha"), func(s grpc.ServiceRegistrar) { echov1.RegisterEchoServer(s, echo) })
	e.register(alpha, alphaFull())
	e.waitStatus("/api/alpha/ping", 200, 10*time.Second)
	// The gateway registered alpha's permissions with auth for the platform tenant.
	if err := e.Gateway.SyncPermissions(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &Platform{Env: e, TenantID: tid, UserID: me["user_id"].(string), Alpha: alpha, Echo: echo}
}

// GrantSelf creates a role holding perms and assigns it to the operator
// (owners may grant anything), keeping the existing roles.
func (p *Platform) GrantSelf(slug string, perms ...string) {
	p.T.Helper()
	code, role := p.JSON(http.MethodPost, "/api/v1/admin/roles", map[string]any{"slug": slug, "display_name": slug, "permissions": perms})
	if code != 201 {
		p.T.Fatalf("create role → %d %v", code, role)
	}
	code, roles := p.JSONList(http.MethodGet, "/api/v1/admin/roles")
	if code != 200 {
		p.T.Fatalf("list roles → %d", code)
	}
	var ids []string
	for _, r := range roles {
		s, _ := r["slug"].(string)
		if s == "owner" || s == "operator" || s == slug {
			ids = append(ids, r["id"].(string))
		}
	}
	if code, body := p.JSON(http.MethodPut, "/api/v1/admin/users/"+p.UserID+"/roles", map[string]any{"role_ids": ids}); code != 200 {
		p.T.Fatalf("assign → %d %v", code, body)
	}
}

// Token mints a platform access token from the live session.
func (p *Platform) Token() string {
	p.T.Helper()
	code, body := p.JSON(http.MethodPost, "/api/v1/session/token", nil)
	if code != 200 {
		p.T.Fatalf("token → %d %v", code, body)
	}
	return body["access_token"].(string)
}

// JSONList is JSON for endpoints returning an array.
func (e *Env) JSONList(method, path string) (int, []map[string]any) {
	e.T.Helper()
	req, _ := http.NewRequest(method, e.Base+path, nil)
	resp, err := e.Client.Do(req)
	if err != nil {
		e.T.Fatal(err)
	}
	defer resp.Body.Close()
	var out []map[string]any
	_ = decodeJSON(resp, &out)
	return resp.StatusCode, out
}

func TestPermissionMatrix(t *testing.T) {
	p := StartPlatform(t)
	// Signed-in operator without the permission: public ok, protected forbidden, anonymous unauthenticated.
	if code, body := p.JSON(http.MethodGet, "/api/alpha/secret", nil); code != 403 || body["reason"] != "forbidden" {
		t.Fatalf("no permission → %d %v", code, body)
	}
	anon := &http.Client{Transport: p.Client.Transport, Timeout: 10 * time.Second}
	resp, _ := anon.Get(p.Base + "/api/alpha/secret")
	if resp.StatusCode != 401 {
		t.Fatalf("anonymous → %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp, _ = anon.Get(p.Base + "/api/alpha/ping")
	if resp.StatusCode != 200 {
		t.Fatalf("anonymous public → %d", resp.StatusCode)
	}
	resp.Body.Close()
	// Grant alpha:read only: read allowed within the decision cache window, write still forbidden.
	p.GrantSelf("alpha-reader", "alpha:read")
	body := p.waitStatus("/api/alpha/secret", 200, 10*time.Second)
	hdr := body["headers"].(map[string]any)
	if !strings.HasPrefix(hdr["Authorization"].(string), "Bearer ey") || hdr["Cookie"] != "" {
		t.Fatalf("forwarded identity: %v", hdr)
	}
	if code, body := p.JSON(http.MethodPost, "/api/alpha/items", map[string]string{"n": "1"}); code != 403 || body["reason"] != "forbidden" {
		t.Fatalf("write without permission → %d %v", code, body)
	}
	p.GrantSelf("alpha-writer", "alpha:write")
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, _ := p.JSON(http.MethodPost, "/api/alpha/items", map[string]string{"n": "1"})
		if code == 200 || time.Now().After(deadline) {
			if code != 200 {
				t.Fatalf("write → %d", code)
			}
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	// Route body limit (64 bytes) → 413 payload_too_large.
	if code, body := p.JSON(http.MethodPost, "/api/alpha/items", map[string]string{"n": strings.Repeat("x", 200)}); code != 413 || body["reason"] != "payload_too_large" {
		t.Fatalf("oversized → %d %v", code, body)
	}
	if n := p.auditCount("permission_refused", ""); n < 2 {
		t.Fatalf("permission_refused audits %d", n)
	}
}

func TestHeaderInjectionAndErrorHygiene(t *testing.T) {
	p := StartPlatform(t)
	anon := &http.Client{Transport: p.Client.Transport, Timeout: 10 * time.Second}
	req, _ := http.NewRequest(http.MethodGet, p.Base+"/api/alpha/secret", nil)
	for k, v := range map[string]string{"X-Forwarded-For": "10.0.0.1", "X-Freya-Peer": "spiffe://example.org/svc/gateway", "X-Gateway-Module": "auth",
		"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1MSJ9.", "Cookie": "__Host-session=forged"} {
		req.Header.Set(k, v)
	}
	resp, err := anon.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("forged credentials → %d", resp.StatusCode)
	}
	// Public route: injected identity headers never reach the module.
	req, _ = http.NewRequest(http.MethodGet, p.Base+"/api/alpha/ping", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Set("Authorization", "Bearer stolen")
	req.Header.Set("X-Gateway-Client", "spoof")
	code, body := p.JSON(http.MethodGet, "/api/alpha/ping", nil, "X-Forwarded-For", "10.0.0.1", "Authorization", "Bearer stolen")
	hdr := body["headers"].(map[string]any)
	if code != 200 || hdr["Authorization"] != "" || hdr["X-Forwarded-For"] != "" {
		t.Fatalf("%d %v", code, hdr)
	}
	// Error hygiene: only {"reason": ...}, no server banners, no module names.
	for path, want := range map[string]string{"/api/nowhere/deep": "not_found", "/api/alpha/undeclared": "not_found", "/gateway/v1/nope": "not_found"} {
		resp, _ := anon.Get(p.Base + path)
		raw := readAll(resp)
		if resp.StatusCode != 404 || strings.TrimSpace(raw) != `{"reason":"`+want+`"}` || resp.Header.Get("Server") != "" || resp.Header.Get("X-Powered-By") != "" {
			t.Fatalf("%s → %d %q %v", path, resp.StatusCode, raw, resp.Header)
		}
	}
	resp, _ = anon.Get(p.Base + "/api/alpha/secret")
	if raw := readAll(resp); strings.TrimSpace(raw) != `{"reason":"unauthenticated"}` || strings.Contains(raw, "alpha") {
		t.Fatalf("%q", raw)
	}
}

func TestTokenMatrix(t *testing.T) {
	p := StartPlatform(t)
	p.GrantSelf("alpha-reader", "alpha:read")
	tok := p.Token()
	machine := &http.Client{Transport: p.Client.Transport, Timeout: 10 * time.Second}
	get := func(bearer string) int {
		req, _ := http.NewRequest(http.MethodGet, p.Base+"/api/alpha/secret", nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := machine.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	deadline := time.Now().Add(10 * time.Second)
	for get(tok) != 200 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
	if code := get(tok); code != 200 {
		t.Fatalf("valid bearer → %d", code)
	}
	// Machine clients need no CSRF: a POST with a bearer token and no cookies passes the edge.
	req, _ := http.NewRequest(http.MethodPost, p.Base+"/api/alpha/items", strings.NewReader(`{"n":"1"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := machine.Do(req)
	if resp.StatusCode != 403 { // alpha:write not granted, but CSRF did not stop it
		t.Fatalf("bearer POST → %d", resp.StatusCode)
	}
	resp.Body.Close()
	for name, bad := range map[string]string{"garbage": "not-a-token", "tampered": tok[:len(tok)-3] + "abc", "empty": ""} {
		if code := get(bad); code != 401 {
			t.Errorf("%s → %d", name, code)
		}
	}
	// Me works with the bearer too, and reports the bearer source.
	req, _ = http.NewRequest(http.MethodGet, p.Base+"/gateway/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, _ = machine.Do(req)
	var me map[string]any
	_ = decodeJSON(resp, &me)
	if resp.StatusCode != 200 || me["source"] != "bearer" || me["user_id"] != p.UserID {
		t.Fatalf("me with bearer → %d %v", resp.StatusCode, me)
	}
	// Sign-out revokes the session; the token is refused within the propagation bound (SC-004).
	cookie := p.SessionCookie()
	if code, _ := p.JSON(http.MethodPost, "/api/v1/signout", nil); code != 204 {
		t.Fatalf("signout → %d", code)
	}
	deadline = time.Now().Add(8 * time.Second)
	for get(tok) != 401 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
	if code := get(tok); code != 401 {
		t.Fatalf("revoked bearer still accepted: %d", code)
	}
	// The old cookie value is refused as well (cached identity invalidated by the relay).
	req, _ = http.NewRequest(http.MethodGet, p.Base+"/gateway/v1/me", nil)
	req.Header.Set("Cookie", "__Host-session="+cookie)
	resp, _ = machine.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("stale cookie → %d", resp.StatusCode)
	}
}
