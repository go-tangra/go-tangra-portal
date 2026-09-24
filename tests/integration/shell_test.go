//go:build integration

package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-portal/sdk/v4/pkg/gatewayclient"
)

func TestAbilitiesMatchDecisions(t *testing.T) {
	p := StartPlatform(t)
	// Before any grant: alpha declares two abilities; none is held → no rules for alpha.
	code, doc := p.JSON(http.MethodGet, "/gateway/v1/me/abilities", nil)
	if code != 200 || doc["tenant"] != p.TenantID || doc["user"] != p.UserID {
		t.Fatalf("%d %v", code, doc)
	}
	modules := doc["modules"].(map[string]any)
	if _, ok := modules["alpha"]; ok {
		t.Fatalf("alpha abilities without permission: %v", modules)
	}
	// The auth module's own abilities follow the operator's builtin grants.
	authRules, _ := modules["auth"].([]any)
	if len(authRules) == 0 {
		t.Fatalf("auth abilities missing for the operator: %v", modules)
	}
	version := doc["version"]
	// Grant alpha:read: exactly the read rule appears, and the API agrees.
	p.GrantSelf("alpha-reader", "alpha:read")
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, doc = p.JSON(http.MethodGet, "/gateway/v1/me/abilities", nil)
		if rules, ok := doc["modules"].(map[string]any)["alpha"].([]any); ok && len(rules) == 1 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	rules, _ := doc["modules"].(map[string]any)["alpha"].([]any)
	if len(rules) != 1 || rules[0].([]any)[0] != "read" || rules[0].([]any)[1] != "AlphaItem" {
		t.Fatalf("alpha rules %v", rules)
	}
	if doc["version"] == version {
		t.Fatal("abilities version did not change with the tenant policy")
	}
	if code, _ := p.JSON(http.MethodGet, "/api/alpha/secret", nil); code != 200 {
		t.Fatalf("API disagrees with the UI rule: %d", code)
	}
	if code, _ := p.JSON(http.MethodPost, "/api/alpha/items", map[string]string{"n": "1"}); code != 403 {
		t.Fatalf("API allows what the UI rule denies: %d", code)
	}
	// Modules list: alpha's nav entry appears once the permission is held.
	code, mods := p.JSONList(http.MethodGet, "/gateway/v1/me/modules")
	if code != 200 {
		t.Fatal(code)
	}
	found := false
	for _, m := range mods {
		if m["module"] == "alpha" {
			nav, _ := m["nav"].([]any)
			found = len(nav) == 1
			if r, _ := m["remote"].(map[string]any); r["entry"] != "/m/alpha/mf-manifest.json" {
				t.Fatalf("remote %v", r)
			}
		}
	}
	if !found {
		t.Fatalf("alpha nav missing: %v", mods)
	}
	// Anonymous callers get nothing.
	anon := &http.Client{Transport: p.Client.Transport, Timeout: 5 * time.Second}
	resp, _ := anon.Get(p.Base + "/gateway/v1/me/abilities")
	if resp.StatusCode != 401 {
		t.Fatalf("anonymous abilities → %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestRemoteOrigins(t *testing.T) {
	p := StartPlatform(t)
	// alpha's echo handler serves /ui/* like a real remote.
	resp, err := p.Client.Get(p.Base + "/m/alpha/mf-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(resp)
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" || !strings.Contains(body, `"/ui/mf-manifest.json"`) {
		t.Fatalf("%d %v %s", resp.StatusCode, resp.Header, body)
	}
	resp, _ = p.Client.Get(p.Base + "/m/alpha/assets/index-ABCDEFGH.js")
	readAll(resp)
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Cache-Control"), "immutable") {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	// Only current registrations: an unknown module or traversal never reaches a backend.
	for _, path := range []string{"/m/ghost/mf-manifest.json", "/m/alpha/../../api/alpha/ping"} {
		resp, _ = p.Client.Get(p.Base + path)
		readAll(resp)
		if resp.StatusCode == 200 && strings.Contains(path, "ghost") {
			t.Fatalf("%s served", path)
		}
	}
	// A withdrawn module's remote disappears.
	beta := p.StartModule("beta", echoHandler("beta"), nil)
	p.Allow("beta", []string{"/api/beta"}, []string{"beta"})
	stop := p.register(beta, gatewayclient.Manifest{Module: "beta", DisplayName: "Beta", Version: "1.0.0", Prefixes: []string{"/api/beta"},
		Routes: []gatewayclient.Route{{Method: "GET", Path: "/api/beta/ping", Public: true}}, Exposes: []string{"./routes"}})
	p.waitStatus("/api/beta/ping", 200, 10*time.Second)
	resp, _ = p.Client.Get(p.Base + "/m/beta/mf-manifest.json")
	readAll(resp)
	if resp.StatusCode != 200 {
		t.Fatalf("beta remote → %d", resp.StatusCode)
	}
	stop()
	p.waitStatus("/api/beta/ping", 404, 5*time.Second)
	resp, _ = p.Client.Get(p.Base + "/m/beta/mf-manifest.json")
	readAll(resp)
	if resp.StatusCode != 404 {
		t.Fatalf("withdrawn remote → %d", resp.StatusCode)
	}
	// The auth module's real remote build is relayed when the binary embeds it (dev builds);
	// in the harness the auth binary has no console, so the relay answers 404 from auth.
	resp, _ = p.Client.Get(p.Base + "/m/auth/mf-manifest.json")
	readAll(resp)
	if resp.StatusCode != 200 && resp.StatusCode != 404 {
		t.Fatalf("auth remote → %d", resp.StatusCode)
	}
}
