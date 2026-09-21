//go:build integration

package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestOperatorControls(t *testing.T) {
	p := StartPlatform(t)
	// Registrations with health and traffic.
	code, regs := p.JSONList(http.MethodGet, "/gateway/v1/ops/registrations")
	if code != 200 || len(regs) < 2 {
		t.Fatalf("%d %v", code, regs)
	}
	var alpha map[string]any
	for _, r := range regs {
		if r["module"] == "alpha" {
			alpha = r
		}
	}
	if alpha == nil || alpha["state"] != "active" || alpha["identity"] != "spiffe://example.org/svc/alpha" || alpha["traffic"].(map[string]any)["requests_1m"].(float64) < 1 {
		t.Fatalf("%v", alpha)
	}
	// Drain: new requests refused, renewals refused → the module withdraws; undrain restores it.
	if code, _ := p.JSON(http.MethodPost, "/gateway/v1/ops/registrations/alpha/drain", nil); code != 204 {
		t.Fatalf("drain → %d", code)
	}
	if code, body := p.JSON(http.MethodGet, "/api/alpha/ping", nil); code != 503 || body["reason"] != "temporarily_unavailable" {
		t.Fatalf("draining → %d %v", code, body)
	}
	if code, _ := p.JSON(http.MethodPost, "/gateway/v1/ops/registrations/alpha/undrain", nil); code != 204 {
		t.Fatalf("undrain → %d", code)
	}
	p.waitStatus("/api/alpha/ping", 200, 15*time.Second)
	// Revoke: reason validated, routes gone, renewals refused durably.
	if code, body := p.JSON(http.MethodPost, "/gateway/v1/ops/registrations/alpha/revoke", map[string]string{"reason": "short"}); code != 400 || body["reason"] != "validation_failed" {
		t.Fatalf("short reason → %d %v", code, body)
	}
	if code, _ := p.JSON(http.MethodPost, "/gateway/v1/ops/registrations/alpha/revoke", map[string]string{"reason": "decommissioned by the platform team"}); code != 204 {
		t.Fatalf("revoke → %d", code)
	}
	p.waitStatus("/api/alpha/ping", 404, 5*time.Second)
	if p.Alpha.App == nil {
		t.Fatal("module handle")
	}
	// Allow-list: add, list, revoke.
	code, entry := p.JSON(http.MethodPost, "/gateway/v1/ops/allowlist", map[string]any{"spiffe_id": "spiffe://example.org/svc/gamma", "prefixes": []string{"/api/gamma/"}, "names": []string{"gamma"}})
	if code != 201 || entry["id"] == "" {
		t.Fatalf("add allow → %d %v", code, entry)
	}
	code, list := p.JSONList(http.MethodGet, "/gateway/v1/ops/allowlist")
	if code != 200 || len(list) < 3 {
		t.Fatalf("list allow → %d %v", code, list)
	}
	if code, _ := p.JSON(http.MethodPost, "/gateway/v1/ops/allowlist/"+entry["id"].(string)+"/revoke", nil); code != 204 {
		t.Fatalf("revoke allow → %d", code)
	}
	// Non-operators are refused; anonymous unauthenticated.
	anon := &http.Client{Transport: p.Client.Transport, Timeout: 5 * time.Second}
	resp, _ := anon.Get(p.Base + "/gateway/v1/ops/registrations")
	readAll(resp)
	if resp.StatusCode != 401 {
		t.Fatalf("anonymous → %d", resp.StatusCode)
	}
	tok := p.Token()
	req, _ := http.NewRequest(http.MethodPost, p.Base+"/gateway/v1/ops/registrations/alpha/drain", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, _ = anon.Do(req)
	body := readAll(resp)
	if resp.StatusCode != 403 { // bearer tokens carry no operator flag: operations need the browser session
		time.Sleep(1500 * time.Millisecond)
		_, refusals := p.JSON(http.MethodGet, "/gateway/v1/ops/audit?event_type=identity_refused", nil)
		t.Fatalf("bearer operator → %d %s\nidentity refusals: %s", resp.StatusCode, body, toJSON(refusals))
	}
	// Audit rows carry the operator identity.
	deadline := time.Now().Add(5 * time.Second)
	var audit map[string]any
	for time.Now().Before(deadline) {
		_, audit = p.JSON(http.MethodGet, "/gateway/v1/ops/audit?module=alpha", nil)
		if strings.Contains(toJSON(audit), "module_revoked") {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	js := toJSON(audit)
	for _, want := range []string{"module_drained", "module_revoked", `"actor_id":"` + p.UserID + `"`, `"actor_kind":"operator"`} {
		if !strings.Contains(js, want) {
			t.Fatalf("audit missing %s: %s", want, js)
		}
	}
	if code, a := p.JSON(http.MethodGet, "/gateway/v1/ops/audit?event_type=allowlist_changed", nil); code != 200 || strings.Count(toJSON(a), "allowlist_changed") < 2 {
		t.Fatalf("allow audit → %d %v", code, a)
	}
}
