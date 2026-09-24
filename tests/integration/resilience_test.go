//go:build integration

package integration

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-portal/sdk/v4/pkg/gatewayclient"
)

// TestDegradation: a hanging module is bounded by its route timeout, the
// breaker opens after repeated failures (fast 503 without touching the
// module), other modules are unaffected and recovery is automatic.
func TestDegradation(t *testing.T) {
	e := Start(t)
	e.Allow("alpha", []string{"/api/alpha"}, []string{"alpha"})
	e.Allow("beta", []string{"/api/beta"}, []string{"beta"})
	var hang atomic.Bool
	var betaHits atomic.Int32
	beta := e.StartModule("beta", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		betaHits.Add(1)
		if hang.Load() {
			select {
			case <-time.After(30 * time.Second):
			case <-r.Context().Done():
			}
			return
		}
		w.WriteHeader(204)
	}), nil)
	e.register(beta, gatewayclient.Manifest{Module: "beta", DisplayName: "Beta", Version: "1.0.0", Prefixes: []string{"/api/beta"},
		Routes: []gatewayclient.Route{{Method: "GET", Path: "/api/beta/slow", Public: true, Timeout: 500 * time.Millisecond}}, Exposes: []string{"./routes"}})
	alpha := e.StartModule("alpha", echoHandler("alpha"), nil)
	e.register(alpha, alphaManifest())
	e.waitStatus("/api/beta/slow", 204, 10*time.Second)
	e.waitStatus("/api/alpha/ping", 200, 10*time.Second)
	hang.Store(true)
	// Bounded: each call ends within the route timeout, answered as temporarily unavailable.
	for i := 0; i < 3; i++ {
		start := time.Now()
		code, body := e.JSON(http.MethodGet, "/api/beta/slow", nil)
		if (code != 504 && code != 503) || body["reason"] != "temporarily_unavailable" || time.Since(start) > 3*time.Second {
			t.Fatalf("hanging module → %d %v after %s", code, body, time.Since(start))
		}
	}
	// Breaker open: fast refusal without a backend hit; alpha unaffected.
	hits := betaHits.Load()
	start := time.Now()
	code, _ := e.JSON(http.MethodGet, "/api/beta/slow", nil)
	if code != 503 || time.Since(start) > 200*time.Millisecond || betaHits.Load() != hits {
		t.Fatalf("breaker: %d after %s hits=%d→%d", code, time.Since(start), hits, betaHits.Load())
	}
	if code, _ := e.JSON(http.MethodGet, "/api/alpha/ping", nil); code != 200 {
		t.Fatalf("alpha affected: %d", code)
	}
	// Recovery: once the module answers again, probes (5 s interval, 10 s cool-down) close the breaker.
	hang.Store(false)
	e.waitStatus("/api/beta/slow", 204, 30*time.Second)
	if e.auditCount("module_unhealthy", "") < 1 || e.auditCount("module_recovered", "") < 1 {
		t.Fatal("health audits missing")
	}
}

// TestHardening: transport and input limits hold on every route class.
func TestHardening(t *testing.T) {
	e := Start(t)
	e.Allow("alpha", []string{"/api/alpha"}, []string{"alpha"})
	alpha := e.StartModule("alpha", echoHandler("alpha"), nil)
	e.register(alpha, gatewayclient.Manifest{Module: "alpha", DisplayName: "Alpha", Version: "1.0.0", Prefixes: []string{"/api/alpha"},
		Routes: []gatewayclient.Route{{Method: "GET", Path: "/api/alpha/ping", Public: true}, {Method: "POST", Path: "/api/alpha/echo", Public: true, MaxBodyBytes: 1024}}, Exposes: []string{"./routes"}})
	e.waitStatus("/api/alpha/ping", 200, 10*time.Second)
	host := strings.TrimPrefix(e.Base, "https://")
	// TLS 1.2 and plaintext are refused.
	old := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}}} //nolint:gosec // probe
	if _, err := old.Get(e.Base + "/api/alpha/ping"); err == nil {
		t.Fatal("TLS 1.2 accepted")
	}
	if resp, err := (&http.Client{Timeout: 3 * time.Second}).Get("http://" + host + "/api/alpha/ping"); err == nil && resp.StatusCode == 200 {
		t.Fatal("plaintext served")
	}
	// Oversized body on a module route → 413 payload_too_large; oversized headers → 431.
	req, _ := http.NewRequest(http.MethodPost, e.Base+"/api/alpha/echo", strings.NewReader(strings.Repeat("x", 4096)))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-CSRF-Token", e.CSRF(e.Base))
	req.Header.Set("Origin", e.Base)
	resp, err := e.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if resp.StatusCode != 413 || body["reason"] != "payload_too_large" {
		t.Fatalf("oversized → %d %v", resp.StatusCode, body)
	}
	req, _ = http.NewRequest(http.MethodGet, e.Base+"/api/alpha/ping", nil)
	req.Header.Set("X-Big", strings.Repeat("a", 20000))
	if resp, err := e.Client.Do(req); err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
			t.Fatalf("big headers → %d", resp.StatusCode)
		}
	}
	// Spoofed X-Forwarded-For never reaches the module and is not trusted for the client pseudonym.
	_, echo := e.JSON(http.MethodGet, "/api/alpha/ping", nil, "X-Forwarded-For", "203.0.113.9")
	if echo["headers"].(map[string]any)["X-Forwarded-For"] != "" {
		t.Fatalf("XFF forwarded: %v", echo["headers"])
	}
	// Security headers on every route class: shell/API/module/remote.
	for _, path := range []string{"/", "/gateway/v1/me", "/api/alpha/ping", "/m/alpha/mf-manifest.json"} {
		resp, err := e.Client.Get(e.Base + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		h := resp.Header
		if !strings.Contains(h.Get("Content-Security-Policy"), "nonce-") || h.Get("X-Frame-Options") != "DENY" || h.Get("Strict-Transport-Security") == "" || h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Server") != "" {
			t.Fatalf("%s: %v", path, h)
		}
	}
}
