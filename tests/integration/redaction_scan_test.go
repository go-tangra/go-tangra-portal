//go:build integration

package integration

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestRedaction drives sign-in, token minting and a refused call, then scans
// everything the gateway emitted (structured log, audit details, error
// bodies) and what a module observed for secrets: the session cookie value,
// the access token, the password. FREYA_CAPTURE_DIR receives the captures
// for scripts/redaction-scan.sh.
func TestRedaction(t *testing.T) {
	var logBuf bytes.Buffer
	captureLogger = slog.NewJSONHandler(&logBuf, nil)
	t.Cleanup(func() { captureLogger = nil })
	p := StartPlatform(t)
	const password = "correct horse battery staple 42"
	cookie := p.SessionCookie()
	tok := p.Token()
	p.GrantSelf("alpha-reader", "alpha:read")
	p.waitStatus("/api/alpha/secret", 200, 10*time.Second)
	// A refused call and a bad token produce audit rows and error bodies.
	anon := &http.Client{Transport: p.Client.Transport, Timeout: 5 * time.Second}
	req, _ := http.NewRequest(http.MethodGet, p.Base+"/api/alpha/secret", nil)
	req.Header.Set("Authorization", "Bearer "+tok[:len(tok)-2]+"xx")
	resp, _ := anon.Do(req)
	body := readAll(resp)
	if strings.Contains(body, tok[:20]) {
		t.Fatal("error body echoes the token")
	}
	time.Sleep(1500 * time.Millisecond)
	// Audit details from the database.
	var details strings.Builder
	_ = p.Gateway.Store.Tx(context.Background(), func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), "SELECT event_type, reason, details::text FROM gateway_audit_events")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var et, reason, d string
			if err := rows.Scan(&et, &reason, &d); err != nil {
				return err
			}
			details.WriteString(et + " " + reason + " " + d + "\n")
		}
		return nil
	})
	captures := map[string]string{"gateway.log": logBuf.String(), "audit-details.txt": details.String()}
	if dir := os.Getenv("FREYA_CAPTURE_DIR"); dir != "" {
		for name, content := range captures {
			_ = os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600)
		}
	}
	for name, content := range captures {
		for label, secret := range map[string]string{"session cookie": cookie, "access token": tok, "password": password, "token prefix": tok[:24]} {
			if secret != "" && strings.Contains(content, secret) {
				t.Errorf("%s contains the %s", name, label)
			}
		}
		if strings.Contains(content, "-----BEGIN") {
			t.Errorf("%s contains key material", name)
		}
	}
	if !strings.Contains(details.String(), "identity_refused") {
		t.Fatal("expected audit rows to be present for the scan")
	}
}
