package gatewayclient

import (
	"context"
	"strings"
	"testing"
	"time"
)

const (
	digestA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	digestB = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752"
)

func TestValidateDocsDigest(t *testing.T) {
	cases := []struct {
		name, in string
		ok       bool
	}{
		{"empty means no docs", "", true},
		{"sha256 hex", digestA, true},
		{"uppercase", strings.ToUpper(digestA), false},
		{"too short", digestA[:63], false},
		{"too long", digestA + "0", false},
		{"non hex", "g" + digestA[1:], false},
		{"surrounding space", " " + digestA[1:], false},
		{"prefixed", "sha256:" + digestA[7:], false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDocsDigest(tc.in)
			if (err == nil) != tc.ok {
				t.Fatalf("ValidateDocsDigest(%q) = %v, want ok=%v", tc.in, err, tc.ok)
			}
		})
	}
}

func registeredDocsDigest(t *testing.T, o Options) string {
	t.Helper()
	f := &fakeRegistry{}
	o.Manifest, o.HTTPURL = manifest(), "https://127.0.0.1:1"
	c, err := New(dial(t, f), o)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if regs, _, _ := f.counts(); regs >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.last == nil {
		t.Fatal("no registration")
	}
	return f.last.GetDocsDigest()
}

func TestRegisterSendsDocsDigest(t *testing.T) {
	t.Cleanup(func() { SetDocsDigest("") })
	if got := registeredDocsDigest(t, Options{}); got != "" {
		t.Fatalf("no docs must send an empty digest: got %q", got)
	}
	SetDocsDigest(digestA)
	if DocsDigest() != digestA {
		t.Fatalf("DocsDigest() = %q", DocsDigest())
	}
	if got := registeredDocsDigest(t, Options{}); got != digestA {
		t.Fatalf("process digest: got %q", got)
	}
	if got := registeredDocsDigest(t, Options{DocsDigest: digestB}); got != digestB {
		t.Fatalf("option overrides process digest: got %q", got)
	}
}

func TestNewRefusesMalformedDocsDigest(t *testing.T) {
	t.Cleanup(func() { SetDocsDigest("") })
	conn := dial(t, &fakeRegistry{})
	base := Options{Manifest: manifest(), HTTPURL: "https://127.0.0.1:1"}

	o := base
	o.DocsDigest = "not-a-digest"
	if _, err := New(conn, o); err == nil || !strings.Contains(err.Error(), "docs digest") {
		t.Fatalf("malformed option digest must fail New: %v", err)
	}
	SetDocsDigest(strings.ToUpper(digestA))
	if _, err := New(conn, base); err == nil || !strings.Contains(err.Error(), "docs digest") {
		t.Fatalf("malformed process digest must fail New: %v", err)
	}
}
