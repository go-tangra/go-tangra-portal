package gatewayclient

import (
	"context"
	"runtime/debug"
	"testing"
	"time"
)

func withBuildInfo(t *testing.T, mainVersion string, ok bool) {
	t.Helper()
	prev := readBuildInfo
	readBuildInfo = func() (*debug.BuildInfo, bool) {
		if !ok {
			return nil, false
		}
		return &debug.BuildInfo{Main: debug.Module{Path: "example.org/orders", Version: mainVersion}}, true
	}
	t.Cleanup(func() { readBuildInfo = prev; SetBuildVersion("") })
}

func TestBuildVersionResolution(t *testing.T) {
	cases := []struct {
		name, set, main string
		ok              bool
		want            string
	}{
		{"explicit wins over build info", " 4.10.2 ", "v9.9.9", true, "4.10.2"},
		{"toolchain release version", "", "v4.10.2", true, "v4.10.2"},
		{"devel build is unknown", "", "(devel)", true, ""},
		{"no build info", "", "", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withBuildInfo(t, tc.main, tc.ok)
			SetBuildVersion(tc.set)
			if got := BuildVersion(); got != tc.want {
				t.Fatalf("BuildVersion() = %q, want %q", got, tc.want)
			}
		})
	}
}

func registeredBuildVersion(t *testing.T, o Options) string {
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
	return f.last.GetBuildVersion()
}

func TestRegisterSendsBuildVersion(t *testing.T) {
	withBuildInfo(t, "(devel)", true)
	SetBuildVersion("4.6.2")
	if got := registeredBuildVersion(t, Options{}); got != "4.6.2" {
		t.Fatalf("process build version: got %q", got)
	}
	if got := registeredBuildVersion(t, Options{BuildVersion: "4.7.0"}); got != "4.7.0" {
		t.Fatalf("option overrides process version: got %q", got)
	}
	SetBuildVersion("")
	if got := registeredBuildVersion(t, Options{}); got != "" {
		t.Fatalf("unknown build version must be empty: got %q", got)
	}
}
