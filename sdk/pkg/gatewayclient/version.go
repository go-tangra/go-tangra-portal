package gatewayclient

import (
	"runtime/debug"
	"strings"
	"sync"
)

// buildVersion is the release the process runs. Modules set it once at
// start-up with SetBuildVersion (typically from their own -ldflags
// "-X main.version=..." value) or stamp it directly with
//
//	-ldflags "-X github.com/go-tangra/go-tangra-portal/sdk/v4/pkg/gatewayclient.buildVersion=4.10.2"
var buildVersion string

var buildMu sync.RWMutex

// readBuildInfo is replaced in tests.
var readBuildInfo = debug.ReadBuildInfo

// SetBuildVersion records the release this process runs; it is sent with
// every registration whose Options.BuildVersion is empty. Call it before New.
func SetBuildVersion(v string) {
	buildMu.Lock()
	buildVersion = strings.TrimSpace(v)
	buildMu.Unlock()
}

// BuildVersion is the process build version: the value from SetBuildVersion
// (or the linker), else the main module version recorded by the Go toolchain
// when it is a real release, else "".
func BuildVersion() string {
	buildMu.RLock()
	v := buildVersion
	buildMu.RUnlock()
	if v != "" {
		return v
	}
	if bi, ok := readBuildInfo(); ok && bi != nil {
		if mv := bi.Main.Version; mv != "" && mv != "(devel)" {
			return mv
		}
	}
	return ""
}
