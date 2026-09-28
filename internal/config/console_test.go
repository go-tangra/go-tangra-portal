package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func withConsole() Config {
	c := valid()
	c.Console.Enabled = true
	c.Console.PublicOrigin = "https://platform.example.org:8444"
	return c
}

func TestConsoleDefaults(t *testing.T) {
	c := Default()
	if c.Console.Enabled || c.Console.Addr != ":8444" || c.Console.SessionMax != time.Hour || c.Console.MaxConcurrent != 64 {
		t.Fatalf("console defaults %+v", c.Console)
	}
	if !reflect.DeepEqual(c.Console.CookieNames(), []string{"freya_kvm"}) {
		t.Fatalf("cookies %v", c.Console.CookieNames())
	}
	if !reflect.DeepEqual(c.Console.RouteMap(), map[string]string{"/bmc/": "ipam"}) {
		t.Fatalf("routes %v", c.Console.RouteMap())
	}
	// Disabled console: nothing is validated and no frame source is added.
	d := valid()
	d.Console.PublicOrigin = "garbage"
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(d.FrameSources()) != 0 {
		t.Fatalf("frame sources %v", d.FrameSources())
	}
}

func TestConsoleValid(t *testing.T) {
	c := withConsole()
	c.Console.PublicOrigin = "https://Platform.Example.org:8444/"
	c.Console.Routes = map[string]string{"/bmc/": "ipam", "/console/v-1_x/": "other-mod"}
	c.Console.Cookies = []string{"freya_kvm", "vendor.sid"}
	c.Edge.FrameSources = []string{"https://docs.example.org"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := c.Console.Origin(); got != "https://platform.example.org:8444" {
		t.Fatalf("origin %q", got)
	}
	if got := c.FrameSources(); !reflect.DeepEqual(got, []string{"https://docs.example.org", "https://platform.example.org:8444"}) {
		t.Fatalf("frame sources %v", got)
	}
	if got := c.Console.RouteMap(); len(got) != 2 {
		t.Fatalf("routes %v", got)
	}
	if got := c.Console.CookieNames(); !reflect.DeepEqual(got, []string{"freya_kvm", "vendor.sid"}) {
		t.Fatalf("cookies %v", got)
	}
	// A distinct host name is a valid console origin too.
	c.Console.PublicOrigin = "https://kvm.example.org"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestConsoleRefused(t *testing.T) {
	mut := func(f func(c *Config)) Config { c := withConsole(); f(&c); return c }
	for name, c := range map[string]Config{
		"no origin":             mut(func(c *Config) { c.Console.PublicOrigin = "" }),
		"http origin":           mut(func(c *Config) { c.Console.PublicOrigin = "http://platform.example.org:8444" }),
		"origin with path":      mut(func(c *Config) { c.Console.PublicOrigin = "https://platform.example.org:8444/bmc" }),
		"origin with query":     mut(func(c *Config) { c.Console.PublicOrigin = "https://platform.example.org:8444?x" }),
		"origin with user":      mut(func(c *Config) { c.Console.PublicOrigin = "https://u@platform.example.org:8444" }),
		"origin injection":      mut(func(c *Config) { c.Console.PublicOrigin = "https://platform.example.org:8444; script-src *" }),
		"origin unparsable":     mut(func(c *Config) { c.Console.PublicOrigin = "%zz" }),
		"origin no host":        mut(func(c *Config) { c.Console.PublicOrigin = "https://" }),
		"origin = portal":       mut(func(c *Config) { c.Console.PublicOrigin = "https://platform.example.org" }),
		"origin = portal :443":  mut(func(c *Config) { c.Console.PublicOrigin = "https://platform.example.org:443" }),
		"origin csrf-allowed":   mut(func(c *Config) { c.Edge.AllowedOrigins = []string{"https://platform.example.org:8444/"} }),
		"no edge cert":          mut(func(c *Config) { c.Edge.CertFile = "" }),
		"no edge key":           mut(func(c *Config) { c.Edge.KeyFile = "" }),
		"no addr":               mut(func(c *Config) { c.Console.Addr = "" }),
		"root prefix":           mut(func(c *Config) { c.Console.Routes = map[string]string{"/": "ipam"} }),
		"no trailing slash":     mut(func(c *Config) { c.Console.Routes = map[string]string{"/bmc": "ipam"} }),
		"no leading slash":      mut(func(c *Config) { c.Console.Routes = map[string]string{"bmc/": "ipam"} }),
		"api prefix":            mut(func(c *Config) { c.Console.Routes = map[string]string{"/api/ipam/": "ipam"} }),
		"gateway prefix":        mut(func(c *Config) { c.Console.Routes = map[string]string{"/gateway/x/": "ipam"} }),
		"remote prefix":         mut(func(c *Config) { c.Console.Routes = map[string]string{"/m/ipam/": "ipam"} }),
		"bad prefix chars":      mut(func(c *Config) { c.Console.Routes = map[string]string{"/b%6dc/": "ipam"} }),
		"dot segment":           mut(func(c *Config) { c.Console.Routes = map[string]string{"/bmc/../": "ipam"} }),
		"double slash":          mut(func(c *Config) { c.Console.Routes = map[string]string{"/bmc//": "ipam"} }),
		"empty module":          mut(func(c *Config) { c.Console.Routes = map[string]string{"/bmc/": ""} }),
		"bad module":            mut(func(c *Config) { c.Console.Routes = map[string]string{"/bmc/": "IPAM!"} }),
		"host cookie":           mut(func(c *Config) { c.Console.Cookies = []string{"__Host-session"} }),
		"secure cookie":         mut(func(c *Config) { c.Console.Cookies = []string{"__secure-x"} }),
		"bad cookie":            mut(func(c *Config) { c.Console.Cookies = []string{"a b"} }),
		"empty cookie":          mut(func(c *Config) { c.Console.Cookies = []string{""} }),
		"session zero":          mut(func(c *Config) { c.Console.SessionMax = 0 }),
		"session long":          mut(func(c *Config) { c.Console.SessionMax = 25 * time.Hour }),
		"concurrency zero":      mut(func(c *Config) { c.Console.MaxConcurrent = 0 }),
		"concurrency huge":      mut(func(c *Config) { c.Console.MaxConcurrent = 10001 }),
		"bad frame source":      mut(func(c *Config) { c.Edge.FrameSources = []string{"http://x"} }),
		"frame source disabled": func() Config { c := valid(); c.Edge.FrameSources = []string{"https://x/p"}; return c }(),
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		} else if !strings.Contains(err.Error(), "config:") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestLoadConsole(t *testing.T) {
	p := filepath.Join(t.TempDir(), "gw.yaml")
	_ = os.WriteFile(p, []byte("service_name: gw\nedge: { frame_sources: [\"https://a.example\"] }\nconsole:\n  enabled: true\n  addr: 0.0.0.0:9444\n  public_origin: https://x:9444\n  routes: { \"/kvm/\": other }\n  cookies: [c1]\n  session_max: 2h\n  max_concurrent: 8\n"), 0o600)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Console.Enabled || c.Console.Addr != "0.0.0.0:9444" || c.Console.PublicOrigin != "https://x:9444" || c.Console.SessionMax != 2*time.Hour || c.Console.MaxConcurrent != 8 {
		t.Fatalf("%+v", c.Console)
	}
	// Configured routes replace the default instead of merging with it.
	if !reflect.DeepEqual(c.Console.RouteMap(), map[string]string{"/kvm/": "other"}) || !reflect.DeepEqual(c.Console.CookieNames(), []string{"c1"}) {
		t.Fatalf("routes %v cookies %v", c.Console.RouteMap(), c.Console.CookieNames())
	}
	if !reflect.DeepEqual(c.Edge.FrameSources, []string{"https://a.example"}) {
		t.Fatalf("frame sources %v", c.Edge.FrameSources)
	}
}
