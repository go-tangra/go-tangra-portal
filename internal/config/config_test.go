package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func valid() Config {
	c := Default()
	c.Config.TrustDomain = "example.org"
	c.Authz.Source, c.Authz.Path = "file", "p.yaml"
	c.PublicOrigin = "https://platform.example.org"
	c.DB.DSN = "postgres://gateway_app:x@db/gateway?sslmode=verify-full"
	c.Valkey.Addresses = []string{"valkey:6379"}
	c.Auth.Issuer = "https://platform.example.org"
	c.Edge.CertFile, c.Edge.KeyFile = "/etc/tls/tls.crt", "/etc/tls/tls.key"
	return c
}

func TestDefaultsValidateWarnings(t *testing.T) {
	c := valid()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Leases.TTL != 30*time.Second || c.Forward.BodyBytes != 1<<20 || c.Operators.Roles[0] != "operator" {
		t.Fatalf("defaults %+v", c)
	}
	mut := func(f func(c *Config)) Config { c := valid(); f(&c); return c }
	for name, c := range map[string]Config{
		"http origin":   mut(func(c *Config) { c.PublicOrigin = "http://x" }),
		"no dsn":        mut(func(c *Config) { c.DB.DSN = "" }),
		"no valkey":     mut(func(c *Config) { c.Valkey.Addresses = nil }),
		"no issuer":     mut(func(c *Config) { c.Auth.Issuer = "" }),
		"short ttl":     mut(func(c *Config) { c.Leases.TTL = 15 * time.Second }),
		"zero limit":    mut(func(c *Config) { c.Forward.BodyBytes = 0 }),
		"no operators":  mut(func(c *Config) { c.Operators.Roles = nil }),
		"prod no cert":  mut(func(c *Config) { c.Config.Env = "production"; c.Edge.CertFile = "" }),
		"prod plain kv": mut(func(c *Config) { c.Config.Env = "production"; c.Valkey.AllowPlaintext = true }),
		"prod weak ssl": mut(func(c *Config) { c.Config.Env = "production"; c.DB.DSN = "postgres://u@db/g?sslmode=disable" }),
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	dev := valid()
	dev.Edge.CertFile = ""
	dev.Valkey.AllowPlaintext = true
	dev.DB.DSN = "postgres://u@db/g?sslmode=disable"
	dev.Edge.AllowedOrigins = []string{"*"}
	if err := dev.Validate(); err != nil {
		t.Fatal(err)
	}
	if w := dev.Warnings(); len(w) != 4 {
		t.Fatalf("warnings %v", w)
	}
}

func TestLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "gw.yaml")
	_ = os.WriteFile(p, []byte("service_name: gw\ntrust_domain: example.org\npublic_origin: https://x\nleases: { ttl: 40s, renew: 5s }\nforward: { body_bytes: 2048 }\n"), 0o600)
	c, err := Load(p)
	if err != nil || c.ServiceName != "gw" || c.Leases.TTL != 40*time.Second || c.Forward.BodyBytes != 2048 || c.Forward.StreamsPerClient != 32 {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil || !strings.Contains(err.Error(), "config") {
		t.Fatal("missing file")
	}
	_ = os.WriteFile(p, []byte("service_name: [\n"), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("malformed yaml")
	}
	_ = os.WriteFile(p, []byte("service_name: gw\nedge: { rate_limit: { per_second: 5, burst: 9 } }\nlimits: { body_bytes: 1 }\n"), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("unknown field must be refused")
	}
	_ = os.WriteFile(p, []byte("service_name: gw\nedge: { rate_limit: { per_second: 5, burst: 9 } }\n"), 0o600)
	if c, err := Load(p); err != nil || c.Edge.RateLimit.PerSecond != 5 || c.Edge.RateLimit.Burst != 9 {
		t.Fatalf("%+v %v", c.Edge.RateLimit, err)
	}
}
