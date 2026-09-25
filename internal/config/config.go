package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	fconfig "github.com/go-tangra/go-tangra/v4/config"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
)

// Config is the Freya configuration plus the gateway's own settings.
type Config struct {
	fconfig.Config `yaml:",inline"`

	PublicOrigin string    `yaml:"public_origin"` // https://host[:port] browsers use
	Edge         Edge      `yaml:"edge"`
	DB           DB        `yaml:"db"`
	Valkey       Valkey    `yaml:"valkey"`
	Auth         Auth      `yaml:"auth"`
	Leases       Leases    `yaml:"leases"`
	Forward      Forward   `yaml:"forward"`
	Operators    Operators `yaml:"operators"`
	Enroll       Enroll    `yaml:"enroll"`
}

// Enroll makes the gateway obtain its SVID by enrolling with lcm over the
// network (direct to lcm's keyless enroll listener), instead of a cert file.
// The first enroll verifies lcm's SVID with ca_file (the mesh trust bundle)
// and server_spiffe_id (default spiffe://<trust_domain>/svc/lcm); insecure
// skips that verification and is refused in production (fconfig.EnrollTLS).
type Enroll struct {
	Enabled           bool   `yaml:"enabled"`
	EnrollURL         string `yaml:"enroll_url"`
	LCMGRPCTarget     string `yaml:"lcm_grpc"`
	TenantID          string `yaml:"tenant_id"`
	TokenFile         string `yaml:"token_file"`
	StateFile         string `yaml:"state_file"`
	fconfig.EnrollTLS `yaml:",inline"`
}

// Edge configures the public listener.
type Edge struct {
	Addr           string         `yaml:"addr"`
	CertFile       string         `yaml:"cert_file"`
	KeyFile        string         `yaml:"key_file"`
	AllowedOrigins []string       `yaml:"allowed_origins"`
	TrustedProxies []string       `yaml:"trusted_proxies"`
	RateLimit      edge.RateLimit `yaml:"rate_limit"`
}

// DB is the gateway database (allow-list, marks, audit).
type DB struct {
	DSN        string `yaml:"dsn"`
	MigrateDSN string `yaml:"migrate_dsn"`
	MaxConns   int32  `yaml:"max_conns"`
}

// Valkey holds registrations, leases and caches.
type Valkey struct {
	Addresses      []string `yaml:"addresses"`
	Username       string   `yaml:"username"`
	Password       string   `yaml:"password"`
	AllowPlaintext bool     `yaml:"allow_plaintext"`
	CAFile         string   `yaml:"ca_file"`
}

// Auth locates the authentication module on the service channel.
type Auth struct {
	Service  string `yaml:"service"`  // discovery name, e.g. "auth"
	Issuer   string `yaml:"issuer"`   // expected token issuer
	Audience string `yaml:"audience"` // audience accepted from machine clients ("gateway")
}

// Leases tunes registration leases.
type Leases struct {
	TTL   time.Duration `yaml:"ttl"`
	Renew time.Duration `yaml:"renew"`
}

// Forward bounds forwarded traffic.
type Forward struct {
	BodyBytes        int64         `yaml:"body_bytes"`
	StreamsPerClient int           `yaml:"streams_per_client"`
	StreamMax        time.Duration `yaml:"stream_max"`
	ModuleTimeout    time.Duration `yaml:"module_timeout"`
}

// Operators names the roles (in the platform tenant) that may operate the gateway.
type Operators struct {
	Roles []string `yaml:"roles"`
}

// Default returns secure defaults; addresses and secrets must be provided.
func Default() Config {
	c := Config{Config: fconfig.Default()}
	c.Config.ServiceName = "gateway"
	c.Edge = Edge{Addr: ":8443"}
	c.DB = DB{MaxConns: 8}
	c.Auth = Auth{Service: "auth", Audience: "gateway"}
	c.Leases = Leases{TTL: 30 * time.Second, Renew: 10 * time.Second}
	c.Forward = Forward{BodyBytes: 1 << 20, StreamsPerClient: 32, StreamMax: 10 * time.Minute, ModuleTimeout: 30 * time.Second}
	c.Operators = Operators{Roles: []string{"operator"}}
	return c
}

// Load reads a YAML file over the defaults; unknown fields are rejected.
func Load(path string) (Config, error) {
	c := Default()
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied configuration path
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("config: %s: %w", path, err)
	}
	return c, nil
}

// Validate refuses insecure or inconsistent settings (stricter in production).
func (c Config) Validate() error {
	if err := c.Config.Validate(); err != nil {
		return err
	}
	prod := c.IsProduction()
	switch {
	case !strings.HasPrefix(c.PublicOrigin, "https://"):
		return errors.New("config: public_origin must be an https origin")
	case c.DB.DSN == "":
		return errors.New("config: db.dsn is required")
	case len(c.Valkey.Addresses) == 0:
		return errors.New("config: valkey.addresses is required")
	case c.Auth.Service == "" || !strings.HasPrefix(c.Auth.Issuer, "https://"):
		return errors.New("config: auth.service and an https auth.issuer are required")
	case c.Leases.TTL <= 0 || c.Leases.Renew <= 0 || c.Leases.TTL < 2*c.Leases.Renew:
		return errors.New("config: leases.ttl must be at least twice leases.renew")
	case c.Forward.BodyBytes <= 0 || c.Forward.StreamsPerClient <= 0 || c.Forward.StreamMax <= 0 || c.Forward.ModuleTimeout <= 0:
		return errors.New("config: forward limits must be positive")
	case len(c.Operators.Roles) == 0:
		return errors.New("config: operators.roles must not be empty")
	}
	if c.Enroll.Enabled {
		switch {
		case !strings.HasPrefix(c.Enroll.EnrollURL, "https://"):
			return errors.New("config: enroll.enroll_url must be an https URL")
		case c.Enroll.LCMGRPCTarget == "":
			return errors.New("config: enroll.lcm_grpc is required")
		case c.Enroll.TokenFile == "":
			return errors.New("config: enroll.token_file is required")
		}
		if err := c.Enroll.EnrollTLS.Validate(c.TrustDomain, prod); err != nil {
			return err
		}
	}
	if prod {
		switch {
		case c.Edge.CertFile == "" || c.Edge.KeyFile == "":
			return errors.New("config: production requires edge.cert_file and edge.key_file")
		case c.Valkey.AllowPlaintext:
			return errors.New("config: production refuses valkey.allow_plaintext")
		case !strings.Contains(c.DB.DSN, "sslmode=verify-full") && !strings.Contains(c.DB.DSN, "sslmode=verify-ca"):
			return errors.New("config: production requires db.dsn sslmode=verify-full or verify-ca")
		}
	}
	return nil
}

// Warnings lists accepted but noteworthy settings.
func (c Config) Warnings() []string {
	var w []string
	if c.Edge.CertFile == "" {
		w = append(w, "edge listener will use a generated self-signed certificate")
	}
	if c.Valkey.AllowPlaintext {
		w = append(w, "valkey connection without TLS (allow_plaintext)")
	}
	if !strings.Contains(c.DB.DSN, "sslmode=verify-full") {
		w = append(w, "db.dsn sslmode is weaker than verify-full")
	}
	if c.Enroll.Enabled {
		w = append(w, c.Enroll.EnrollTLS.Warnings()...)
	}
	for _, o := range c.Edge.AllowedOrigins {
		if o == "*" {
			w = append(w, "edge.allowed_origins permits every origin")
		}
	}
	return w
}
