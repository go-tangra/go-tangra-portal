package config

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Console configures the optional console listener (feature 025): a second
// public TLS port serving only the configured path prefixes (the BMC KVM
// consoles of ipam) on an origin of their own, so vendor console JavaScript
// never runs on the portal origin. It authenticates nobody: the module's
// console token gates access. Off by default.
type Console struct {
	Enabled bool `yaml:"enabled"`
	// Addr is the listen address (default ":8444").
	Addr string `yaml:"addr"`
	// PublicOrigin is the https origin browsers use for the listener, e.g.
	// https://portal.example.com:8444. It must differ from public_origin and
	// must not be in edge.allowed_origins.
	PublicOrigin string `yaml:"public_origin"`
	// Routes maps a path prefix ("/bmc/") to the module that serves it
	// (default {"/bmc/": "ipam"}); every other path answers 404.
	Routes map[string]string `yaml:"routes"`
	// Cookies are the only cookie names forwarded to the module and relayed
	// back to the browser (default ["freya_kvm"]).
	Cookies []string `yaml:"cookies"`
	// SessionMax bounds a console WebSocket (default 1h, at most 24h).
	SessionMax time.Duration `yaml:"session_max"`
	// MaxConcurrent bounds in-flight requests (default 64).
	MaxConcurrent int `yaml:"max_concurrent"`
}

// DefaultConsoleRoutes is used when console.routes is empty.
var DefaultConsoleRoutes = map[string]string{"/bmc/": "ipam"}

// DefaultConsoleCookies is used when console.cookies is empty.
var DefaultConsoleCookies = []string{"freya_kvm"}

func defaultConsole() Console {
	return Console{Addr: ":8444", SessionMax: time.Hour, MaxConcurrent: 64}
}

// RouteMap returns the configured routes, or the default.
func (c Console) RouteMap() map[string]string {
	src := c.Routes
	if len(src) == 0 {
		src = DefaultConsoleRoutes
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// CookieNames returns the configured cookie allow-list, or the default.
func (c Console) CookieNames() []string {
	if len(c.Cookies) == 0 {
		return append([]string(nil), DefaultConsoleCookies...)
	}
	return append([]string(nil), c.Cookies...)
}

// Origin returns the canonical console origin ("" when invalid).
func (c Console) Origin() string {
	o, _ := canonicalOrigin(c.PublicOrigin)
	return o
}

// FrameSources returns the origins the portal's pages may frame: the
// configured edge.frame_sources plus the console origin when enabled.
func (c Config) FrameSources() []string {
	out := append([]string(nil), c.Edge.FrameSources...)
	if c.Console.Enabled {
		if o := c.Console.Origin(); o != "" {
			out = append(out, o)
		}
	}
	return out
}

var (
	prefixRe = regexp.MustCompile(`^/[a-z0-9_-]+(/[a-z0-9_-]+)*/$`)
	moduleRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	// RFC 6265 cookie-name token characters.
	cookieRe = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")
)

// reservedPrefixes are the portal's own path spaces; a console prefix may
// never shadow them.
var reservedPrefixes = []string{"/api/", "/gateway/", "/m/"}

func (c Config) validateConsole() error {
	for _, f := range c.Edge.FrameSources {
		if _, err := canonicalOrigin(f); err != nil {
			return fmt.Errorf("config: edge.frame_sources %q: %w", f, err)
		}
	}
	k := c.Console
	if !k.Enabled {
		return nil
	}
	origin, err := canonicalOrigin(k.PublicOrigin)
	if err != nil {
		return fmt.Errorf("config: console.public_origin: %w", err)
	}
	if portal, _ := canonicalOrigin(c.PublicOrigin); portal == origin {
		return errors.New("config: console.public_origin must differ from public_origin")
	}
	for _, a := range c.Edge.AllowedOrigins {
		if o, _ := canonicalOrigin(a); o == origin {
			return errors.New("config: console.public_origin must not be in edge.allowed_origins (it must never pass the CSRF origin check)")
		}
	}
	switch {
	case c.Edge.CertFile == "" || c.Edge.KeyFile == "":
		return errors.New("config: console requires edge.cert_file and edge.key_file (the listener reuses the edge certificate)")
	case strings.TrimSpace(k.Addr) == "":
		return errors.New("config: console.addr is required")
	case k.SessionMax < time.Minute || k.SessionMax > 24*time.Hour:
		return errors.New("config: console.session_max must be within [1m, 24h]")
	case k.MaxConcurrent < 1 || k.MaxConcurrent > 10000:
		return errors.New("config: console.max_concurrent must be within [1, 10000]")
	}
	routes := k.RouteMap()
	prefixes := make([]string, 0, len(routes))
	for p := range routes {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)
	for _, p := range prefixes {
		if !prefixRe.MatchString(p) {
			return fmt.Errorf("config: console.routes prefix %q must look like /name/ (lower-case letters, digits, '-', '_')", p)
		}
		for _, r := range reservedPrefixes {
			if strings.HasPrefix(p, r) {
				return fmt.Errorf("config: console.routes prefix %q is reserved by the portal", p)
			}
		}
		if !moduleRe.MatchString(routes[p]) {
			return fmt.Errorf("config: console.routes %q: invalid module name %q", p, routes[p])
		}
	}
	for _, n := range k.CookieNames() {
		l := strings.ToLower(n)
		switch {
		case !cookieRe.MatchString(n):
			return fmt.Errorf("config: console.cookies: invalid cookie name %q", n)
		case strings.HasPrefix(l, "__host-") || strings.HasPrefix(l, "__secure-"):
			return fmt.Errorf("config: console.cookies: %q is a portal-reserved cookie prefix", n)
		}
	}
	return nil
}

// canonicalOrigin returns v as a lower-case https origin without a trailing
// slash or the default port, or an error when v is not exactly an origin.
func canonicalOrigin(v string) (string, error) {
	if strings.ContainsAny(v, " \t\r\n;,'\"") {
		return "", errors.New("must not contain whitespace, quotes, ';' or ','")
	}
	u, err := url.Parse(v)
	if err != nil {
		return "", errors.New("not a URL")
	}
	switch {
	case u.Scheme != "https":
		return "", errors.New("must be an https origin")
	case u.Hostname() == "" || strings.HasSuffix(u.Host, ":"):
		return "", errors.New("host is required")
	case u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.Opaque != "":
		return "", errors.New("must be an origin (no user, path, query or fragment)")
	}
	host := strings.ToLower(u.Host)
	host = strings.TrimSuffix(host, ":443")
	return "https://" + host, nil
}
