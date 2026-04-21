package data

import (
	"os"
	"strings"

	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"gopkg.in/yaml.v3"
)

// PublicBaseURL is the externally-reachable origin of the portal (scheme + host
// [+ port]) used when embedding links in outbound emails. No trailing slash.
type PublicBaseURL string

// NewPublicBaseURL resolves the public base URL with the following priority:
//  1. PORTAL_PUBLIC_BASE_URL env var
//  2. First entry in webauthn.rp_origins (already configured for production)
//  3. http://localhost:8080 (dev fallback)
func NewPublicBaseURL(ctx *bootstrap.Context) PublicBaseURL {
	if v := strings.TrimRight(os.Getenv("PORTAL_PUBLIC_BASE_URL"), "/"); v != "" {
		return PublicBaseURL(v)
	}

	var cfg webAuthnYAMLConfig
	for _, p := range configSearchPaths() {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if yaml.Unmarshal(data, &cfg) == nil && len(cfg.WebAuthn.RPOrigins) > 0 {
			if origin := strings.TrimRight(cfg.WebAuthn.RPOrigins[0], "/"); origin != "" {
				return PublicBaseURL(origin)
			}
			break
		}
	}

	return PublicBaseURL("http://localhost:8080")
}
