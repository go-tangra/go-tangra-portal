package gatewayclient

import (
	"fmt"
	"sync"
)

// docsDigest identifies the documentation bundle the process ships (see
// SetDocsDigest).
var (
	docsDigest string
	docsMu     sync.RWMutex
)

// SetDocsDigest records the digest of the documentation bundle this process
// ships: the lowercase hex SHA-256 (64 characters) the helpdocs package
// yields, or "" when the module ships no documentation. It is sent with every
// registration whose Options.DocsDigest is empty. Call it before New; New
// refuses a malformed digest (see ValidateDocsDigest).
//
// The digest travels beside the manifest, not in it: changing documentation
// never needs a manifest version bump.
func SetDocsDigest(d string) {
	docsMu.Lock()
	docsDigest = d
	docsMu.Unlock()
}

// DocsDigest is the process documentation digest set with SetDocsDigest
// ("" when none was set).
func DocsDigest() string {
	docsMu.RLock()
	defer docsMu.RUnlock()
	return docsDigest
}

// ValidateDocsDigest accepts "" (no documentation) or exactly 64 lowercase
// hexadecimal characters (a SHA-256 digest); the gateway applies the same
// rule and refuses anything else with docs_digest_invalid.
func ValidateDocsDigest(d string) error {
	if d == "" {
		return nil
	}
	if len(d) != 64 {
		return fmt.Errorf("gatewayclient: docs digest %q must be 64 lowercase hex characters (sha256) or empty, got %d characters", d, len(d))
	}
	for i := 0; i < len(d); i++ {
		if c := d[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("gatewayclient: docs digest %q must be 64 lowercase hex characters (sha256) or empty", d)
		}
	}
	return nil
}
