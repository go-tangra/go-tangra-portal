// Package catalogue reads module catalogue entries from their source
// repositories' GitHub releases and verifies them before anything is stored
// (spec 035). An entry is trusted only when its GitHub artifact attestation
// (Sigstore, keyless) shows it was built by a workflow of that repository
// running on the release tag.
package catalogue

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// GitHubIssuer is the OIDC issuer of GitHub Actions workflow identities.
const GitHubIssuer = "https://token.actions.githubusercontent.com"

// ErrAttestation wraps every attestation refusal.
var ErrAttestation = errors.New("catalogue: attestation refused")

// Verifier checks release attestations against Sigstore trusted material.
type Verifier struct {
	trusted root.TrustedMaterial
}

// NewVerifier uses trusted (the public-good trusted root in production; a
// virtual Sigstore in tests).
func NewVerifier(trusted root.TrustedMaterial) *Verifier { return &Verifier{trusted: trusted} }

// LiveTrustedRoot fetches Sigstore's public-good trusted root over TUF and
// refreshes it daily. The local cache is off: the gateway image has no
// writable home.
func LiveTrustedRoot() (root.TrustedMaterial, error) {
	opts := tuf.DefaultOptions()
	opts.DisableLocalCache = true
	return root.NewLiveTrustedRootFromTargetWithPeriod(opts, "trusted_root.json", 24*time.Hour)
}

// VerifyBundle parses a Sigstore bundle (catalogue.sigstore.json) and
// verifies it covers every artifact for repository at tag. It returns the
// workflow identity (certificate SAN) that built them.
func (v *Verifier) VerifyBundle(bundleJSON []byte, repository, tag string, artifacts ...[]byte) (string, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return "", fmt.Errorf("%w: not a Sigstore bundle", ErrAttestation)
	}
	return v.verifyEntity(&b, repository, tag, artifacts...)
}

func (v *Verifier) verifyEntity(entity verify.SignedEntity, repository, tag string, artifacts ...[]byte) (string, error) {
	if len(artifacts) == 0 {
		return "", fmt.Errorf("%w: nothing to verify", ErrAttestation)
	}
	owner, repo, ok := strings.Cut(repository, "/")
	if !ok || owner == "" || repo == "" || !strings.HasPrefix(tag, "v") {
		return "", fmt.Errorf("%w: bad repository or tag", ErrAttestation)
	}
	// The repository's own workflow, at exactly this tag. GitHub owner and
	// repository names are case-insensitive; the rest is exact.
	san := `^https://github\.com/(?i:` + regexp.QuoteMeta(owner) + `/` + regexp.QuoteMeta(repo) + `)/\.github/workflows/[^@]+@refs/tags/` + regexp.QuoteMeta(tag) + `$`
	id, err := verify.NewShortCertificateIdentity(GitHubIssuer, "", "", san)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrAttestation, err)
	}
	sv, err := verify.NewVerifier(v.trusted, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrAttestation, err)
	}
	var who string
	// Every artifact must be a subject of the same attestation.
	for i, a := range artifacts {
		res, err := sv.Verify(entity, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(a)), verify.WithCertificateIdentity(id)))
		if err != nil {
			return "", fmt.Errorf("%w: artifact %d: %v", ErrAttestation, i+1, err)
		}
		if res.Signature != nil && res.Signature.Certificate != nil {
			who = res.Signature.Certificate.SubjectAlternativeName
		}
	}
	return who, nil
}

// LazyVerify returns a VerifyFunc that fetches the live trusted root on first
// use (and again after a failed fetch), so the gateway starts without
// reaching Sigstore.
func LazyVerify(fetch func() (root.TrustedMaterial, error)) VerifyFunc {
	var (
		mu sync.Mutex
		v  *Verifier
	)
	return func(attestation []byte, repo, tag string, artifacts ...[]byte) (string, error) {
		mu.Lock()
		if v == nil {
			tm, err := fetch()
			if err != nil {
				mu.Unlock()
				return "", fmt.Errorf("%w: Sigstore trusted root unavailable: %v", ErrUnavailable, err)
			}
			v = NewVerifier(tm)
		}
		cur := v
		mu.Unlock()
		return cur.VerifyBundle(attestation, repo, tag, artifacts...)
	}
}
