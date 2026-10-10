package catalogue

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
)

const ghIssuer = "https://token.actions.githubusercontent.com"

func statement(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var subjects []map[string]any
	for name, data := range files {
		sum := sha256.Sum256(data)
		subjects = append(subjects, map[string]any{"name": name, "digest": map[string]string{"sha256": hex.EncodeToString(sum[:])}})
	}
	b, err := json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v1", "subject": subjects,
		"predicateType": "https://slsa.dev/provenance/v1", "predicate": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyAttestation(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	entry, bundle := []byte(`{"module":"sms-gw"}`), []byte("PK zip bytes")
	san := "https://github.com/go-tangra/go-tangra-sms-gw/.github/workflows/ci.yaml@refs/tags/v4.3.0"
	good, err := vs.Attest(san, ghIssuer, statement(t, map[string][]byte{"catalogue-entry.json": entry, "bundle.zip": bundle}))
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(vs)
	id, err := v.verifyEntity(good, "go-tangra/go-tangra-sms-gw", "v4.3.0", entry, bundle)
	if err != nil || id != san {
		t.Fatalf("valid attestation refused: %q %v", id, err)
	}
	// Repository names are case-insensitive on GitHub.
	if _, err := v.verifyEntity(good, "Go-Tangra/go-tangra-SMS-gw", "v4.3.0", entry, bundle); err != nil {
		t.Fatalf("case: %v", err)
	}

	other, _ := vs.Attest("https://github.com/evil/go-tangra-sms-gw/.github/workflows/ci.yaml@refs/tags/v4.3.0", ghIssuer, statement(t, map[string][]byte{"catalogue-entry.json": entry, "bundle.zip": bundle}))
	branch, _ := vs.Attest("https://github.com/go-tangra/go-tangra-sms-gw/.github/workflows/ci.yaml@refs/heads/main", ghIssuer, statement(t, map[string][]byte{"catalogue-entry.json": entry, "bundle.zip": bundle}))
	notGitHub, _ := vs.Attest(san, "https://accounts.google.com", statement(t, map[string][]byte{"catalogue-entry.json": entry, "bundle.zip": bundle}))
	onlyEntry, _ := vs.Attest(san, ghIssuer, statement(t, map[string][]byte{"catalogue-entry.json": entry}))
	lookalike, _ := vs.Attest("https://github.com/go-tangra/go-tangra-sms-gw-fork/.github/workflows/ci.yaml@refs/tags/v4.3.0", ghIssuer, statement(t, map[string][]byte{"catalogue-entry.json": entry, "bundle.zip": bundle}))
	for name, tc := range map[string]struct {
		entity any
		repo   string
		tag    string
		entry  []byte
		bundle []byte
	}{
		"tampered entry":        {good, "go-tangra/go-tangra-sms-gw", "v4.3.0", []byte(`{"module":"evil"}`), bundle},
		"tampered bundle":       {good, "go-tangra/go-tangra-sms-gw", "v4.3.0", entry, []byte("PK evil")},
		"other tag":             {good, "go-tangra/go-tangra-sms-gw", "v4.3.1", entry, bundle},
		"other repository":      {other, "go-tangra/go-tangra-sms-gw", "v4.3.0", entry, bundle},
		"look-alike repository": {lookalike, "go-tangra/go-tangra-sms-gw", "v4.3.0", entry, bundle},
		"branch, not tag":       {branch, "go-tangra/go-tangra-sms-gw", "v4.3.0", entry, bundle},
		"not GitHub Actions":    {notGitHub, "go-tangra/go-tangra-sms-gw", "v4.3.0", entry, bundle},
		"bundle not attested":   {onlyEntry, "go-tangra/go-tangra-sms-gw", "v4.3.0", entry, bundle},
	} {
		e := tc.entity.(*ca.TestEntity)
		if _, err := v.verifyEntity(e, tc.repo, tc.tag, tc.entry, tc.bundle); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A bundle that is not a Sigstore bundle at all.
	if _, err := v.VerifyBundle([]byte(`{"not":"a bundle"}`), "go-tangra/go-tangra-sms-gw", "v4.3.0", entry, bundle); err == nil || !strings.Contains(err.Error(), "attestation") {
		t.Fatalf("garbage accepted: %v", err)
	}
}
