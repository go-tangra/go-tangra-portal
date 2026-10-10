# Implementation Plan: Catalogue Sources (phase 2)

**Branch**: `035-catalogue-sources` | **Date**: 2026-10-10 | **Spec**: [spec.md](spec.md)

## Summary

A shared `catalogue` package and `tangra-catalogue` command in the framework
define and build entries; a composite action in the framework repository
validates, builds, attests and attaches them on module releases; the pilot
modules (sms-gw, asterisk) adopt it. The gateway stores sources and allowed
owners, polls GitHub releases off the request path, verifies Sigstore bundles
with sigstore-go, stores verified entries and bundles, and merges them into
the catalogue view (`available`, `update_available`).

## Technical Context

**Language/Version**: Go 1.26; TypeScript/Vue 3 (shell); GitHub Actions YAML
**Primary Dependencies**: new `github.com/sigstore/sigstore-go` v1.3.0 (gateway
only, research R2); `gopkg.in/yaml.v3` (framework, already used)
**Storage**: gateway Postgres: `catalogue_sources`, `catalogue_entries`,
`catalogue_allowed_owners` (migration 0006)
**Testing**: `go test -race`; Sigstore virtual CA (`sigstore-go/pkg/testing/ca`)
for verification tests; httptest GitHub fake
**Constraints**: poller never on request/registration paths; fixed outbound hosts
**Scale/Scope**: ~18 sources, entries ≤ 256 KiB, bundles ≤ 8 MiB

## Constitution Check

- [x] **I. Secure by Default**: verification cannot be disabled; allowed owners default `[go-tangra]`.
- [x] **II. Zero Trust**: content trusted only after Sigstore verification; admin-only changes.
- [x] **III. Boundary Validation**: strict YAML/JSON (unknown fields refused), size limits, zip validation, owner/repo pattern.
- [x] **IV. Test-First**: tests listed first: tampered, foreign-repo, wrong-tag, downgrade, takeover, zip traversal.
- [x] **V. Observability**: audit events for sources, owners, verified and refused entries.
- [x] **VI. Supply Chain**: sigstore-go justified (R2); no custom crypto; govulncheck.
- [x] **VII. Simplicity**: typed config `catalogue: { poll, github_token_env, allowed_owners }`.
- [x] **Threat Model**: STRIDE in research.md.

## Project Structure

```text
fw: go-tangra (branch 035-catalogue-sources)
  catalogue/                      # Descriptor, Entry, Validate, BuildBundle, version compare
  cmd/tangra-catalogue/           # validate | build (used by the action)
  .github/actions/catalogue-entry/action.yml
sms: go-tangra-sms-gw-v4 / ast: go-tangra-asterisk-v4 (branch 035-catalogue-sources)
  tangra-module.yaml, deploy/bundle/*, .github/workflows/ci.yaml (release job)
portal: go-tangra-portal-v4
  internal/store/migrations/0006_catalogue.sql, store repos, adapter, memstore
  internal/catalogue/             # poller (GitHub client), verifier (sigstore), service
  internal/httpapi/catalogue.go   # sources, owners, upload; view merge
  api/openapi/gateway.yaml        # + spec 003 copy
  shell/src/views/ops/Modules.vue # available, update notices, Sources panel
```

## Complexity Tracking

| Addition | Why needed | Simpler alternative rejected |
|---|---|---|
| sigstore-go dependency (large tree) | Keyless attestation verification (R1/R2) | Custom verification = custom crypto (forbidden); shared key (decision against) |
