# Research: Catalogue Sources

## R1. How releases prove where an entry came from

**Decision**: GitHub artifact attestations (`actions/attest-build-provenance@v2`),
keyless through Sigstore's public-good instance. The release job attaches each
asset's Sigstore bundle (`<asset>.sigstore.json`) to the release, so the
gateway needs no GitHub attestation API and the upload path verifies the same
files.

**Rationale**: No shared signing key (2026-10-10 decision); the certificate
names the exact workflow and tag.

**Alternatives**: a central signing key in go-tangra-tech (rejected: shared
secret, go-tangra-tech is documentation only); cosign keyed signatures
(rejected: key per repository); trusting HTTPS from github.com alone
(rejected: no protection against a compromised release upload token).

## R2. Verification library

**Decision**: `github.com/sigstore/sigstore-go` v1.3.0.

**Rationale** (Constitution VI): the reference Go implementation of Sigstore
bundle verification (certificate chain to Fulcio, SCTs, Rekor inclusion
proofs, DSSE/in-toto subjects). Writing this ourselves would be custom
cryptographic verification, which the constitution forbids. Maintained by the
Sigstore project (OpenSSF), Apache-2.0, used by `gh attestation verify`.
`govulncheck` is run on the result.

**Policy**: issuer exactly `https://token.actions.githubusercontent.com`;
SAN matching
`^https://github\.com/<owner>/<repo>/\.github/workflows/[^@]+@refs/tags/<tag>$`
(the source repository's own workflow on the release tag); transparency log
inclusion required (threshold 1); artifact digest = sha256 of the downloaded
bytes.

## R3. Trusted root

**Decision**: `root.NewLiveTrustedRoot` with TUF from Sigstore's public CDN,
local cache disabled (distroless container, no writable home), refreshed
daily; tests inject trusted material from the virtual Sigstore.

## R4. Where the shared release step lives

**Decision**: composite action `go-tangra/go-tangra/.github/actions/catalogue-entry`
(the framework repository every module already depends on), pinned by tag in
module workflows.

**Rationale**: `go-tangra-actions` is an automation engine product, not a
GitHub Actions repository. A composite action keeps the attestation identity
the module's own workflow (R2 policy), unlike a reusable workflow.

## R5. Descriptor validation in the action

**Decision**: the action runs `go run github.com/go-tangra/go-tangra/v4/cmd/tangra-catalogue@<tag>`
(new small command in the framework: validate the YAML strictly, check the
image tag with an anonymous registry HEAD, build the entry and the bundle zip
deterministically).

**Rationale**: one implementation shared by every module; the same Go types
are used by the gateway to parse entries (shared package
`github.com/go-tangra/go-tangra/v4/catalogue`).

## R6. Polling budget

18 sources × 4 polls/day × (1 API call for the latest release) = 72 API calls
per day, far below 60 per hour unauthenticated. Asset downloads go to
`objects.githubusercontent.com` and do not count.

## R7. Version ordering

Semantic versions without a leading `v`; pre-releases (`-rc.1`) are ignored
by polling (GitHub "latest release" never returns them) and refused on upload.

## STRIDE

| Threat | Scenario | Mitigation |
|---|---|---|
| Spoofing | A repository impersonates another module | SAN must name the source repository; module name bound to the first source that published it |
| Tampering | Release asset replaced after release | Sigstore bundle covers exact bytes; transparency log inclusion |
| Tampering | Zip with `../` paths or symlinks | Zip validation (SR-003) before storing |
| Repudiation | Who added a source | Audit `catalogue_source_added/removed`, `allowed_owners_changed` |
| Information disclosure | Optional GitHub token logged | Token only from config/env, never logged |
| Denial of service | Huge assets, slow GitHub | Size limits, 30 s timeouts, poller off the request path |
| Elevation of privilege | Source URL used for SSRF | Sources are `owner/repo` names; fixed hosts only (SR-002) |
| Downgrade | Old release replayed by upload | Version must increase per module |
