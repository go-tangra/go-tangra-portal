# Feature Specification: Catalogue Sources (gateway module catalogue, phase 2)

**Feature Branch**: `035-catalogue-sources`
**Created**: 2026-10-10
**Status**: Draft
**Input**: Gateway module catalogue design, phase 2: every module repository
describes itself (`tangra-module.yaml`, `deploy/bundle/`) and its release
workflow publishes an attested catalogue entry; the gateway reads the latest
release of each source repository, verifies the attestation, lists available
modules and flags instances running an older release.

## Context

Phase 1 (034, released in gateway 4.9.0) gave the gateway a memory of every
module it has seen register. It still knows nothing about modules that are not
installed, nor whether a running module is behind its latest release.

Decisions (2026-10-10): module data lives in each module's own repository,
never in go-tangra-tech (documentation only); entries are attested at release
by GitHub (no shared signing key); production cores reach GitHub; the gateway
both polls on a schedule and accepts uploads; only platform-tenant
administrators manage the catalogue.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A module release publishes its catalogue entry (Priority: P1) 🎯 MVP

A maintainer tags `v4.3.0` on sms-gw. The release workflow validates
`tangra-module.yaml`, checks the image tag is pullable, writes
`catalogue-entry.json` (with version and the permission list from the module's
manifest), packs `deploy/bundle/` into `bundle.zip`, attests both (one attestation
with both as subjects) and attaches them and `catalogue.sigstore.json` to the
GitHub release.

**Why this priority**: Without published entries the gateway has nothing to
read. It is also useful alone: every release carries a verifiable description.

**Independent Test**: Tag a pilot module; the release has
`catalogue-entry.json`, `bundle.zip` and `catalogue.sigstore.json`, and
`gh attestation verify` accepts them for that repository.

**Acceptance Scenarios**:

1. **Given** a valid `tangra-module.yaml`, **When** a `v*` tag is pushed,
   **Then** the release carries the entry, the bundle and the attestation bundle.
2. **Given** a `tangra-module.yaml` with an unknown field or a missing
   required field, **When** the tag is pushed, **Then** the release job fails
   and nothing is attached.
3. **Given** the image tag is not pullable, **When** the tag is pushed,
   **Then** the release job fails.

---

### User Story 2 - Administrators add source repositories (Priority: P1)

A platform administrator adds `go-tangra/go-tangra-sms-gw` as a catalogue
source. The gateway reads its latest release, verifies the attestation and
shows sms-gw on the Modules page with its latest version, even if sms-gw is
not installed (`available`).

**Why this priority**: The core of phase 2: the catalogue knows modules that
are not installed.

**Independent Test**: Add a source; within one refresh the module is listed
with the entry's latest version and summary; a source whose owner is not
allowed is refused.

**Acceptance Scenarios**:

1. **Given** `go-tangra` is an allowed owner, **When** an administrator adds
   `go-tangra/go-tangra-sms-gw`, **Then** its latest release entry is verified
   and stored, and the Modules page shows it.
2. **Given** a repository of another owner, **When** it is added, **Then** the
   request is refused (400) and nothing is stored.
3. **Given** a release whose attestation does not verify (wrong repository,
   wrong workflow, tampered bytes), **When** the gateway refreshes, **Then**
   the entry is refused, the source shows the error, and the previous entry
   stays current.
4. **Given** an older release than the stored one, **When** it is offered
   (refresh or upload), **Then** it is refused (no rollback by replay).

---

### User Story 3 - Update available (Priority: P2)

On the Modules page a running module whose instances run an older release
than the catalogue's latest shows **update available** with both versions.

**Why this priority**: The first operational payoff of having entries.

**Independent Test**: With sms-gw running 4.2.0 and the entry at 4.3.0, the
row shows update available 4.2.0 → 4.3.0.

**Acceptance Scenarios**:

1. **Given** sms-gw runs 4.2.0 and the latest entry is 4.3.0, **Then** the
   row shows `update available` and both versions.
2. **Given** sms-gw runs 4.3.0, **Then** no update is shown.
3. **Given** a module with no entry, **Then** nothing is shown about updates.

---

### User Story 4 - Air-gapped cores upload entries (Priority: P3)

An administrator uploads a release's `catalogue-entry.json`, `bundle.zip`
and `catalogue.sigstore.json`; the gateway verifies them exactly as
when polling.

**Why this priority**: Exception path; prod reaches GitHub.

**Independent Test**: Upload valid assets → stored; tampered entry → 400.

---

### User Story 5 - Administrators manage the allowed owners (Priority: P3)

Administrators see and change the list of GitHub owners whose repositories
may be sources; gateway config only seeds it.

**Independent Test**: Replace the list; adding a source of a removed owner is
refused; existing sources of a removed owner stop refreshing.

### Edge Cases

- GitHub unreachable or rate-limited: last verified entries stay current; the
  source shows `last_error`; nothing else changes.
- A release without catalogue assets (a module not migrated yet): the source
  shows "no catalogue entry in release vX".
- An entry whose `module` differs from the module previously published by the
  same repository: refused.
- Two repositories claiming the same module name: the second is refused.
- Oversized assets: refused before reading fully (entry ≤ 256 KiB, bundle
  ≤ 8 MiB).
- A bundle zip with paths escaping the root, symlinks or absolute paths:
  refused.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Module repositories MUST describe themselves in
  `tangra-module.yaml` (schema 1, see contracts/tangra-module.md) and keep
  their install bundle in `deploy/bundle/`.
- **FR-002**: A shared composite action (`go-tangra/go-tangra/.github/actions/catalogue-entry`)
  MUST validate the file, check the image tag is pullable, produce
  `catalogue-entry.json` and `bundle.zip`, attest both with GitHub artifact
  attestations, and attach them with the attestation bundle to the release.
- **FR-003**: The gateway MUST store catalogue sources (GitHub `owner/repo`)
  added by administrators, only for allowed owners.
- **FR-004**: The gateway MUST read each source's latest release every 6 hours
  and on demand, download the entry, the bundle and `catalogue.sigstore.json`,
  and accept them only after verification (FR-005).
- **FR-005**: Verification MUST check, for each asset: a valid Sigstore bundle
  over exactly the downloaded bytes, a certificate issued by GitHub Actions
  (`https://token.actions.githubusercontent.com`) for a workflow of that
  source repository running on the release tag, and a transparency-log
  inclusion proof against Sigstore's public trusted root.
- **FR-006**: The gateway MUST refuse an entry whose version is not newer than
  the stored one for that module, whose `module` changes for a repository, or
  whose module name is claimed by another source.
- **FR-007**: `GET /gateway/v1/ops/catalogue` MUST include available modules
  (entry, not known) with state `available`, and for every module with an
  entry: latest version, summary, category, image, and `update_available`
  when a running instance is older than the latest.
- **FR-008**: Administrators MUST be able to list, add, remove and refresh
  sources, upload release assets, and read and replace the allowed owners.
- **FR-009**: Every change and every refused entry MUST be audited.
- **FR-010**: The console Modules page MUST show available modules, update
  notices, and a Sources panel for administrators.

### Security Requirements *(mandatory — Constitution: Development Workflow)*

- **Trust boundaries crossed**: gateway → GitHub API and release downloads
  (internet, untrusted content); gateway → Sigstore trusted root (TUF);
  browser → gateway ops API.
- **Data classification**: public release metadata; no secrets.
- **Authentication/Authorization**: GitHub artifact attestations (keyless,
  workflow identity) for content; platform-tenant administrators for changes;
  operators read.
- **Threat scenarios**: tampered or substituted assets; a compromised or
  impersonating repository; downgrade by replaying an old release; module-name
  takeover; zip path traversal; oversized downloads; SSRF via source URLs;
  GitHub outage used to hide updates.
- **SR-001**: Content MUST NOT be stored or displayed before FR-005 passes.
- **SR-002**: Sources MUST be `owner/repo` names (no URLs); the gateway MUST
  only contact `api.github.com`, `github.com` release download URLs and their
  redirect targets on `*.githubusercontent.com`, with a 30 s timeout.
- **SR-003**: Downloads MUST be size-limited (FR edge cases) and zip entries
  validated (no traversal, no symlinks, no absolute paths, ≤ 200 files).
- **SR-004**: Allowed owners and sources MUST change only through
  administrator requests; each change is audited.
- **SR-005**: Polling MUST run beside routing (never on the request or
  registration path), like the phase 1 recorder.

### Key Entities

- **Module descriptor** (`tangra-module.yaml`): written by the module team.
- **Catalogue entry** (`catalogue-entry.json`): the descriptor plus version,
  permissions and bundle digest, published per release.
- **Catalogue source**: a GitHub repository the gateway reads.
- **Verified entry**: an entry stored after verification, per module and version.
- **Allowed owner**: a GitHub owner whose repositories may be sources.

## Success Criteria *(mandatory)*

- **SC-001**: A pilot module's tagged release carries a verifiable entry
  without manual steps.
- **SC-002**: An added source's module appears on the Modules page within one
  refresh (on-demand refresh: under 30 s).
- **SC-003**: A tampered entry, a foreign repository and a downgrade are each
  refused in tests and never stored.
- **SC-004**: With GitHub unreachable, the Modules page still shows the last
  verified entries.

## Assumptions

- Pilot modules for this feature: sms-gw and asterisk. The remaining module
  repositories adopt the descriptor in follow-up changes (tracked in tasks).
- Sigstore public-good instance is reachable from cores (same as GitHub).
- An optional GitHub token may be configured to raise API limits; none is
  required for public repositories.

## Dependencies

- 034-known-modules (gateway 4.9.0).
- GitHub artifact attestations (`actions/attest-build-provenance`).
- `github.com/sigstore/sigstore-go` (justified in research.md).
