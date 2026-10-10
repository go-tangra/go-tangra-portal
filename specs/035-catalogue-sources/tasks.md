---
description: "Task list for 035 Catalogue Sources (gateway module catalogue, phase 2)"
---

# Tasks: Catalogue Sources (phase 2)

**Input**: `specs/035-catalogue-sources/`
**Tests**: MANDATORY (Constitution IV): tests first, seen failing.
**Paths**: gateway (go-tangra-portal-v4) unless prefixed `fw:` (go-tangra),
`sms:` (go-tangra-sms-gw-v4), `ast:` (go-tangra-asterisk-v4). Each repo works
on branch `035-catalogue-sources`.
**Release tasks** need explicit user confirmation.

## Phase 1: Setup

- [x] T001 Spec, research, contracts, data model, plan, tasks
- [x] T002 Branches in fw, sms, ast

## Phase 2: Foundational

- [x] T003 [P] fw: tests `catalogue/catalogue_test.go`: strict descriptor parse (unknown/missing fields, bad names, prefix scope, host-input patterns compile), entry build, deterministic bundle zip, version compare, zip validation (traversal, symlink, absolute, count, size)
- [x] T004 fw: `catalogue/` package: `Descriptor`, `Entry`, `ParseDescriptor`, `BuildEntry`, `PackBundle`, `ValidateBundle`, `NewerVersion`
- [x] T005 fw: `cmd/tangra-catalogue` (`validate`, `build --version --repository --permissions-from <cmd>`), tests
- [x] T006 fw: composite action `.github/actions/catalogue-entry/action.yml`: build, check image (`docker manifest inspect`), `actions/attest-build-provenance@v2` for both assets, upload assets + `.sigstore.json` bundles to the release
- [x] T007 gateway migration 0006 + store repos + adapter + memstore; tests (memstore parity; integration test written, not yet run: needs Docker)
- [x] T008 gateway config `catalogue: { poll: 6h, allowed_owners: [go-tangra], github_api, github_token_env }` + validation tests

## Phase 3: US1 - Releases publish entries (P1)

- [x] T009 [US1] sms: `tangra-module.yaml`, `deploy/bundle/` (compose.yaml, config.yaml templates, README), `smsgwsvc catalogue-permissions` subcommand + test, release job calling the action
- [x] T010 [US1] ast: same for asterisk (`asterisksvc catalogue-permissions`)
- [ ] T011 [US1] fw: release v4.7.0 with `catalogue` + action (user confirmation)

## Phase 4: US2 - Sources and verification (P1)

- [x] T012 [P] [US2] gateway tests `internal/catalogue/verify_test.go` (virtual Sigstore): valid; tampered bytes; other repository; other tag; non-GitHub issuer; no tlog entry
- [x] T013 [P] [US2] gateway tests `internal/catalogue/poller_test.go` (fake GitHub): stores verified entry+bundle; no catalogue assets; module change refused; name takeover refused; downgrade refused; oversize refused; GitHub down keeps entries; poller not on request path
- [x] T014 [P] [US2] gateway tests `catalogue_test.go`: sources CRUD, owners, admin gate, audit, validation
- [x] T015 [US2] `internal/catalogue/verify.go` (sigstore-go, policy R2, live trusted root R3)
- [x] T016 [US2] `internal/catalogue/poller.go` (GitHub client: latest release, assets, limits, fixed hosts) and service `Refresh/RefreshAll/Run`
- [x] T017 [US2] handlers + OpenAPI (+ spec 003 copy) + app wiring

## Phase 5: US3 - Update available (P2)

- [x] T018 [US3] tests: view merge (`available`, `update_available`, `latest_version`, `installable`)
- [x] T019 [US3] view merge implementation
- [x] T020 [US3] shell: available rows, update badge, Sources panel; tests

## Phase 6: US4/US5 - Upload and allowed owners (P3)

- [x] T021 [US4] upload tests + handler (multipart, same verification)
- [x] T022 [US5] owners endpoint tests + handler; shell owners editor

## Phase 7: Polish

- [x] T023 go vet, race tests, shell lint/test/build; docs/operations.md (govulncheck still to run)
- [ ] T024 Remaining module repositories adopt `tangra-module.yaml` (follow-up, one PR each): auth, lcm, portal (gateway is core: no entry), warden, notification, scheduler, inventory, ipam, dns, deployer, asset, paperless, ticket, signing, hr
- [ ] T025 PRs, releases, prod rollout (user confirmation)
