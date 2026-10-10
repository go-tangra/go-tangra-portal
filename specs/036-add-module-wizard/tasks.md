---
description: "Task list for 036 Add-Module Wizard (gateway module catalogue, phase 3)"
---

# Tasks: Add-Module Wizard (phase 3)

**Input**: `specs/036-add-module-wizard/`
**Tests**: MANDATORY, first, seen failing.
**Paths**: gateway unless prefixed `auth:` (go-tangra-auth). Branch
`036-add-module-wizard` (gateway: on top of `035-catalogue-sources`).

## Phase 1: Setup

- [x] T001 Spec, research, plan, contract, tasks
- [x] T002 Branches

## Phase 2: Foundational (auth)

- [x] T003 auth: tests: 24 h accepted, > 24 h refused (InvalidArgument, not shortened), default 10 min unchanged
- [x] T004 auth: `maxEnrollLifetime` 24 h; refuse above; mint RPC maps it to InvalidArgument
- [x] T005 auth: tests for `TokenStatus` (consumed/unconsumed/unknown; non-gateway caller refused by policy)
- [x] T006 auth: proto + generated code + handler + `deploy/policy.yaml` rule

## Phase 3: US1 + US2 - Bundle, token, allow-list (P1)

- [x] T007 [P] tests `internal/catalogue/join_test.go`: inputs validation (missing, extra, pattern, newline/`$`/quotes); render all placeholders; unresolved placeholder fails; generated passwords distinct; TLS material verifies; zip layout and modes; core values equal config
- [x] T008 [P] tests `internal/httpapi/catalogue_join_test.go`: admin gate; 404 no entry; allow-list created / kept / conflict 409; prefix widening refused; ttl bounds; auth down 503 (no allow-list change if before; entry kept if after); audit without token or secrets; no-store
- [x] T009 config `catalogue.join` + tests
- [x] T010 `internal/catalogue/join.go`
- [x] T011 migration 0007 `catalogue_joins` + store
- [x] T012 handler + OpenAPI + wiring

## Phase 4: US3 - Progress (P2)

- [x] T013 tests: progress (token used via fake auth, registered from registry, last refusal from audit), 404 after retention
- [x] T014 progress endpoint
- [x] T015 shell: Add wizard (form from host inputs, ttl, download, live progress polling every 5 s) + tests

## Phase 5: Polish

- [x] T016 vet, race, lint, build; docs/operations.md
- [ ] T017 quickstart on a test host with sms-gw (user)
- [ ] T018 PRs, releases (auth, gateway), prod policy update for TokenStatus, rollout (user confirmation)
