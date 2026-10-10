---
description: "Task list for 034 Known Modules (gateway module catalogue, phase 1)"
---

# Tasks: Known Modules (gateway module catalogue, phase 1)

**Input**: Design documents from `specs/034-known-modules/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: MANDATORY (Constitution IV). In every story the tests are listed
first and must be written and seen failing before the implementation tasks.
Negative security tests are listed explicitly.

**Paths**: relative to go-tangra-portal-v4.

**Release tasks** (PR merge, tag, production rollout) require explicit user
confirmation and are left open.

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup

- [x] T001 Create branch `034-known-modules` and `specs/034-known-modules/` (spec, plan, research, data model, contract, quickstart)

---

## Phase 2: Foundational (blocks every story)

- [x] T002 Migration `internal/store/migrations/0005_known_modules.sql`: table + `gateway_app` grants (data-model.md)
- [x] T003 `store.KnownModule` in `internal/store/models.go`; `SeeKnown`, `ListKnown`, `SetKnownExpected`, `ForgetKnown` in `internal/store/repos.go`
- [x] T004 [P] Adapter methods in `internal/storeadapter/adapter.go`
- [x] T005 [P] In-memory equivalents in `internal/memstore/memstore.go`
- [ ] T006 Store integration test (written; not yet run: needs Docker for testcontainers, unavailable on the dev host and not run in CI) `internal/store/known_integration_test.go`: insert sets first/last seen; repeat keeps first-seen; last-seen never moves backwards; empty version keeps the known one; forget hides, re-see un-forgets; expected/forget on unknown → `ErrNotFound`
- [x] T007 [P] memstore parity test in `internal/memstore/memstore_test.go` (same cases as T006)
- [x] T008 Audit event types `known_module_expected`, `known_module_forgotten` in `internal/audit/audit.go` (+ OpenAPI audit enum if listed)
- [x] T009 Config `operators.admin_roles` (default `[owner, admin]`, must not be empty) in `internal/config/config.go` + test in `config_test.go`

**Checkpoint**: storage, audit vocabulary and config ready.

---

## Phase 3: User Story 1 - See modules that are installed but down (P1) 🎯 MVP

**Goal**: every module ever registered stays listed; missing ones show `down`.

**Independent Test**: register, stop, wait for lease expiry → listed `down`
with last version; survives restart.

### Tests for User Story 1 (write first, see them fail) ⚠️

- [x] T010 [P] [US1] Recorder tests in `internal/known/recorder_test.go`: startup records current registrations; `registered`/`updated` event records; `withdrawn` records last seen; refresh writes each registered module once per interval and nothing between (SR-006); newest build version wins; store errors are retried on the next refresh and logged once; watch overflow triggers resync
- [x] T011 [P] [US1] Isolation test in `internal/known/recorder_test.go`: with a store that blocks forever, `Registry.Register`/`Renew` complete within 100 ms (FR-004, SC-002)
- [x] T012 [P] [US1] Handler tests in `internal/httpapi/catalogue_test.go`: GET merges live + known (active/draining/unhealthy/revoked/down/stopped); registered-but-unrecorded module listed; sorted by module; `can_manage` true for admin, false for operator; 401 anonymous; 403 for a non-platform-tenant user and for a member with neither operator nor admin role
- [x] T013 [P] [US1] Contract test: the three operations are declared in `api/openapi/gateway.yaml` with the module pattern (existing route/contract parity test picks them up)

### Implementation for User Story 1

- [x] T014 [US1] `internal/known/recorder.go`: `Recorder{Reg, Store, Interval=5m, Now, Logger}`; `Run(ctx)` = initial refresh, follow `Watch`, ticker refresh, resubscribe on overflow
- [x] T015 [US1] `internal/httpapi/catalogue.go`: `CatalogueDeps`, `GET /gateway/v1/ops/catalogue`, reader gate (operator or admin roles)
- [x] T016 [US1] OpenAPI: add the three operations to `api/openapi/gateway.yaml`
- [x] T017 [US1] Wire recorder and endpoints in `internal/app/app.go` (store adapter as known store; recorder goroutine bound to app lifetime)
- [x] T018 [P] [US1] Shell: regenerate `shell/src/api/schema.d.ts`; `shell/src/views/ops/Modules.vue` (table: module, state chip, version, instances, first/last seen); route `/ops/modules`; nav entry in `shell/src/layouts/Default.vue` (carries the pending ops menu icon fix)
- [x] T019 [P] [US1] Shell unit test `shell/tests/unit/modules.spec.ts`: renders states, hides admin actions when `can_manage` is false; icon test stays green

**Checkpoint**: US1 deliverable on its own (read-only Modules page).

---

## Phase 4: User Story 2 - Say which modules should be running (P2)

### Tests for User Story 2 (write first) ⚠️

- [x] T020 [P] [US2] `catalogue_test.go`: PATCH by admin → 204, row `stopped`, audit `known_module_expected`; PATCH by operator without admin role → 403 + `permission_refused` audit, store untouched (CSRF is enforced by the edge, covered by its own tests); bad module name → 400; bad body (extra field, non-boolean) → 400; unknown module → 404; store error → 503 without detail
- [x] T021 [P] [US2] Shell test: toggle shown to admins, calls PATCH, refreshes row

### Implementation for User Story 2

- [x] T022 [US2] PATCH handler + admin gate in `internal/httpapi/catalogue.go`
- [x] T023 [US2] Expected switch in `Modules.vue`

---

## Phase 5: User Story 3 - Forget a removed module (P3)

### Tests for User Story 3 (write first) ⚠️

- [x] T024 [P] [US3] `catalogue_test.go`: DELETE by admin on a down module → 204, gone from GET, audit `known_module_forgotten`; on a registered module → 409; by operator → 403; unknown → 404; re-registration after forget → listed again (recorder + memstore)
- [x] T025 [P] [US3] Shell test: Forget asks for confirmation, hidden for registered modules

### Implementation for User Story 3

- [x] T026 [US3] DELETE handler in `internal/httpapi/catalogue.go`
- [x] T027 [US3] Forget action with confirmation in `Modules.vue`

---

## Phase 6: Polish & Cross-Cutting

- [x] T028 `go vet ./...`, `go test -race ./...`, shell `npm run lint`, `npm test`, `npm run build`
- [x] T029 [P] Docs: ops section of `README.md` / `docs/` mentions Modules page and `operators.admin_roles`
- [ ] T030 Run quickstart.md against the local stack
- [ ] T031 Commit, push, open PR (on user request)
- [ ] T032 Release + production rollout (explicit user confirmation)

## Dependencies & Execution Order

- Phase 2 blocks all stories. US1 → US2 → US3 build on the same handler file
  and page; their tests can be written in parallel.
- [P] tasks touch different files.
