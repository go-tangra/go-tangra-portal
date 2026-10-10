# Implementation Plan: Known Modules (gateway module catalogue, phase 1)

**Branch**: `034-known-modules` | **Date**: 2026-10-10 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `specs/034-known-modules/spec.md`

## Summary

Give the gateway a persistent record of every module it has seen register, so
a module that is installed but down stays visible. A `known_modules` table in
the gateway's Postgres is written by a separate **recorder** that follows the
registry's event stream and refreshes registered modules every 5 minutes; the
registration and routing paths never touch it. A new ops endpoint merges the
record with the live registry into one state per module, administrators can
mark a module expected or forget it, and the console gets a Modules page.

## Technical Context

**Language/Version**: Go 1.26 (gateway), TypeScript + Vue 3 (shell)
**Primary Dependencies**: existing only: pgx/v5, goose migrations, the
gateway's registry, httpapi (`MustHandle`, OpenAPI validator), `@go-tangra/ui`
**Storage**: gateway Postgres (TimescaleDB instance), new table `known_modules`
**Testing**: `go test -race ./...`; store integration tests behind the
existing Postgres harness (`internal/store/*_integration_test.go`); shell
vitest
**Target Platform**: Linux container (gateway), browser (shell)
**Project Type**: web service + SPA (one repository: `internal/`, `shell/`)
**Performance Goals**: zero added latency on Register/Renew/dispatch;
≤ 1 write per module per 5 min in steady state
**Constraints**: recorder failure must never affect routing; replicas write
concurrently; no new dependencies
**Scale/Scope**: ~20 modules, 1–3 gateway replicas

## Constitution Check

*Evaluated against `go-tangra/.specify/memory/constitution.md` v1.0.0.*

- [x] **I. Secure by Default**: new `operators.admin_roles` defaults to
      `[owner, admin]`; mutations are refused unless the caller is a
      platform-tenant member with one of them. No insecure option is added.
- [x] **II. Zero Trust**: endpoints sit behind the existing session identity
      and the ops role gate before any handler code; mutations reuse the ops
      CSRF check. The recorder adds no network surface.
- [x] **III. Boundary Validation**: request bodies and the `{module}` path
      parameter are declared in `api/openapi/gateway.yaml` (validator runs
      first); handlers re-check the module-name pattern; body size limit is
      the existing ops limit.
- [x] **IV. Test-First**: tasks list tests before implementation for each
      story, including negative authorization tests (operator without admin
      role, other tenant, missing CSRF) and a test proving registration does
      not wait on a blocked store.
- [x] **V. Observability**: two new audit event types
      (`known_module_expected`, `known_module_forgotten`); permission refusals
      use the existing `permission_refused`; recorder failures are logged
      (rate-limited) with no new metrics endpoint.
- [x] **VI. Supply Chain**: no new dependency.
- [x] **VII. Simplicity**: one table, one recorder goroutine, two store
      interfaces; configuration is the typed `operators.admin_roles` list.
- [x] **Threat Model**: STRIDE for the new endpoints and recorder in
      research.md.

## Project Structure

### Documentation (this feature)

```text
specs/034-known-modules/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── ops-catalogue.md
├── checklists/requirements.md
└── tasks.md
```

### Source Code (repository root)

```text
internal/
├── store/
│   ├── migrations/0005_known_modules.sql   # table + gateway_app grants
│   ├── models.go                            # KnownModule
│   ├── repos.go                             # SeeKnown, ListKnown, SetKnownExpected, ForgetKnown
│   └── known_integration_test.go
├── storeadapter/adapter.go                  # Postgres-backed known store
├── memstore/memstore.go                     # in-memory known store (tests)
├── known/                                   # NEW: recorder
│   ├── recorder.go                          # follows Registry.Watch + 5-min refresh
│   └── recorder_test.go
├── audit/audit.go                           # 2 new event types
├── config/config.go                         # operators.admin_roles
├── httpapi/
│   ├── catalogue.go                         # GET/PATCH/DELETE /gateway/v1/ops/catalogue…
│   └── catalogue_test.go
└── app/app.go                               # wire recorder + endpoints
api/openapi/gateway.yaml                     # contract for the 3 operations
shell/
├── src/api/schema.d.ts                      # regenerated from the contract
├── src/views/ops/Modules.vue                # NEW page
├── src/router/index.ts                      # /ops/modules
├── src/layouts/Default.vue                  # nav entry (+ pending icon fix)
└── tests/unit/modules.spec.ts
```

**Structure Decision**: everything lives in go-tangra-portal-v4: the gateway
in `internal/`, the console in `shell/`. The recorder is its own package so the
registry gains no Postgres dependency.

## Complexity Tracking

No constitution violations.
