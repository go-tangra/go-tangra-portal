# Feature Specification: Known Modules (gateway module catalogue, phase 1)

**Feature Branch**: `034-known-modules`
**Created**: 2026-10-10
**Status**: Draft
**Input**: Gateway module catalogue design, phase 1 "Remember known modules": a
persistent record per module so an installed-but-down module stays visible with
its last version and last-seen time; administrators mark a module expected or
forget it.

## Context

The gateway's registry keeps registrations in Valkey under leases. When a
module's last instance withdraws or its lease expires, the registration is
deleted (`internal/registry/registry.go`, `withdraw`). An installed module that
is down then looks exactly like one that was never installed: the ops page
simply stops listing it. Operators find out from users ("SMS pages are gone"),
not from the console.

This feature gives the gateway a memory of every module it has seen register.
It is phase 1 of the gateway module catalogue design; phases 2 (per-repository
catalogue entries) and 3 (add-module wizard) are separate features.

Decisions taken on 2026-10-10 that apply here: only administrators of the
platform tenant change the catalogue; operators may read it.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - See modules that are installed but down (Priority: P1) 🎯 MVP

A platform operator opens Gateway operations › Modules and sees every module
the gateway has ever seen register: the ones running now, with their live
state, and the ones that are not registered any more, marked **down** with the
last version they ran and when they were last seen.

**Why this priority**: This is the blind spot that motivated the catalogue. On
its own it turns a silent outage into a visible one.

**Independent Test**: Register a module, stop it, wait for its lease to expire;
the module stays listed as down with its last version and last-seen time, and
the list survives a gateway restart.

**Acceptance Scenarios**:

1. **Given** sms-gw registered running build 4.2.0, **When** its lease expires,
   **Then** Modules lists sms-gw as `down`, last version `4.2.0`, last seen at
   about the time of its last renewal.
2. **Given** sms-gw is down, **When** it registers again, **Then** it is listed
   as running with its live state and instance count, and its first-seen time
   is unchanged.
3. **Given** a module is listed as down, **When** the gateway restarts, **Then**
   it is still listed as down.
4. **Given** a module has been registered for an hour, **When** the operator
   opens Modules, **Then** its last-seen time is no older than 5 minutes.

---

### User Story 2 - Say which modules should be running (Priority: P2)

A platform administrator marks a module as **not expected** (for example a
module switched off on purpose). It is then listed as `stopped` instead of
`down`, so `down` keeps meaning "something is wrong". The administrator can
mark it expected again.

**Why this priority**: Without it, every intentionally stopped module reads as
an outage and operators learn to ignore `down`.

**Independent Test**: Mark a down module not expected; it shows `stopped`;
mark it expected; it shows `down` again. An operator who is not an
administrator cannot change it.

**Acceptance Scenarios**:

1. **Given** asterisk is down, **When** an administrator marks it not expected,
   **Then** it is listed as `stopped` and an audit event records who did it.
2. **Given** asterisk is marked not expected, **When** it registers again,
   **Then** it is listed as running (the mark only changes how a missing
   module is shown).
3. **Given** an operator without the administrator role, **When** they try to
   change the mark, **Then** the request is refused (403) and nothing changes.

---

### User Story 3 - Forget a removed module (Priority: P3)

A platform administrator removes a module that was uninstalled for good, so it
no longer appears in Modules.

**Why this priority**: Housekeeping; useful once modules are retired, not
urgent.

**Independent Test**: Forget a down module; it disappears from Modules; when
that module registers again later it reappears as running.

**Acceptance Scenarios**:

1. **Given** a module that is down, **When** an administrator forgets it,
   **Then** it no longer appears in Modules and an audit event records it.
2. **Given** a module that is running, **When** an administrator tries to
   forget it, **Then** the request is refused (409) with a reason saying it
   is registered.
3. **Given** a forgotten module, **When** it registers again, **Then** it
   reappears as running and expected.

---

### Edge Cases

- Postgres is unreachable when a module registers: registration and routing
  continue unaffected; the record is written when the store is back (the
  periodic refresh catches up).
- Several gateway replicas record the same module at once: the record stays
  consistent (last-seen never moves backwards, last version is never blanked).
- A module reports no build version: the last known version is kept.
- A module is revoked (operator mark) while registered: it is listed with the
  live `revoked` state, not as down.
- The registry event stream overflows: the recorder resynchronises from the
  current registrations instead of missing changes.
- The module name in a request path is not a valid module name: 400, nothing
  touched.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The gateway MUST record a module when it registers or updates
  its registration: module name, SPIFFE identity, display name, manifest hash,
  newest build version, first-seen and last-seen times.
- **FR-002**: While a module is registered, the gateway MUST refresh its
  last-seen time at least every 5 minutes.
- **FR-003**: When a module's registration ends (withdrawal or lease expiry),
  the gateway MUST record that moment as last seen.
- **FR-004**: Recording MUST happen outside the registration and routing
  paths: a slow or failing store MUST NOT delay or fail a registration,
  renewal or routed request.
- **FR-005**: `GET /gateway/v1/ops/catalogue` MUST list every known module not
  forgotten, merged with the live registry: state (`active`, `draining`,
  `unhealthy`, `revoked` when registered; `down` or `stopped` when not),
  instance count, running build versions, last version, first seen, last seen,
  expected.
- **FR-006**: The list MUST also say whether the caller may change the
  catalogue, so the console shows actions only to administrators.
- **FR-007**: Administrators MUST be able to set a known module expected or
  not expected (`PATCH /gateway/v1/ops/catalogue/{module}`).
- **FR-008**: Administrators MUST be able to forget a known module that is not
  registered (`DELETE /gateway/v1/ops/catalogue/{module}`); forgetting a
  registered module MUST be refused with 409.
- **FR-009**: A forgotten module that registers again MUST be known again,
  expected.
- **FR-010**: The console MUST offer a Modules page under Gateway operations
  showing the list, with the expected toggle and Forget action for
  administrators.
- **FR-011**: Changing the expected flag and forgetting MUST each write a
  gateway audit event naming the module and the administrator.

### Security Requirements *(mandatory — Constitution: Development Workflow)*

- **Trust boundaries crossed**: browser → gateway ops API (session cookie,
  CSRF-protected mutations); gateway → its own Postgres.
- **Data classification**: internal-only operational metadata (module names,
  SPIFFE ids, versions, timestamps). No secrets, no PII beyond operator user
  ids in audit events.
- **Authentication/Authorization**: existing gateway session identity. Read:
  platform-tenant members holding an operator role (as the other ops pages).
  Write: platform-tenant members holding an administrator role (`owner` or
  `admin`, configurable).
- **Threat scenarios**: a non-administrator operator changing or erasing the
  record of a module (hiding an outage); forged module names in the path
  (injection, unbounded keys); store errors leaking internals; recorder load
  on Postgres from renewals every 10 s.
- **SR-001**: Mutating catalogue endpoints MUST refuse callers that are not
  administrators of the platform tenant (403) before touching the store.
- **SR-002**: Module names in paths MUST be validated against the manifest
  module-name pattern; invalid names MUST get 400.
- **SR-003**: Mutations MUST require the existing CSRF protection of the ops
  API (double-submit header, enforced by the edge for cookie-bearing calls).
- **SR-004**: Every successful mutation MUST be audited; refused attempts by
  non-administrators MUST be audited as permission refusals.
- **SR-005**: Store errors MUST surface as `temporarily_unavailable` without
  internal detail.
- **SR-006**: The recorder MUST write at most once per module per 5 minutes in
  steady state (renewals do not write).

### Key Entities

- **Known module**: a module the gateway has seen register. Name (key),
  last SPIFFE identity, display name, last version, manifest hash, first seen,
  last seen, expected, forgotten time.
- **Catalogue view row**: a known module merged with its live registration (if
  any) into one displayed state.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A module whose lease expires is shown as `down` within 1 minute
  (lease TTL plus one sweep), with its last version.
- **SC-002**: Registration and renewal latency are unchanged: no Postgres
  access is added to those paths (verified by test with a store that blocks).
- **SC-003**: Known modules and their marks survive a gateway restart.
- **SC-004**: With 20 modules registered, the recorder performs at most
  20 writes per 5 minutes in steady state.

## Assumptions

- "Administrator" means an administrator of the platform tenant (roles
  `owner` or `admin` by default), per the 2026-10-10 decision that only
  administrators manage the catalogue.
- The Modules page becomes the first page of Gateway operations later
  (phase 2); in this feature it is added beside Registrations, which stays.
- Existing modules are recorded the first time each gateway replica starts
  with this feature (from the live registry); history before that is not
  reconstructed.

## Dependencies

- Gateway Postgres (goose migrations, `gateway_app` grants).
- Registry events (`Registry.Watch`) and `Registrations()`.
- Session identity (`identity.Identity.Operator`, roles).
