# Research: Known Modules

## R1. Where to write the record

**Decision**: a separate recorder (`internal/known`) follows `Registry.Watch`
events and periodically lists `Registry.Registrations()`; it upserts into
Postgres from its own goroutine.

**Rationale**: the registry's Register/Renew/withdraw paths stay free of
Postgres (FR-004, SC-002). The event stream already exists for the shell SSE
feed and gRPC watchers.

**Alternatives**: writing inside `Register`/`withdraw` (adds Postgres latency
and a failure mode to registration; rejected); using `Options.OnAccepted`
(called on the registration path, and has no withdrawal hook; rejected).

## R2. Last-seen while registered

**Decision**: the recorder refreshes every registered module every 5 minutes,
and on `registered`/`updated`/`withdrawn` events. Renewals (every 10 s) are
not recorded.

**Rationale**: meets FR-002 with ≤ 1 write per module per 5 minutes
(SR-006, SC-004). A module that dies shows `down` as soon as its registration
leaves the live registry (lease TTL 30 s + sweep), independent of the write
interval, because the down state is computed from the live registry.

## R3. Several gateway replicas

**Decision**: every replica records; the upsert is idempotent: last-seen uses
`GREATEST`, an empty version never overwrites a known one, first-seen is only
set on insert.

**Rationale**: no coordination needed; replicas converge.

## R4. Event stream overflow

**Decision**: `Watch` closes the channel on overflow; the recorder re-subscribes
from the registry's current version and performs a full refresh.

## R5. Who may change the catalogue

**Decision**: new `operators.admin_roles` (default `[owner, admin]`); a caller
must be a platform-tenant member (`identity.Operator`) holding one of them.
Reading requires the existing operator roles **or** an administrator role.

**Rationale**: 2026-10-10 decision: only administrators of the platform
tenant manage the catalogue. Prod's administrator holds `owner`, `admin` and
`operator`.

## R6. Forgetting a registered module

**Decision**: refuse with 409 `conflict` (`module is registered`).

**Rationale**: a forget of a live module would be undone by the next refresh
and only confuses; operators drain/revoke a live module first.

## R7. Module name validation

**Decision**: `^[a-z0-9][a-z0-9-]{0,62}$` in the OpenAPI path parameter and in
the handler.

**Rationale**: the manifest has no explicit name pattern today; every module
name in use (`sms-gw`, `asterisk`, `hr`, …) fits a DNS label, which is also
what SPIFFE paths use.

## STRIDE threat model (new endpoints and recorder)

| Threat | Scenario | Mitigation |
|---|---|---|
| Spoofing | Caller without a session or from another tenant | Existing identity resolution; `identity.Operator` required |
| Tampering | Operator (not admin) marks a down module not expected to hide an outage | SR-001 admin roles; 403 audited as `permission_refused` |
| Tampering | Cross-site request changes a mark | Ops CSRF header required on PATCH/DELETE (SR-003) |
| Repudiation | Admin denies forgetting a module | Audit events with actor id and tenant (SR-004) |
| Information disclosure | Store errors leak SQL detail | Generic `temporarily_unavailable` (SR-005) |
| Denial of service | Recorder floods Postgres on every renewal | Renewals not recorded; 5-minute refresh (SR-006) |
| Denial of service | Postgres down blocks registrations | Recorder off the registration path (FR-004), test with blocking store |
| Elevation of privilege | Invalid `{module}` used for injection | OpenAPI pattern + handler check; parameterised SQL |
