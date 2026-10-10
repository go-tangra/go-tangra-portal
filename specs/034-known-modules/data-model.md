# Data Model: Known Modules

## Table `known_modules` (migration 0005)

| Column | Type | Notes |
|---|---|---|
| `module` | text, PK | manifest module name |
| `identity` | text | last SPIFFE id that registered it |
| `display_name` | text | from the manifest |
| `last_version` | text | newest instance build version seen; never blanked by a report without one |
| `manifest_hash` | text | last accepted manifest hash |
| `first_seen_at` | timestamptz | set on insert only |
| `last_seen_at` | timestamptz | `GREATEST` of writes; never moves backwards |
| `expected` | boolean, default true | administrators: should be running |
| `forgotten_at` | timestamptz, null | set by forget; cleared when the module registers again |

Grants: `SELECT, INSERT, UPDATE` to `gateway_app` (no DELETE: forgetting is a
soft delete, kept for audit).

## Displayed state (catalogue view row)

| Live registration | `expected` | State |
|---|---|---|
| present | any | registry state: `active`, `draining`, `unhealthy` or `revoked` |
| absent | true | `down` |
| absent | false | `stopped` |

## Store operations

- `SeeKnown(module, identity, display_name, last_version, manifest_hash, seen_at)`: upsert per R3; clears `forgotten_at`.
- `ListKnown()`: rows with `forgotten_at IS NULL`, by module.
- `SetKnownExpected(module, expected)`: `ErrNotFound` when unknown or forgotten.
- `ForgetKnown(module)`: sets `forgotten_at`; `ErrNotFound` when unknown or forgotten.

## Audit events

| Type | Actor | Subject | Details |
|---|---|---|---|
| `known_module_expected` | operator (admin user id, tenant) | module | `{expected: bool}` |
| `known_module_forgotten` | operator (admin user id, tenant) | module | `{}` |
