# Data Model: Catalogue Sources (migration 0006)

| Table | Columns | Notes |
|---|---|---|
| `catalogue_allowed_owners` | `owner` PK, `added_by`, `added_at` | seeded from `catalogue.allowed_owners` when empty |
| `catalogue_sources` | `repo` PK (`owner/repo`), `added_by`, `added_at`, `module` (null until first entry), `last_checked_at`, `last_error` | `module` binds the repository to one module name |
| `catalogue_entries` | (`module`, `version`) PK, `repo`, `entry` jsonb, `entry_sha256`, `bundle` bytea, `bundle_sha256`, `attested_by` (certificate SAN), `verified_at` | newest version per module is current |

Unique: `catalogue_sources.module` (one source per module).

Grants to `gateway_app`: SELECT, INSERT, UPDATE, DELETE on the three tables
(sources and owners can be removed; entries are kept).

## View additions (`GET /gateway/v1/ops/catalogue`)

Per item: `latest_version`, `summary`, `category`, `image`, `repository`,
`update_available` (bool), `installable` (entry with bundle). State
`available` = entry, not known and not registered.

Top level (administrators): `sources[]` (repo, module, last_checked_at,
last_error), `allowed_owners[]`.

## Audit events

`catalogue_source_added`, `catalogue_source_removed`, `allowed_owners_changed`,
`catalogue_entry_verified`, `catalogue_entry_refused` (reason).
