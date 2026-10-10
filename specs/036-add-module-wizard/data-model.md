# Data Model: Add-Module Wizard (migration 0007)

| Table | Columns | Notes |
|---|---|---|
| `catalogue_joins` | `id` uuid PK, `module`, `version`, `jti` uuid, `minted_by`, `created_at`, `expires_at` | no token, no secrets; rows deleted 24 h after `expires_at` |

Audit: `module_join_bundle` (module, version, admin, jti, expires_at; never
the token or generated secrets).
