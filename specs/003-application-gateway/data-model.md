# Data Model — Application Gateway

Live state (Valkey, TTL-bound, rebuilt from renewals) is separated from durable state
(TimescaleDB). Identifiers are UUIDv7; times are UTC.

## Live state (Valkey)

### Registration `reg:<module>`

| Field | Rules |
|-------|-------|
| module | `^[a-z][a-z0-9-]{1,39}$`, unique |
| identity | SPIFFE ID of the registrant; all instances must share it |
| manifest | validated manifest (below), `version` monotonic per module |
| instances | set of `instance_id` with backend addresses and last renewal |
| state | `active` \| `draining` \| `unhealthy` \| `revoked` (revoked/draining come from durable marks) |
| updated_at | last manifest change |

`lease:<module>:<instance>` — value `renewed_at`, TTL = lease TTL (30 s). Expiry of the
last lease withdraws the registration (`registration_withdrawn`).

### Manifest (validated by `contracts/manifest.schema.json`)

| Field | Rules |
|-------|-------|
| module, display_name, version | name grammar above; version `^[0-9]+\.[0-9]+\.[0-9]+$` |
| prefixes[] | absolute normalised paths, ≤ 8, no overlap with other modules |
| backend | `http_url` (https, private), `grpc_target` (host:port); both served over the Freya channel with the registrant identity |
| routes[] | `{method, path, permission \| public, max_body_bytes?, timeout?}`; path under an owned prefix; ≤ 500 |
| methods[] | `{full_method, permission \| public, streaming, max_stream_duration?}`; ≤ 500 |
| permissions[] | API permissions this module registers in auth (`resource:action`, description) |
| abilities[] | CASL raw rules `{action, subject, fields?, conditions?, inverted?, reason?, requires}` — `requires` is a declared permission; conditions ≤ 4 KiB, operators limited to `$eq $ne $in $nin $lt $lte $gt $gte $exists` |
| remote | `{entry: "/m/<module>/mf-manifest.json", exposes: ["./routes", "./nav"?, "./boot"?], integrity?}` |
| nav[] | `{title, path, icon?, order, requires}` — `requires` a declared permission |

### Caches

| Key | Value | TTL |
|-----|-------|-----|
| `ident:<sha256(cookie)>` | identity + access token + exp | min(60 s, token exp) |
| `dec:<tenant>:<user>:<perm>@<tenant_version>` | allowed/denied | 2 s |
| `health:<module>:<instance>` | consecutive failures, open_until | rolling |
| `rev:*` | mirrored revocation marks from the auth feed | 60 min |

Pub/sub: `gateway:registry` (register/withdraw/mark), `gateway:revoked`.

## Durable state (TimescaleDB, database `gateway`)

### allow_list

| id | spiffe_id (unique) | prefixes text[] | names text[] | created_by | created_at | revoked_at |

A registration is accepted only if the peer identity matches a row and every requested
prefix/name is within the row's lists.

### module_marks

| module | mark (`draining` \| `revoked`) | reason | set_by | set_at | cleared_at |

### gateway_audit_events (hypertable, 400 d retention)

| ts | event_type | module | actor_kind (`service` \| `operator` \| `user` \| `system`) | actor_id | tenant_id? | subject_kind | subject_id | outcome | reason | correlation_id | details jsonb |

Closed vocabulary: `registration_accepted`, `registration_refused`,
`registration_updated`, `registration_withdrawn`, `renewal_refused`, `module_drained`,
`module_revoked`, `module_unhealthy`, `module_recovered`, `allowlist_changed`,
`identity_refused`, `permission_refused`, `stream_terminated`, `limit_exceeded`.

## Route table (in memory, immutable snapshot)

Radix tree over prefixes → module; per module: method/path matcher for HTTP routes,
map of full gRPC methods; each leaf carries `permission | public`, limits and timeouts.
Snapshots are swapped atomically on registry events; a request always sees one snapshot.

## Identity and decisions

- **Identity**: `{user_id, tenant_id, session_id?, roles[], amr[], token, token_exp, source: session|bearer}`.
- **Decision**: `{allowed, reason, policy_version}` from `auth.v1.Authorization`.
- **Abilities response**: `{tenant, user, roles, modules: {<module>: packed CASL rules}, version}`.

## State transitions

Registration: `— → active` (Register accepted) → `draining` (operator) → `revoked`
(operator; renewals refused) ; `active → unhealthy` (probe failures) → `active`
(recovery); any → withdrawn (last lease expired or Deregister).
