# Data Model: KVM Console on a Separate Origin

No database changes. Configuration and in-memory state only.

## Framework — `edge.Config`

| Field | YAML (gateway) | Type | Default | Rules |
|---|---|---|---|---|
| `FrameSources` | `edge.frame_sources` | `[]string` | empty | each an https origin (`https://host[:port]`), no path/query/fragment/user info, no `;` `,` `'` or whitespace; empty ⇒ CSP unchanged |

## Gateway — `console` section

| Key | Type | Default | Rules |
|---|---|---|---|
| `enabled` | bool | `false` | off ⇒ nothing below is used, 8444 not bound |
| `addr` | string | `:8444` | listen address |
| `public_origin` | string | — (required when enabled) | https origin, ≠ `public_origin`, not in `edge.allowed_origins` |
| `routes` | map prefix → module | `{"/bmc/": "ipam"}` | prefix starts and ends with `/`, not `/`, chars `[a-z0-9/_-]`; not under `/api/`, `/gateway/`, `/m/`; module non-empty `[a-z0-9-]` |
| `cookies` | []string | `["freya_kvm"]` | valid cookie names; never `__Host-*`/`__Secure-*` |
| `session_max` | duration | `1h` | 1m … 24h — WebSocket lifetime |
| `max_concurrent` | int | `64` | 1 … 10000 in-flight requests |

Requires `edge.cert_file` and `edge.key_file` (same certificate, reloaded
every minute). When enabled, `public_origin` of the console is appended to
the edge frame sources.

## IPAM — `kvm` section

| Key | Type | Default | Rules |
|---|---|---|---|
| `token_ttl_seconds` | int | 60 | 5 … 3600 — start token lifetime (existing) |
| `session_seconds` | int | 3600 | 60 … 86400 — console session lifetime (existing, now used) |
| `console_origin` | string | empty | empty or https origin (no path/query/fragment/user info) |

## IPAM in-memory state (`internal/kvm.Manager`)

- **start token** `tokens[token] = {deviceID, host, creds, expires}` —
  single-use; deleted on first use or expiry.
- **console session** `consoles[id] = {deviceID, host, creds, expires}` —
  created from a token; `id` is 32 random bytes hex; cookie
  `freya_kvm=<id>; Path=/bmc/<device>/; Secure; HttpOnly; SameSite=Strict`.
- **BMC session cache** `sessions[host+user] = {SID cookie, expires}` —
  unchanged.
