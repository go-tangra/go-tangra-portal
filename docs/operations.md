# Operations — application gateway

## Bootstrap

1. Start the dependencies (`deploy/compose.yaml`: TimescaleDB with the
   `gateway` database and `gateway_app` role, Valkey, OpenFGA, Mailpit) and
   the auth module in gateway mode (`services/auth/deploy/gateway-mode.yaml`).
2. Seed the allow-list; a module cannot register before its SPIFFE identity is
   allowed for its prefixes and module names:

   ```bash
   gatewaysvc bootstrap -config deploy/dev.yaml \
     -allow "spiffe://example.org/svc/auth=/api/v1,/authorize,/.well-known,/console;auth" \
     -allow "spiffe://example.org/svc/hello=/api/hello;hello"
   ```

   Migrations run first; existing entries are skipped; every addition is audited
   (`allowlist_changed`).
3. Run `gatewaysvc -config deploy/dev.yaml`. The public edge listens on
   `edge.addr`; the registry on `server.grpc_addr` (Freya channel only).
4. Operators are members of the platform tenant holding one of
   `operators.roles` (default `operator`); the auth bootstrap invitation grants it.

## Allow-list

- Managed at **Operations → Allow-list** or `POST /gateway/v1/ops/allowlist`
  (`{spiffe_id, prefixes[], names[]}`); revoke with
  `POST /gateway/v1/ops/allowlist/{id}/revoke`.
- One active entry per identity; prefixes are normalised; a registration is
  accepted only when every requested prefix is equal to or under a granted
  prefix and the module name is granted.
- Revoking an entry does not stop running instances; their next registration
  (restart or version bump) is refused with `identity_not_allowed`.

## Drain, undrain, revoke

| Action | Effect | Audit |
|--------|--------|-------|
| Drain | New requests to the module answer `temporarily_unavailable`; in-flight requests complete; renewals are refused so instances withdraw within the lease TTL (30 s) | `module_drained` |
| Undrain | Clears the mark; instances re-register within their backoff (≤ 30 s) | `module_recovered` (reason `undrained`) |
| Revoke | Durable: routes and remote disappear immediately, renewals and new registrations are refused until an operator clears the mark in the database (`module_marks.cleared_at`) | `module_revoked` with the reason (≥ 10 characters) |

Every action carries the operator's user id in the audit trail
(`GET /gateway/v1/ops/audit`, filters `module`, `event_type`, `from`, `to`,
`cursor`).

## Health

- Each instance is probed every 5 s over the channel (HTTP HEAD on its Freya
  HTTP server or a TLS handshake for gRPC-only backends); three consecutive
  failures mark it unhealthy (`module_unhealthy` when the last instance
  fails), a 10 s cool-down precedes the next probe, one success recovers
  (`module_recovered`). Forwarding failures count as observations too.
- Traffic in the operations view is per gateway instance over the last minute
  (requests, refusals, p95 latency).

## Valkey

The gateway's Valkey user needs key and channel access (`~* &*`): registry
changes are published on `gateway:registry`, and the auth service publishes
revocations the same way (an ACL without `&*` makes sign-out fail).

## Valkey loss

Registrations, leases and caches live in Valkey. If it becomes unreachable:

- the in-memory route table keeps serving the last known snapshot;
- new registrations and renewals fail with `registry_unavailable` (modules
  keep retrying); after the lease TTL nothing is withdrawn because sweeps see
  no keys — the gateway keeps routing to the last known instances;
- identity and decision caches miss, so every request costs one auth call;
  the gateway never fails open.

Restore Valkey and the instances refresh their leases on the next renewal.

## Rotation

- **Gateway identity**: the Freya identity provider renews the SVID; forwarders
  are rebuilt on rotation (client connections are re-dialled).
- **Module identity**: the registrant identity is fixed per module; a renamed
  service identity needs a new allow-list entry and a re-registration.
- **Auth signing keys**: verified through the auth module's key feed; no
  gateway restart is needed.
- **Edge certificate**: `edge.cert_file`/`edge.key_file` are re-read every
  minute and swapped without restart.

## Audit retention

`gateway_audit_events` is a TimescaleDB hypertable with a 400-day retention
policy; the application role can only insert and read it.
