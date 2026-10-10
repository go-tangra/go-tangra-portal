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

## Mesh enrollment (`enroll`)

With `enroll.enabled` the gateway obtains its SVID from lcm at start. It
cannot enroll through its own edge, so it calls lcm's keyless enroll listener
directly (`enroll_url: https://lcm:9947/api/lcm/v1/enroll`), which presents
lcm's own SVID: a URI SAN `spiffe://<trust_domain>/svc/lcm`, no DNS name,
issued by the mesh root. Verify it with the mesh trust bundle:

```yaml
enroll:
  enabled: true
  enroll_url: https://lcm:9947/api/lcm/v1/enroll
  lcm_grpc: lcm:9945
  token_file: /tokens/gateway.token
  state_file: /state/svid.json
  ca_file: /certs/ca.pem          # mesh root bundle (lcm bootstrap output)
  # server_spiffe_id: spiffe://<trust_domain>/svc/lcm   (default)
```

`ca_file` unset means public verification (system roots + host name), which
lcm's SVID can never pass. `insecure: true` skips verification of this first
call (renewals are always verified); it is a development-only setting, warned
at start and refused when `env: production`. `insecure` and `ca_file` are
mutually exclusive.

## Console listener (`console`, feature 025)

BMC KVM consoles (ipam `/bmc/`) run the BMC vendor's JavaScript, so they are
served on an origin of their own — a second TLS port — and never on the
portal origin:

```yaml
edge:
  cert_file: /edge/tls.crt   # required: the console reuses this certificate
  key_file: /edge/tls.key
  # frame_sources: []        # other origins the shell may frame (optional)
console:
  enabled: true
  addr: 0.0.0.0:8444
  public_origin: https://portal.example.com:8444
  routes: { "/bmc/": ipam }  # default
  # cookies: [freya_kvm]     # default: the only cookie forwarded/relayed
  # session_max: 1h          # WebSocket lifetime (1m..24h)
  # max_concurrent: 64       # in-flight requests
```

- The listener serves only the configured prefixes and forwards them (HTTP
  and WebSocket) to the module over the mesh; everything else is 404. It
  authenticates nobody: ipam's single-use console token gates access.
- `public_origin` must differ from the portal's `public_origin` and must not
  be listed in `edge.allowed_origins`; the gateway refuses to start otherwise.
- The console origin is added to the shell's `frame-src`; console responses
  may be framed only by the portal (`frame-ancestors <public_origin>`).
- Set ipam's `kvm.console_origin` to the same origin.
- Publish the port and open it in the firewall for administrators. A
  distinct host name (`https://kvm.example.com`, with a certificate naming
  it) instead of a port isolates cookies completely (see the security model).

## Modules (known modules, feature 034)

- **Operations → Modules** (`GET /gateway/v1/ops/catalogue`) lists every
  module the gateway has seen register, running or not. A module whose last
  instance left is shown `down` (or `stopped` when marked not expected) with
  its last version and when it was last seen; the registry itself forgets it.
- The record lives in Postgres (`known_modules`) and is written by a recorder
  that follows registry events and refreshes registered modules every
  5 minutes. Registration and routing never wait for it; with Postgres down
  the page lists only what is registered now (`partial`).
- Changing the list needs an administrator of the platform tenant
  (`operators.admin_roles`, default `[owner, admin]`); operators only read it:
  - **Expected** (`PATCH /gateway/v1/ops/catalogue/{module}` `{"expected":false}`):
    a module switched off on purpose shows `stopped` instead of `down`.
    Audited `known_module_expected`.
  - **Forget** (`DELETE /gateway/v1/ops/catalogue/{module}`): removes a module
    that is not registered (409 while it is). It reappears if it registers
    again. Audited `known_module_forgotten`.
- Refusals of non-administrators are audited `permission_refused`.

## Catalogue sources (feature 035)

- Module repositories describe themselves in `tangra-module.yaml` and publish
  `catalogue-entry.json`, `bundle.zip` and `catalogue.sigstore.json` with every
  `v*` release (`go-tangra/go-tangra/.github/actions/catalogue-entry`).
- Administrators add sources at **Operations → Modules → Sources**
  (`POST /gateway/v1/ops/catalogue/sources` `{"repo":"owner/repo"}`); only
  repositories of allowed owners (`catalogue.allowed_owners`, default
  `[go-tangra]`, then `PUT /gateway/v1/ops/catalogue/allowed-owners`).
- The gateway reads each source's latest release every `catalogue.poll`
  (default 6h) and on **Read now**. An entry is stored only when its GitHub
  artifact attestation verifies (Sigstore public-good: built by that
  repository's workflow on the release tag); tampered, foreign, downgraded
  or renamed releases are refused and shown on the source
  (`catalogue_entry_refused`). GitHub or Sigstore being unreachable keeps the
  stored entries. Cores without GitHub access upload the three assets
  (`POST /gateway/v1/ops/catalogue/upload`).
- Modules shows `available` modules (entry, never installed) and
  `update <version>` when an instance runs an older release.

## Adding a module (feature 036)

- Needs `catalogue.join` in the gateway configuration: the mesh addresses a
  module host reaches (`auth_grpc`, `gateway_grpc`, `lcm_grpc`), optionally
  `enroll_url` (default `<public_origin>/api/lcm/v1/enroll`), `mesh_tenant_id`
  and `mesh_ca_file` (only for a file identity; otherwise the gateway's own
  trust bundle is used).
- **Modules → Add** (administrators): fill in the inputs the module
  declares and download `<module>-join.zip`. The gateway ensures the
  allow-list entry for `spiffe://<td>/svc/<module>` (an existing different
  entry is a 409 to resolve on the Allow-list page), mints a single-use join
  token (1-24 h; auth refuses longer) and renders every core value
  (issuer, trust domain, addresses, mesh CA) into the bundle. Generated store
  passwords and the bundle's local TLS keys are in the zip and nowhere else.
- On the module host: `unzip`, `cd <module>`, `docker compose up -d`. The
  wizard follows the install (token used, registered, active) and shows the
  last registration refusal. Audit: `module_join_bundle` (never the token).

### Delivering through the inventory agent (feature 037)

- Needs `catalogue.join` plus `catalogue.agent_delivery.inventory_service`
  (the inventory's mesh service name, usually `inventory`), the gateway
  policy rule `inventory-module-bundle` (inventory → gateway
  `inventory.v1.ModuleBundleSource/RenderModuleBundle`), and on the
  inventory `module_delivery.enabled: true` with `gateway` in
  `module_delivery.sources`.
- **Modules → Add → Deliver to a host**: pick a host of your tenant whose
  agent supports module delivery (the picker shows why other hosts are not
  eligible), check the inputs (pre-filled from the host's reported name and
  addresses) and deliver. Nothing secret exists yet: when the agent fetches
  its item, the inventory asks the gateway, which then mints the token
  (valid until the delivery expires) and renders the bundle; at most five
  renders per delivery. Audit: `module_join_bundle` with `channel: agent`,
  then `module_bundle_rendered` (join, item, jti; never the token).
- The agent writes the bundle to `<modules.directory>/<module>/` (default
  `/opt/tangra/modules`), never over an existing directory
  (`already_installed`), and runs only its locally configured
  `modules.deploy_hook` (for example `docker compose up -d`). Without a hook,
  start the module on the host by hand. The wizard shows the delivery state
  (pending, delivered, fetched, installed, failed, hook failed), then token
  used and registered as for a download.

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
`cursor`). Without `from` the page view covers the last 7 days (the legacy
`cursor`/`limit` view the last 24 hours); `to - from` may not exceed 90 days
— a wider range is refused with `400 validation_failed`, `detail.param:
"from"`. Query older periods in 90-day slices.

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
