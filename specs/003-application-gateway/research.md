# Research — Application Gateway

## 1. Public ingress: one listener, three client kinds

- **Decision**: reuse `transport/edge` (TLS 1.3, `h2` + `http/1.1`, security headers,
  CSRF, rate limits, body limits) as the only public listener. Dispatch by request:
  `content-type: application/grpc*` → gRPC passthrough (grpc-go `Server.ServeHTTP` on the
  edge's HTTP/2 connection with `UnknownServiceHandler`), `application/grpc-web*` →
  gRPC-web bridge, everything else → HTTP reverse proxy or shell.
- **Rationale**: one origin satisfies FR-001/FR-014 and keeps the browser protections
  the constitution already certifies; grpc-go's `http.Handler` mode is supported for
  HTTP/2-over-TLS, which is exactly the public case.
- **Alternatives**: separate gRPC port (second public surface, breaks "one origin");
  Envoy sidecar (outside the Freya identity/policy model, second component to harden).

## 2. Registration protocol and leases

- **Decision**: `gateway.v1.Registry` gRPC over the Freya channel: `Register(manifest)
  → lease{id, ttl}`, `Renew(lease_id) → lease`, `Deregister`, `Watch` (server stream of
  registry changes, used by other gateway instances and the operations UI). Lease TTL
  30 s, renew every 10 s, missed renewals audited after the second. Registrant identity =
  the SPIFFE peer identity of the call; the allow-list maps identities to permitted
  prefixes/names. Several instances with identical manifests form one module with several
  backends; a differing manifest is refused until the previous instances are gone (or the
  new version bumps `manifest.version`, which replaces atomically once all instances agree).
- **Rationale**: leases give SC-005 without operator action; identity from the channel
  gives SR-001 for free; `Watch` avoids polling Valkey from every instance.
- **Alternatives**: static configuration (defeats "no gateway change per module");
  Kubernetes-native discovery (couples to one platform; modules may run anywhere).

## 3. Registry state

- **Decision**: Valkey holds registrations (`reg:<module>` hash + `lease:<instance>` key
  with TTL), health state and the decision/identity caches; a pub/sub channel
  (`gateway:registry`) fans out changes; each instance keeps an immutable in-memory route
  table swapped atomically on change. TimescaleDB holds the allow-list, drain/revoke marks
  and the audit hypertable. Loss of Valkey degrades to the last route table in memory
  (read-only) and refuses protected routes once the decision cache TTL passes (fail closed).
- **Rationale**: TTL semantics and fan-out are native to Valkey; durability and retention
  belong to TimescaleDB; both are already platform dependencies.
- **Alternatives**: in-memory only (single instance; no HA); Postgres for leases (write
  churn); etcd (new dependency, new operational surface).

## 4. Route matching and manifests

- **Decision**: manifests are validated by an embedded JSON Schema (`contracts/
  manifest.schema.json`) plus semantic checks in `internal/manifest`: prefixes are
  normalised absolute paths without wildcards; routes are `METHOD /pattern` with `{param}`
  segments only; gRPC methods are `/pkg.Service/Method`; every route/method has
  `permission: "resource:action"` or `public: true`; navigation entries reference declared
  permissions. The route table is a radix tree over prefixes with a per-prefix method map;
  longest prefix wins; overlap between modules is refused at registration.
- **Rationale**: data-only manifests keep the parser small and fuzzable; refusing overlap
  at registration (not at request time) makes hijacking impossible (SR-001).
- **Alternatives**: regex routes (unbounded parsing cost, injection surface); glob
  prefixes (ambiguous overlap rules).

## 5. Identity at the gateway

- **Browser sessions**: the session cookie (`__Host-session`) is set on the gateway's
  public origin by responses relayed from the auth module. The gateway calls the new
  `auth.v1.Sessions/Exchange(secret)` over the channel, receiving `{identity, access_token,
  expires_at}`; the identity and token are cached under the secret's SHA-256 for
  `min(60 s, token exp)` and invalidated by the revocation feed (`Sessions/RevokedSince`)
  and by sign-out relay. The gateway never sees passwords, codes or secrets other than the
  cookie value it relays.
- **Machine HTTP and gRPC clients**: `Authorization: Bearer <platform access token>`
  verified offline with `pkg/authclient` (keys from `Keys/List`, revocation feed, audience
  must contain `gateway` or be absent); permission decided per call.
- **Forwarded identity**: the gateway always forwards a platform access token (the
  browser's exchanged token or the client's own) in `Authorization`/`authorization`
  metadata and strips every inbound `X-Forwarded-*`, `X-Freya-*` and `Authorization`
  header from browser requests before adding its own. Modules verify the token with
  `pkg/authclient` (already how the downstream example works), so no module trusts
  headers (SR-002).
- **Rationale**: sessions remain owned by the auth module; tokens are the one identity
  currency every module can verify without calling anyone; cache bounds keep p95 within
  SC-003 while the revocation feed keeps SC-004.
- **Alternatives**: gateway-minted identity JWT (second issuer to trust); signed headers
  (custom crypto path); per-request `Introspect` (adds a hop to every call).
- **Auth contract changes**: `Sessions/Exchange` and `Sessions/MintToken` (for the shell's
  own calls) — see `contracts/auth-changes.md`.

## 6. Authorization: API permissions and CASL abilities from one source

- **Decision**: a route's `permission` is checked with `auth.v1.Authorization/BatchCheck`
  (tenant/user from the identity, the route's `resource:action`), cached 2 s under
  `dec:<tenant>:<user>:<perm>@<tenant version>`. UI abilities are declared in the manifest
  as CASL raw rules extended with `requires: "resource:action"` (and optional `fields`,
  `conditions` limited to a documented subset and 4 KiB). `GET /gateway/v1/me/abilities`
  evaluates every registered module's `requires` for the caller in one `BatchCheck`,
  drops rules whose permission is not held, strips `requires`, and returns CASL packed
  rules grouped by module with the caller's tenant/user/roles. The shell builds one
  `Ability` (`@casl/ability`) and provides it through `@casl/vue`'s `abilitiesPlugin`;
  remotes import `@casl/ability` and `@casl/vue` as shared singletons and use `Can` /
  `useAbility()`; when the gateway publishes a registry change or the tenant version
  changes, the shell refetches abilities and calls `ability.update(rules)`.
- **Rationale**: the user asked for two permission kinds; deriving UI rules from API
  permissions guarantees they cannot diverge; CASL's `update()` gives live consistency;
  CASL conditions let modules express field/record-level UI logic the API still enforces.
- **Alternatives**: modules computing abilities themselves (N implementations, divergence);
  shipping API permissions to the UI and letting each module map them (same divergence).

## 7. Forwarding

- **HTTP**: `httputil.ReverseProxy` over a new framework helper
  `transport/http.NewClient(rt, expectedSPIFFEID)` (mTLS with the gateway's SVID, server
  identity pinned to the registrant), request/response header allow-lists, hop-by-hop
  headers removed, `X-Request-Id` correlation, streaming responses, 30 s default per-module
  timeout, response size unbounded but connection-bounded. WebSockets: refused with 501 in
  v1 (documented; the shell and auth do not need them).
- **gRPC**: passthrough proxy with a raw-bytes codec and `UnknownServiceHandler`; unary and
  all streaming kinds; metadata allow-list; deadline propagation capped by the module's
  declared maximum; permission decided once at stream start; a revocation observed on the
  feed cancels streams of that session/user/tenant (FR-025).
- **gRPC-web**: bridge accepting `application/grpc-web(+proto|+json)` and `-text`
  (base64) over HTTP/1.1 or HTTP/2, translating to a client stream on the channel; server
  streaming supported, client streaming refused (gRPC-web limitation); strict framing
  decoder (fuzzed).
- **Rationale**: all three paths reuse the Freya channel and the module's pinned identity;
  no second trust path exists.

## 8. Shell and Module Federation

- **Decision**: the shell is a Vite 8 + Vue 3 + Vuetify 4 app built as a Module
  Federation **host** with `@module-federation/vite` 1.22 and loads remotes dynamically at
  runtime with `@module-federation/enhanced/runtime` (`registerRemotes` + `loadRemote`)
  from `GET /gateway/v1/me/modules`, which lists the caller's visible modules with their
  remote entry (`/m/<module>/mf-manifest.json`) served through the gateway. Shared
  singletons: `vue`, `vue-router`, `pinia`, `vuetify`, `@casl/ability`, `@casl/vue`
  (`singleton: true`, `strictVersion: false`, `requiredVersion` from the shell). Each
  remote exposes `./routes` (route records mounted under its navigation path) and
  optionally `./nav` (dynamic entries) and `./boot` (receives the shared session/ability
  once). The shell wraps each remote in an error boundary with retry (US3). CSP stays
  `script-src 'self' 'nonce-…'` because every remote asset is same-origin via the gateway.
- **Rationale**: the user mandates Module Federation; Vite keeps parity with the auth
  console; runtime registration is what makes new modules appear without a shell deploy.
- **Alternatives**: Rspack/Rsbuild + `@module-federation/enhanced` build plugin (viable,
  but a second bundler for the platform); native import maps / web components (no shared
  singletons, no version negotiation).

## 9. Dependency justification (deltas)

| Dependency | Version | Purpose | Alternatives rejected | Maintenance |
|------------|---------|---------|------------------------|-------------|
| `@module-federation/vite` | 1.22.0 | MF host/remote builds for Vite | Rspack toolchain (second bundler) | Active (module-federation org) |
| `@module-federation/enhanced` | 2.9.0 | runtime `registerRemotes`/`loadRemote`, manifest protocol | hand-rolled script loading (no version negotiation) | Active |
| `@casl/ability` | 7.0.1 | UI abilities, `packRules`, `update()` | custom permission helpers per module | Active |
| `@casl/vue` | 3.0.1 | `Can` component, `useAbility` | manual injection | Active |

Go: no new modules. Existing justifications (`services/auth/docs/dependencies.md`) cover
grpc, valkey-go, pgx, goose, kin-openapi, golang-jwt (via `pkg/authclient`). The gRPC
proxy/bridge is in-house code on grpc-go (≈ 600 lines, fully fuzzed) rather than an
archived library.

## 10. Threat model (STRIDE)

| Threat | Mitigation | Verified by |
|--------|------------|-------------|
| **S** rogue module registers another module's prefix/name | identity allow-list with permitted prefixes; overlap refused at registration; audited | `TestPrefixHijack` |
| **S** identity header injection from the public network | all inbound identity/forwarding headers stripped; modules verify tokens, never headers | `TestHeaderInjection`, module-side verifier tests |
| **S** token replay / audience confusion (machine, gRPC) | offline verification: signature, issuer, expiry, audience contains `gateway` or absent, revocation feed | `TestTokenMatrix` |
| **T** confused deputy (forwarding a call the user may not make) | permission decided per route/method before forwarding; fail closed on decision outage | `TestPermissionMatrix` (SC-002), `TestDecisionOutage` |
| **T** manifest poisoning (huge/odd manifests, regex, CASL conditions) | JSON Schema + semantic validation, size caps, data-only grammar, fuzzing | `FuzzManifest`, `FuzzCASLRule` |
| **T** malicious remote code in the shell | remotes only from current registrations, served same-origin, CSP without remote origins; SRI on remote entry where the build provides hashes | `TestRemoteOrigins`, Playwright CSP checks |
| **R** operator drains/revokes, allow-list edits | audited with operator identity | `TestOperatorAudit` |
| **I** enumeration of modules through errors | uniform error vocabulary; unknown paths `not_found` without prefix hints | `TestErrorHygiene` (SC-008) |
| **I** cookies/tokens in logs | Freya redaction + gateway redaction list; scan | `TestRedactionScan` |
| **D** slow/oversized requests, stream floods | edge limits; per-module timeouts and circuit breaker; per-client stream caps | `TestHardening`, `TestStreamCaps` |
| **E** UI shows actions the API forbids (or vice versa) | abilities derived from API permissions in one call; `update()` on change | `TestAbilitiesMatchDecisions`, shell unit tests |
| **S/T** stale decisions after revocation | 2 s decision cache keyed by tenant version; revocation feed cancels streams and identity cache | `TestRevocationPropagation` (SC-004) |
