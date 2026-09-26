# Security model — application gateway

The gateway is the only public listener of the platform. Every other module
stays on the Freya channel (SPIFFE mTLS, TLS 1.3) and is reached exclusively
through the gateway. This document describes what the gateway trusts, what it
decides, and what it forwards. Threats follow the STRIDE analysis in
`specs/003-application-gateway/research.md` §10.

## Trust boundaries

| Boundary | Authentication | Authorization |
|----------|----------------|---------------|
| Public edge (`transport/edge`) | Server-authenticated TLS 1.3 only; browsers hold the platform session cookie, machine clients a platform access token | Per-route / per-method permission (below); CSRF double-submit for cookie-bearing state changes |
| Registry (`gateway.v1.Registry`, Freya gRPC) | mTLS peer identity (SPIFFE ID) | Freya policy (`deploy/policy.yaml`) + allow-list (`allow_list` table): identity → permitted prefixes and module names |
| Forwarding (gateway → module) | Gateway SVID; the module's registered SPIFFE ID is pinned per connection (`transport/http.NewClient`, `credentials.NewTLS` in `grpcproxy`) | The module verifies the forwarded platform token with `pkg/authclient` and never trusts headers |
| Auth module (`auth.v1`) | Gateway SVID; auth policy restricts `Sessions/Exchange` and `Sessions/MintToken` to the gateway identity | — |

## Identity

- **Browser sessions.** The `__Host-session` cookie is set on the gateway
  origin by responses relayed from the auth module (the only module whose
  `Set-Cookie` is relayed and the only module that receives `Cookie`). The
  gateway exchanges the cookie through `Sessions/Exchange` for the caller's
  identity and a platform access token (audience `gateway`), caches both under
  the cookie's SHA-256 for at most 60 s (bounded by the token lifetime) and
  re-verifies the cached token offline on every hit, so revocations seen on the
  auth feed invalidate the entry without a round trip. A relayed sign-out
  drops the entry immediately.
- **Machine and gRPC clients.** `Authorization: Bearer <token>` is verified
  offline (`pkg/authclient`: EdDSA signature, issuer, expiry, revocation feed,
  audience `gateway` or absent). A stale revocation feed refuses tokens
  (`temporarily_unavailable`), never accepts them.
- Every refusal is audited as `identity_refused`; outages are `failed`, bad
  credentials `refused`.

- Session identities carry the person's display name and avatar address from
  the auth module (feature 004); `/gateway/v1/me` exposes them to modules and
  the shell header shows them. A response from the auth module carrying
  `X-Freya-Identity-Refresh` drops the cached identity of that cookie; the
  header is removed before it reaches the browser and dropped from inbound
  requests, and only the auth module can trigger it. Roles in the identity are
  the user's effective roles (direct and through groups).

## Decisions

- A route or method is either `public` or carries exactly one
  `resource:action` permission (enforced by the manifest schema and the
  registry). Protected entries are decided with
  `auth.v1.Authorization/BatchCheck` for the caller's tenant and user, naming
  the route's module (`PermissionRef.module`): the same `resource:action` of
  two modules are different permissions. Answers are cached for 2 s under
  `gwdec:<tenant>:<user>:<module>:<resource:action>@<policy version>`, denied
  on outage (`permission_refused` audited with `decision_unavailable`).
- Navigation entries and CASL abilities (`/gateway/v1/me/modules`,
  `/gateway/v1/me/abilities`) are decided the same way: a manifest's bare
  `requires` is qualified with the registration's module, so a permission
  held for one module never unlocks another module's navigation or rules.
- Streams decide once at stream start; a revocation observed on the feed
  cancels every stream of that session, user or tenant with
  `PERMISSION_DENIED` (`grpcproxy.CancelSubject`).
- Draining, unhealthy and revoked modules answer `temporarily_unavailable`
  before any identity work.

## Forwarding (contracts/forwarding.md)

- HTTP: `httputil.ReverseProxy` over a client pinned to the module identity.
  Inbound `Authorization`, `Cookie` (except to auth), `Forwarded`,
  `X-Forwarded-*`, `X-Real-IP`, `X-Freya-*`, `X-Gateway-*` and `X-Request-Id`
  are removed; the gateway adds `Authorization: Bearer <platform token>` (only
  for protected routes), `X-Request-Id`, `X-Forwarded-Proto/Host`,
  `X-Gateway-Module` and the hashed `X-Gateway-Client` (and the plain
  `X-Gateway-Client-Addr` only on routes flagged `client_address`). Module
  `Set-Cookie` (except auth), `Content-Security-Policy` and
  `Strict-Transport-Security` never reach the browser. Redirects are not
  followed; WebSocket upgrades are refused (501).
- gRPC: passthrough with a raw codec (payloads are never decoded), metadata
  allow-list with the same removals, deadline capped by the method's declared
  maximum, per-client concurrent streams bounded.
- gRPC-web: binary and text framing decoded with strict size limits; client
  streaming refused; server streaming supported.
- Body, header, timeout and stream limits come from the manifest (per route)
  or `forward.*` configuration.

## Registration

- The registrant identity is the mTLS peer; the request carries no identity
  field. The allow-list maps the identity to permitted prefixes and names.
- Manifests are validated against the published JSON Schema plus semantic
  rules (prefix normalisation and overlap, `permission` xor `public`,
  declared permissions, CASL condition grammar ≤ 4 KiB, catch-all only as the
  last segment). Prefix or CASL subject overlap with another module is refused
  (`prefix_conflict`, `subject_conflict`); a different identity cannot join a
  module (`identity_mismatch`); a changed manifest needs a version bump.
- Leases (30 s, renewed every 10 s) withdraw crashed instances; drain and
  revoke marks refuse renewals. Every accept, refusal, update, withdrawal and
  renewal refusal is audited once with the registrant identity.
- Module permissions are registered with the auth module for every tenant
  (`Authorization/RegisterPermissions`) when a manifest is accepted and again
  every five minutes, on the module's behalf: the request names the module
  and its display name and carries permissions only — never roles, role sets
  or built-in grants (those come from the module's own registration). A
  refused registration is logged and the other modules still register.

## Error hygiene

Every refusal is `{"reason": "<closed vocabulary>"}`; module and upstream
failures are `temporarily_unavailable` (503/504 or `UNAVAILABLE`); internal
details, module names and stack traces never leave the gateway.

## STRIDE summary (research.md §10)

| Threat | Control |
|--------|---------|
| Spoofing a registrant | mTLS identity + allow-list; no identity field in the request |
| Tampering with forwarded identity | Inbound identity headers stripped; forwarded token minted by auth and verifiable offline |
| Repudiation | Audit vocabulary with registrant, user and correlation ids; append-only hypertable |
| Information disclosure | Uniform refusals, payloads never decoded, secrets never logged (redaction scan) |
| Denial of service | Body/header/timeout/stream caps, rate limits at the edge, health circuit per instance |
| Elevation of privilege | Permission decided per call from the tenant policy; drift refused; CASL abilities derived from held permissions only |
