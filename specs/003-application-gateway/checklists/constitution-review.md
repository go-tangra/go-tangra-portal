# Constitution compliance review — 003 Application Gateway

**Reviewed**: 2026-09-16 · **Constitution**: 1.0.0 · **Scope**: `services/gateway`, `transport/http.NewClient`, `transport/edge.Config.CSRFExempt`, auth gateway mode

## I. Secure by Default
- [x] Edge listener is TLS 1.3 only; a generated certificate is refused in production (`config.Validate`).
- [x] Every insecure convenience (`valkey.allow_plaintext`, weak `sslmode`, wildcard origins, gateway mode delegating CSRF) logs a startup warning (`config.Warnings`, auth `config.Warnings`).
- [x] Zero configuration refuses to start (`public_origin`, `db.dsn`, `valkey.addresses`, `auth.issuer` required).
- [x] Protected routes default to deny: no identity → 401, no decision → 503, unknown module → 404.

## II. Zero Trust Service Communication
- [x] Registration identity is the mTLS peer (`authn.FromContext`), never a request field; allow-list per SPIFFE ID.
- [x] Forwarding pins the registrant's SPIFFE ID (`transport/http.NewClient`, `credentials.NewTLS` in `grpcproxy`); no hostname trust, no redirects.
- [x] Auth RPCs `Sessions/Exchange` and `MintToken` are restricted to the gateway identity by policy.
- [x] Modules verify the forwarded platform token with `pkg/authclient`; inbound identity headers are stripped.

## III. Boundary Validation & Defense in Depth
- [x] Manifests validated against the published JSON Schema plus semantic rules; gateway API requests validated against the OpenAPI document; gRPC-web frames decoded with strict size limits.
- [x] Limits enforced at the edge (rate, body, headers, TLS handshake) and again per route/method (body, timeout, streams, stream lifetime).
- [x] Path normalisation refuses traversal before routing; the remote relay only reaches `/ui/` of current registrations.

## IV. Test-First with Security Verification
- [x] Unit, contract, fuzz (`FuzzManifest`, `FuzzCASLRule`, `FuzzPrefix`, `FuzzRoutePath`, `FuzzRegisterRequest`, `FuzzGRPCWebFrame`, `FuzzBearerToken`, `FuzzPathNormalize`, `FuzzAbilityPack`) and integration suites with negative security tests (hijack, injection, token matrix, revocation, outage, hardening).
- [x] Coverage gate: ≥ 80 % overall and 100 % for `internal/{authz,route,identity,manifest}` (`scripts/coverage-gate.sh`; see T088 results in quickstart-results.md).

## V. Observability & Auditability
- [x] Closed audit vocabulary (14 event types) in an append-only hypertable; every registration, refusal, renewal refusal, drain/revoke, identity and permission refusal is recorded once with correlation ids.
- [x] Audit details redact forbidden keys; error bodies carry only `{"reason"}`; redaction scan over captured output (`scripts/redaction-scan.sh`).
- [x] Admin/health/metrics on the Freya admin listener, never on the public edge.

## VI. Supply Chain Integrity & Minimal Dependencies
- [x] New direct dependencies justified in `docs/dependencies.md` (`santhosh-tekuri/jsonschema/v6`, `google/uuid`, `gopkg.in/yaml.v3`); `govulncheck` clean; `go.sum` committed.
- [x] No custom cryptography: SHA-256 for cache keys/pseudonyms, EdDSA verification via `pkg/authclient`.

## VII. Simplicity & Explicit Configuration
- [x] Typed YAML configuration with unknown-field rejection and start-up validation; no environment discovery.
- [x] Deviations recorded: JSON-Schema library (Complexity Tracking in plan.md); in-house gRPC passthrough instead of a proxy library.

## Open items
- SC-003 (p95 forwarding overhead < 10 ms at 1,000 concurrency) could not be confirmed on the 4-core development workstation: the direct path itself measures ~760 ms p95 at that concurrency; the benchmark and gate exist (`BenchmarkForward`, `scripts/perf-gate.sh`) for a sized environment.
