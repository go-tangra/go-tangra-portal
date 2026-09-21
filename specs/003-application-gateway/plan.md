# Implementation Plan: Application Gateway

**Branch**: `003-application-gateway` | **Date**: 2026-09-16 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/003-application-gateway/spec.md`

## Summary

`services/gateway` is the platform's single public entry point, built on Freya. Private
modules register a **manifest** over the mTLS service channel (`gateway.v1.Registry`):
owned path prefixes, HTTP routes and gRPC methods with their **API permission**
(`resource:action`) or an explicit public marker, **UI abilities** expressed as CASL
rules bound to API permissions, the location of their Module Federation remote and their
navigation entries. Registrations are 30-second leases stored in Valkey and mirrored on
every gateway instance. The public listener (`transport/edge`, TLS 1.3, HTTP/1.1 + HTTP/2)
accepts browsers (session cookie → identity via `auth.v1.Sessions/Exchange`), machine
HTTP clients and gRPC/gRPC-web clients (platform access tokens verified offline with
`pkg/authclient`), checks the route's permission through `auth.v1.Authorization/BatchCheck`
with a 2-second decision cache, then forwards over mTLS to the owning module — HTTP via a
new Freya mTLS HTTP client, gRPC via an in-house passthrough proxy, gRPC-web via an
in-house bridge — always carrying a verified platform access token that modules check with
`pkg/authclient`. The gateway serves the **shell** (Vue 3 + Vuetify host built with
`@module-federation/vite`), which loads module remotes at runtime from the registry,
builds navigation from manifests filtered by the user's permissions and hands each remote
a shared CASL `Ability` computed by the gateway from the same permissions, so UI and API
authorization can never disagree. `services/auth` becomes the first module: it gains a
gateway mode (browser API over the Freya HTTP server, edge disabled, CSRF at the gateway),
two `auth.v1` RPCs and a federated console.

## Technical Context

**Language/Version**: Go 1.26 (toolchain go1.26.8) on Freya (Kratos v3, grpc v1.83.2);
TypeScript 5.9 for the shell and remotes.

**Primary Dependencies**: Go — `github.com/go-freya/freya` (edge listener, mTLS servers,
identity, policy, audit), `google.golang.org/grpc` (gRPC ingress and passthrough proxy),
`github.com/valkey-io/valkey-go` (registry state, decision cache, pub/sub), `pgx` +
`goose` (allow-list, operator configuration, audit hypertable in TimescaleDB),
`github.com/getkin/kin-openapi` (gateway API validation), `services/auth/pkg/authclient`
(token verification, revocation feed). Console — Vue 3.5, Vuetify 4, vue-router 5, Pinia 4,
`@module-federation/vite` 1.22, `@module-federation/enhanced` 2.9 (runtime),
`@casl/ability` 7, `@casl/vue` 3, Vite 8, Vitest 5, Playwright 1.63 + axe. Details and
alternatives in research.md §9.

**Storage**: Valkey for registrations/leases, backend health, decision and identity caches
(TTL-bound, rebuildable from module renewals); TimescaleDB (`gateway` database) for the
identity allow-list, drained/revoked marks and the audit hypertable (retention 400 d).

**Testing**: Go `testing` + `-race`; unit tests with in-memory registry/KV fakes; contract
tests for `gateway.v1`, the manifest JSON Schema and the gateway OpenAPI document; fuzz
targets for manifest, path matching, gRPC-web framing, CASL rule validation and token
parsing; integration suite (`-tags integration`, testcontainers: TimescaleDB, Valkey,
OpenFGA, auth service, two test modules) covering the cross-module permission matrix,
lease expiry, drain/revoke, gRPC/gRPC-web ingress, revocation propagation and error
hygiene; Vitest for shell components/composables; Playwright + axe for the composed UI.

**Target Platform**: Linux server (containers); browsers (evergreen) for the shell.

**Project Type**: web service (public edge + private-channel client) with a federated
frontend host; own Go module under `services/gateway`, movable to its own repository.

**Performance Goals**: ≤ 10 ms p95 gateway overhead at 1,000 concurrent users (SC-003);
route table lookups O(log n) over prefixes; decision cache hit ratio > 95 % in steady state;
shell first render ≤ 3 s (SC-010).

**Constraints**: fail closed on any identity/decision outage (SR-003); revocation and
permission changes visible ≤ 5 s (FR-010, SC-004); leases 10 s renew / 30 s expiry
(SC-005); one public origin — every module asset and API is served through it (FR-014);
gRPC ingress requires HTTP/2 over TLS; WebSockets are out of scope for v1 (research §7).

**Scale/Scope**: tens of modules, hundreds of routes, thousands of concurrent users,
multiple gateway instances behind a TCP/L4 load balancer; a shell, an operations UI and
the auth console converted to a remote.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- [x] **I. Secure by Default**: PASS. Public listener is `transport/edge` (TLS 1.3 only,
      HSTS, CSP with nonces and no remote origins, frame-deny, CSRF double-submit, rate
      and size limits); registrations require an allow-listed SPIFFE identity; routes
      without a declared permission are refused; caller identity headers are stripped;
      dev conveniences (self-signed edge cert, plaintext Valkey) need `env != production`.
- [x] **II. Zero Trust**: PASS. Registration and forwarding use the Freya mTLS channel
      with the module's identity pinned to its registration; modules verify the forwarded
      platform access token themselves (`pkg/authclient`) instead of trusting headers;
      the gateway holds no user credentials.
- [x] **III. Boundary Validation**: PASS. Manifests validated against a JSON Schema and
      protobuf constraints (sizes, grammar, prefix overlap, CASL rule shape); public HTTP
      bodies/headers bounded before forwarding; gRPC message sizes and stream counts
      capped; gRPC-web framing parsed by a strict, fuzzed decoder; path matching is exact
      longest-prefix with normalisation and no regex from manifests.
- [x] **IV. Test-First (NON-NEGOTIABLE)**: PASS. Every story lists negative security
      tests (cross-module permission matrix, header injection, prefix hijack, token
      audience confusion, stale-decision fail-closed, stream termination on revocation)
      and fuzz targets; coverage gate 80 % overall and 100 % for `internal/{authz,route,
      identity,manifest}`.
- [x] **V. Observability**: PASS. Freya audit stream plus the gateway audit hypertable
      (closed vocabulary, data-model.md); correlation id issued at the edge and propagated
      to modules (`X-Request-Id` / gRPC metadata); per-module metrics on the admin
      listener only; redaction covers cookies, tokens and forwarded authorization.
- [x] **VI. Supply Chain**: PASS. No new Go dependencies beyond those already justified
      for `services/auth`; three new console dependencies (`@module-federation/vite`,
      `@module-federation/enhanced`, `@casl/*`) justified in research.md §9; gRPC proxy and
      gRPC-web bridge implemented in-house on grpc-go (no unmaintained proxy libraries).
- [x] **VII. Simplicity**: PASS with justified additions (Complexity Tracking): Module
      Federation runtime, an in-house gRPC/gRPC-web ingress, and two backing stores. Typed
      configuration via Freya `config`; no reflection-based routing; manifests are data.
- [x] **Threat Model**: PASS. STRIDE for public ingress, registration, forwarding, shell
      composition and operations in research.md §10.

*Post-Phase 1 re-check (2026-09-16)*: all gates still PASS. The design added two RPCs to
`auth.v1` (research §5) and one framework helper (`transport/http.NewClient`); neither
introduces a dependency or an insecure default.

## Project Structure

### Documentation (this feature)

```text
specs/003-application-gateway/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── gateway.v1.proto            # Registry (register/renew/deregister/watch) over the Freya channel
│   ├── manifest.schema.json        # module manifest (routes, permissions, CASL abilities, remote, nav)
│   ├── gateway-api.openapi.yaml    # shell + operations HTTP API (/gateway/v1/...)
│   ├── forwarding.md               # what modules receive: token, headers, metadata, errors
│   ├── federation.md               # Module Federation host/remote contract and CASL distribution
│   └── auth-changes.md             # required changes to services/auth (gateway mode, new RPCs)
└── tasks.md                        # /speckit-tasks
```

### Source Code (repository root)

```text
transport/http/client.go            # NEW (framework): mTLS HTTP client pinned to a SPIFFE ID

services/gateway/                   # own module: github.com/go-freya/freya/services/gateway
├── go.mod                          # replace github.com/go-freya/freya => ../..
├── cmd/gatewaysvc/main.go          # run; bootstrap (allow-list seed)
├── api/
│   ├── proto/gateway/v1/           # gateway.v1 (registry) — generated with buf
│   ├── openapi/gateway.yaml        # shell/operations API (embedded, validated at runtime)
│   └── schema/manifest.schema.json # embedded; validates every manifest
├── internal/
│   ├── config/                     # Freya config + Edge, Valkey, DB, Auth, Limits, Leases
│   ├── manifest/                   # parse/validate manifests, CASL rule grammar (fuzzed)
│   ├── registry/                   # leases, allow-list, health, drain/revoke; Valkey + memory
│   ├── route/                      # immutable route table, longest-prefix match, method map
│   ├── identity/                   # session exchange, token verification, identity cache
│   ├── authz/                      # decision client (BatchCheck), decision cache, CASL builder
│   ├── proxy/
│   │   ├── httpproxy/              # reverse proxy over transport/http.NewClient
│   │   ├── grpcproxy/              # passthrough (UnknownServiceHandler + raw codec)
│   │   └── grpcweb/                # gRPC-web ↔ gRPC bridge (framing, trailers, text mode)
│   ├── health/                     # backend probes, circuit state, cool-down
│   ├── audit/                      # closed vocabulary, batched hypertable writer
│   ├── httpapi/                    # shell API, operations API, CSRF, session cookie relay
│   ├── grpcapi/                    # gateway.v1.Registry server
│   ├── store/                      # migrations (allow-list, marks, audit hypertable), RLS n/a
│   └── app/                        # wiring: config → Freya → stores → proxies → edge
├── pkg/gatewayclient/              # module-side SDK: Register/Renew loop, manifest builder
├── shell/                          # Vue 3 + Vuetify host (Module Federation host)
│   ├── src/{main.ts,App.vue,router/,stores/,api/,federation/,casl/,layouts/,views/}
│   ├── module-federation.config.ts # shared singletons: vue, vue-router, pinia, vuetify, @casl/*
│   └── tests/{unit,e2e}
├── examples/hello-module/          # reference module: Go service + federated remote UI
├── deploy/{compose.yaml,dev.yaml,policy.yaml,init-db.sql}
├── docs/{security-model.md,operations.md,module-guide.md,dependencies.md}
├── scripts/{coverage-gate.sh,redaction-scan.sh,perf-gate.sh}
└── tests/{contract,fuzz,integration}

services/auth/                      # changes (contracts/auth-changes.md)
├── api/proto/auth/v1/auth.proto    # + Sessions/Exchange, Sessions/MintToken
├── internal/app/                   # gateway mode: browser API on the Freya HTTP server
├── internal/gatewayreg/            # manifest + registration loop via pkg/gatewayclient
└── console/                        # becomes a federated remote (exposes ./routes, ./nav)
```

**Structure Decision**: same shape as `services/auth` (own module, `internal/*` logic
packages with `*db` bindings, `pkg/` for the SDK other modules import, `shell/` instead
of `console/`). The gateway persists only what cannot be re-derived (allow-list, marks,
audit); everything about a live module is a lease renewed by the module.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| In-house gRPC passthrough proxy and gRPC-web bridge (`internal/proxy/grpcproxy`, `grpcweb`) | Q1 = C: external gRPC and gRPC-web clients must reach registered service methods through the single public origin with per-method permissions | Maintained proxy libraries do not exist for grpc-go v1.83 (mwitkow/grpc-proxy and improbable-eng/grpc-web are archived); Envoy/contour would add a second public component outside the constitution's identity/policy model |
| Module Federation runtime (`@module-federation/enhanced` runtime + `@module-federation/vite`) | User requirement: every module UI is a federated remote composed by the shell | Iframes break shared session/design system and CASL distribution; build-time bundling of all module UIs defeats independent deployment (SC US3-5) |
| Two backing stores (Valkey for leases/caches, TimescaleDB for allow-list/marks/audit) | Leases are TTL data shared by several gateway instances; allow-list and audit need durability and retention | Single Postgres store would make lease renewals (every 10 s per module instance) and decision caches write-heavy on the durable store; single Valkey store cannot hold the 400-day audit retention |
| Two new `auth.v1` RPCs and an auth "gateway mode" | Browser sessions are owned by the auth module; the gateway must turn a session cookie into a verifiable identity and token without seeing user credentials | Per-request `Introspect` of a minted token is circular for cookie sessions; duplicating session storage in the gateway would split the security-critical session logic across two services |
