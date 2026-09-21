---

description: "Task list for Application Gateway"
---

# Tasks: Application Gateway

**Input**: Design documents from `/specs/003-application-gateway/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/, quickstart.md

**Tests**: Tests are MANDATORY (Constitution Principle IV, NON-NEGOTIABLE). Every user story lists its test tasks before its implementation tasks, and tests MUST be written and confirmed failing before implementation. Every story touches transport, authentication, authorization or parsing, so each includes negative security tests; every parser (manifest, CASL rules, path matcher, gRPC-web framing, tokens, OpenAPI bodies) has a fuzz target.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: Which user story this task belongs to (US1–US5)
- Include exact file paths in descriptions

## Path Conventions

- Gateway service: `services/gateway/` (own Go module `github.com/go-freya/freya/services/gateway`, `replace ../..`), shell at `services/gateway/shell/`
- Framework additions: `transport/http/client.go`
- Auth changes: `services/auth/` (contracts/auth-changes.md)
- Design references: `specs/003-application-gateway/{plan,research,data-model,quickstart}.md`, `contracts/`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Module skeleton, contracts, toolchains and CI so every later task has a home.

- [X] T001 Create the service module skeleton per plan.md (go.mod with `replace ../..`, `cmd/gatewaysvc`, `internal/{config,manifest,registry,route,identity,authz,proxy/{httpproxy,grpcproxy,grpcweb},health,audit,httpapi,grpcapi,store,app}`, `pkg/gatewayclient`, `examples/hello-module`, `deploy`, `docs`, `scripts`, `tests/{contract,fuzz,integration}`, doc.go per package) in services/gateway/
- [X] T002 Copy contracts into the module and generate code: `specs/003-application-gateway/contracts/gateway.v1.proto` → `services/gateway/api/proto/gateway/v1/gateway.proto` (buf.yaml, buf.gen.yaml, generated `*.pb.go`), `manifest.schema.json` → `services/gateway/api/schema/manifest.schema.json` (embedded), `gateway-api.openapi.yaml` → `services/gateway/api/openapi/gateway.yaml` (embedded)
- [X] T003 [P] Makefile mirroring services/auth (lint, vuln, test, test-integration, cover with `COVERPKG` excluding `api/proto`, `*db`, `store`, `app`, `cmd`, `examples`, `tests`, `shell`; fuzz; generate; shell-build; redaction-scan; perf-gate; compose-up/down) and `scripts/{coverage-gate.sh (100 % for internal/{authz,route,identity,manifest}), redaction-scan.sh, perf-gate.sh}` in services/gateway/Makefile and services/gateway/scripts/
- [X] T004 [P] Development stack `services/gateway/deploy/{compose.yaml (TimescaleDB with `gateway` + `openfga` + `auth` databases, Valkey, OpenFGA, mailpit), init-db.sql (roles `gateway_app`, `auth_app`), dev.yaml, policy.yaml (auth may call Registry; gateway may call auth.v1 Sessions/Exchange|MintToken|RevokedSince, Keys/List, Authorization/BatchCheck)}` and `.dev/ca` generation for `auth,gateway,hello` (root Makefile `testca` services list)
- [X] T005 [P] Shell scaffold `services/gateway/shell/` (Vite 8 + Vue 3.5 + Vuetify 4 + vue-router 5 + Pinia 4 + TypeScript 5.9, `@module-federation/vite` 1.22, `@module-federation/enhanced` 2.9, `@casl/ability` 7, `@casl/vue` 3, Vitest 5 + jsdom setup, Playwright 1.63 + axe, eslint with browser globals, `module-federation.config.ts` host with shared singletons, `npm run gen:api` from api/openapi/gateway.yaml) with `package.json`, `vite.config.ts`, `tsconfig*.json`, `index.html` (csp-nonce meta), `src/main.ts`, `src/App.vue`
- [X] T006 [P] Dependency justification `services/gateway/docs/dependencies.md` (research.md §9) and `.github/workflows/ci.yml` jobs `gateway-service` (lint, vuln, test, cover, shell lint/unit/build/audit) and `gateway-service-integration` (`-tags integration`, compose, Playwright)
- [X] T007 [P] Root `.gitignore` entries for `services/*/shell/{node_modules,dist,test-results,playwright-report}` and `services/gateway/.gitignore`

**Checkpoint**: `go build ./...` and `npm run build` succeed on empty skeletons; CI jobs are wired.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Contracts, configuration, stores, the framework's mTLS HTTP client, audit, and the auth-side RPCs every story relies on.

### Tests (write first)

- [X] T008 [P] Unit tests for `transport/http.NewClient`: mTLS with the runtime's SVID, server SPIFFE ID pinned (wrong ID refused), TLS 1.3 only, timeouts, audited handshake refusal in transport/http/client_test.go
- [X] T009 [P] Unit tests for `config`: defaults, `Validate` (production refuses plaintext Valkey, missing edge certificate, weak sslmode, lease TTL < 2×renew), `Warnings` in services/gateway/internal/config/config_test.go
- [X] T010 [P] Unit tests for `manifest`: JSON Schema acceptance/refusal, semantic checks (prefix overlap within a manifest, route outside prefix, `permission` xor `public`, unknown `requires`, CASL condition operator allow-list and 4 KiB cap, duplicate subjects), proto ↔ struct conversion in services/gateway/internal/manifest/manifest_test.go
- [X] T011 [P] Fuzz targets `FuzzManifest`, `FuzzCASLRule`, `FuzzPrefix`, `FuzzRoutePath` in services/gateway/tests/fuzz/manifest_fuzz_test.go
- [X] T012 [P] Unit tests for `route`: radix longest-prefix match, method map, path params, normalisation (`//`, `.`, `..`, trailing slash, percent-encoding), no overlap across modules, immutable snapshot swap under concurrent lookups in services/gateway/internal/route/table_test.go
- [X] T013 [P] Unit tests for `store` migrations + `memstore` double (allow-list lookup by SPIFFE ID with prefixes/names, marks, audit rows) in services/gateway/internal/store/migrate_test.go (`//go:build integration`) and services/gateway/internal/memstore/memstore_test.go
- [X] T014 [P] Unit tests for gateway `audit` writer (closed vocabulary from data-model.md, redaction of cookie/token/authorization keys, batching) in services/gateway/internal/audit/audit_test.go
- [X] T015 [P] Unit tests for `auth.v1.Sessions/Exchange` and `MintToken` (resolve like the cookie path, token minted for the session, revoked/expired refused, only the gateway identity may call — policy) in services/auth/internal/grpcapi/sessions_test.go
- [X] T016 [P] Contract tests: `gateway.v1` shapes and `RegistryEvent.kind` vocabulary, manifest schema self-validation, gateway OpenAPI document parses and every route is mounted in services/gateway/tests/contract/{grpc_test.go,manifest_test.go,openapi_test.go}
- [X] T017 [P] Unit tests for `httpapi` skeleton (OpenAPI validation, error encoder `{"reason"}` only, 5xx → `temporarily_unavailable`, CSRF double-submit for state-changing `/gateway/v1/*`, security headers) in services/gateway/internal/httpapi/server_test.go

### Implementation

- [X] T018 Implement `transport/http.NewClient(rt, expectedID) (*http.Client, error)` (Freya tlsconf client config, SPIFFE pin via `VerifyConnection`, audited refusals) in transport/http/client.go; add to the contract reflection walk and CHANGELOG.md
- [X] T019 [P] Implement `config` (Freya `config.Config` + `Edge`, `Valkey`, `DB`, `Auth{Service, Issuer, Audience}`, `Leases{TTL, Renew}`, `Limits{Body, StreamsPerClient, StreamMax}`, `Operators{Roles}`) with `Load/Validate/Warnings` in services/gateway/internal/config/config.go
- [X] T020 [P] Implement `manifest` (schema validation via embedded JSON Schema, semantic validation, proto conversion, CASL condition grammar) in services/gateway/internal/manifest/{manifest.go,casl.go,convert.go}
- [X] T021 [P] Implement `route` (radix prefix tree, per-module HTTP matcher and gRPC method map, snapshot builder from registrations, `Match(method, path)` / `MatchMethod(full)`) in services/gateway/internal/route/table.go
- [X] T022 Write goose migrations (allow_list, module_marks, gateway_audit_events hypertable 400 d retention, grants to `gateway_app`) and `store` (Open/Migrate/Tx, repositories) in services/gateway/internal/store/{migrations/0001_schema.sql,0002_hypertables.sql,0003_grants.sql,store.go,repos.go}; in-memory double in services/gateway/internal/memstore/memstore.go
- [X] T023 [P] Implement gateway `audit` (vocabulary, `Writer`, `Query`) and `auditdb` binding in services/gateway/internal/audit/{audit.go,query.go} and services/gateway/internal/audit/auditdb/db.go
- [X] T024 [P] Implement `auth.v1.Sessions/Exchange` and `MintToken` (proto, generated code, handler on `session.Manager` + `token.Issuer`, `token_exchanged` audit event, policy rule for the gateway identity) in services/auth/api/proto/auth/v1/auth.proto, services/auth/internal/grpcapi/sessions.go, services/auth/deploy/policy.yaml
- [X] T025 Implement `httpapi` skeleton (OpenAPI-validated router for `/gateway/v1/*`, error encoder, CSRF filter reuse from `transport/edge`, shell static serving with CSP nonce, `/m/{module}/*` placeholder) in services/gateway/internal/httpapi/{server.go,errors.go,shell.go}
- [X] T026 [P] Implement `grpcapi` skeleton registering `gateway.v1.Registry` (unimplemented) on the Freya gRPC server in services/gateway/internal/grpcapi/server.go
- [X] T027 Implement `cmd/gatewaysvc` and `internal/app` wiring (config → Freya `App` + edge listener via `AddServer` → stores → audit → httpapi/grpcapi; `bootstrap -allow <spiffe>=<prefixes>` seeding the allow-list) in services/gateway/cmd/gatewaysvc/{main.go,bootstrap.go} and services/gateway/internal/app/app.go
- [X] T028 [P] Integration harness (testcontainers: TimescaleDB, Valkey TLS, OpenFGA, mailpit; auth service in gateway mode in-process; gateway in-process; two test modules `alpha`/`beta` with HTTP routes, gRPC methods and static remotes; helpers for browsers, tokens, registration) in services/gateway/tests/integration/harness_test.go
- [X] T029 [P] Shell foundation: router with error boundaries, `session` store (`GET /gateway/v1/me`), `api` client (CSRF header, error mapping, outage event), `federation/` runtime wrapper (`registerRemotes`, `loadRemote`, retry), `casl/` provider (`createMongoAbility`, `abilitiesPlugin`, `update`), layouts and outage/forbidden views in services/gateway/shell/src/{router/index.ts,stores/session.ts,api/client.ts,federation/runtime.ts,casl/ability.ts,layouts/Default.vue,views/{Outage,Forbidden,NotFound}.vue}
- [X] T030 [P] Module SDK `pkg/gatewayclient` (manifest builder from typed Go values, `Register/Renew` loop with jitter and backoff, `Deregister` on shutdown, expects the Freya client conn) in services/gateway/pkg/gatewayclient/{client.go,manifest.go} with unit tests in client_test.go

**Checkpoint**: gateway boots against the compose stack, serves the empty shell, accepts nothing yet; auth exposes `Sessions/Exchange`.

---

## Phase 3: User Story 1 - A Module Registers Itself and Its Routes (Priority: P1) 🎯 MVP

**Goal**: Modules register manifests over the mTLS channel under an allow-list; leases expire; conflicts refused; public routes forwarded; unregistered paths 404.

**Independent Test**: quickstart.md §2 and §7 — start gateway + `alpha`; `alpha` registers two routes; public route answers through the gateway; unknown path → `not_found`; stopping `alpha` withdraws its routes within 30 s.

### Tests for User Story 1 (MANDATORY) ⚠️

- [X] T031 [P] [US1] Unit tests for `registry`: register (allow-list, prefix/name conflicts, identity mismatch, manifest drift across instances, version bump replaces atomically), renew/expiry (fake clock), deregister, watch events, Valkey and memory backends in services/gateway/internal/registry/registry_test.go
- [X] T032 [P] [US1] Unit tests for `httpproxy`: forwarding over a pinned mTLS client (test module with `testrt`), hop-by-hop and identity headers stripped, `X-Request-Id`/`X-Forwarded-Proto/Host` added, `Set-Cookie` dropped except from the auth module, body/timeout limits, 502/504 → `temporarily_unavailable` in services/gateway/internal/proxy/httpproxy/proxy_test.go
- [X] T033 [P] [US1] Unit tests for `health` (probe failures → unhealthy after N, cool-down, recovery, per-instance state) in services/gateway/internal/health/health_test.go
- [X] T034 [US1] Integration `TestRegistrationLifecycle`: accept, conflict (`TestPrefixHijack`), unknown identity refused, lease expiry withdraws, restart re-registers, two instances load-balanced, each event audited once (SC-001, SC-005, SC-009) in services/gateway/tests/integration/registration_test.go
- [X] T035 [P] [US1] Fuzz `FuzzRegisterRequest` (arbitrary proto bytes never panic; only valid manifests register) in services/gateway/tests/fuzz/registry_fuzz_test.go

### Implementation for User Story 1

- [X] T036 [US1] Implement `registry` (leases in Valkey with TTL keys + in-memory mirror, allow-list check, conflict detection, instance sets, `Watch` fan-out via pub/sub, snapshot publication to `route`) in services/gateway/internal/registry/{registry.go,valkey.go,memory.go,events.go}
- [X] T037 [US1] Implement `gateway.v1.Registry` server (identity from `authn.FromContext`, audit `registration_*`/`renewal_refused`) in services/gateway/internal/grpcapi/registry.go
- [X] T038 [P] [US1] Implement `httpproxy` (reverse proxy per module over `transport/http.NewClient`, header policy from contracts/forwarding.md, per-route limits, correlation) in services/gateway/internal/proxy/httpproxy/proxy.go
- [X] T039 [P] [US1] Implement `health` (backend probes over the channel, circuit state in Valkey, `module_unhealthy`/`module_recovered` audit) in services/gateway/internal/health/health.go
- [X] T040 [US1] Implement the public dispatcher (edge → route snapshot → public route → httpproxy; unknown → `not_found`; draining/unhealthy → `temporarily_unavailable`) in services/gateway/internal/httpapi/dispatch.go and wire registry/health/proxy into services/gateway/internal/app/app.go
- [X] T041 [P] [US1] Example module `hello-module` (Freya service with HTTP `GET /api/hello` public + `POST /api/hello` protected, gRPC `hello.v1.Hello/Say`, manifest via `pkg/gatewayclient`) in services/gateway/examples/hello-module/{main.go,manifest.go,api/hello.proto} and deploy config services/gateway/deploy/hello.yaml

**Checkpoint**: MVP — a module registers and its public route is reachable through the gateway; quickstart §2 (registration lines) and §7 (leases) pass.

---

## Phase 4: User Story 2 - End Users Reach the Platform Through One Entry Point (Priority: P1)

**Goal**: Identity from sessions (Exchange) and bearer tokens; per-route/method permission enforcement with cached decisions; gRPC and gRPC-web ingress; forwarded token; uniform refusals; auth in gateway mode.

**Independent Test**: quickstart.md §3, §4, §6 — sign-in through the gateway; permission matrix; header injection; token audience; gRPC/gRPC-web calls; revocation within 5 s.

### Tests for User Story 2 (MANDATORY) ⚠️

- [X] T042 [P] [US2] Unit tests for `identity`: session exchange with cache (hash-keyed, TTL, revocation invalidation, sign-out relay), bearer verification (audience `gateway`/absent, expired, revoked, wrong issuer), fail closed when auth is unreachable in services/gateway/internal/identity/identity_test.go
- [X] T043 [P] [US2] Unit tests for `authz` decisions: BatchCheck client with 2 s cache keyed by tenant version, deny on outage, public routes skip identity, permission required per route/method in services/gateway/internal/authz/decide_test.go
- [X] T044 [P] [US2] Unit tests for `grpcproxy`: passthrough unary/server/client/bidi streams with raw codec, metadata allow-list, deadline cap, permission at stream start, cancellation on revocation (FR-025), per-client stream cap in services/gateway/internal/proxy/grpcproxy/proxy_test.go
- [X] T045 [P] [US2] Unit tests for `grpcweb`: framing encode/decode (binary and text), trailers frame, server streaming, client streaming refused, oversized frame refused in services/gateway/internal/proxy/grpcweb/bridge_test.go
- [X] T046 [P] [US2] Fuzz `FuzzGRPCWebFrame`, `FuzzBearerToken`, `FuzzPathNormalize` in services/gateway/tests/fuzz/ingress_fuzz_test.go
- [X] T047 [P] [US2] Unit tests for auth gateway mode (browser API mounted on the Freya HTTP server, edge disabled, CSRF not enforced by auth, `Set-Cookie` still issued, manifest registration loop) in services/auth/internal/app/gatewaymode_test.go
- [X] T048 [US2] Integration `TestPermissionMatrix` (every alpha/beta route and method × user with/without permission, anonymous, public), `TestHeaderInjection`, `TestTokenMatrix` (audience confusion, revoked, expired), `TestErrorHygiene` (SC-002, SC-008) in services/gateway/tests/integration/permissions_test.go
- [X] T049 [US2] Integration `TestSigninThroughGateway` (anonymous → sign-in redirect → return; cookie on the gateway origin; `GET /gateway/v1/me`), `TestGRPCIngress`, `TestGRPCWebBridge`, `TestStreamTermination`, `TestRevocationPropagation` (SC-004), `TestDecisionOutage` (fail closed) in services/gateway/tests/integration/ingress_test.go

### Implementation for User Story 2

- [X] T050 [US2] Implement `identity` (session exchange client over the channel, identity cache in Valkey, `pkg/authclient` verifier with `GRPCKeys`/`GRPCRevocations`, sign-out relay invalidation, `identity_refused` audit) in services/gateway/internal/identity/{identity.go,session.go,bearer.go,cache.go}
- [X] T051 [US2] Implement `authz` decisions (BatchCheck client, decision cache, tenant-version invalidation via auth events, `permission_refused` audit) in services/gateway/internal/authz/decide.go
- [X] T052 [P] [US2] Implement `grpcproxy` (grpc-go server with `UnknownServiceHandler`, raw codec, per-module client conns pinned to registrant identity, metadata policy, deadline/stream caps, revocation-driven cancellation registry) in services/gateway/internal/proxy/grpcproxy/{proxy.go,codec.go,streams.go}
- [X] T053 [P] [US2] Implement `grpcweb` bridge (HTTP/1.1 + HTTP/2 handler, binary/text framing, unary + server streaming over the passthrough client) in services/gateway/internal/proxy/grpcweb/{bridge.go,framing.go}
- [X] T054 [US2] Extend the dispatcher: content-type dispatch (grpc / grpc-web / http), identity resolution, permission check before forwarding, forwarded `Authorization` and header stripping per contracts/forwarding.md, uniform refusals; mount grpc handlers on the edge HTTP/2 server in services/gateway/internal/httpapi/dispatch.go and services/gateway/internal/app/app.go
- [X] T055 [US2] Implement `/gateway/v1/me` and the session-cookie relay rules (only auth module routes receive `Cookie`; `Set-Cookie` allowed only from auth) in services/gateway/internal/httpapi/me.go and services/gateway/internal/proxy/httpproxy/cookies.go
- [X] T056 [US2] Implement auth gateway mode + registration (`config.gateway.enabled`, browser API on the Freya HTTP server, `internal/gatewayreg` manifest with prefixes `/api/v1`, `/authorize`, `/.well-known`, permissions, abilities and nav; `deploy/gateway-mode.yaml`) in services/auth/internal/app/app.go, services/auth/internal/gatewayreg/register.go, services/auth/deploy/gateway-mode.yaml
- [X] T057 [US2] Document the flow in services/gateway/docs/security-model.md (identity, decisions, forwarding, gRPC ingress) and STRIDE from research.md §10

**Checkpoint**: both P1 stories usable together; quickstart §3, §4 and §6 pass.

---

## Phase 5: User Story 3 - The Shell Composes Module User Interfaces (Priority: P2)

**Goal**: Navigation from manifests filtered by permissions; runtime-loaded federated remotes with shared singletons; CASL abilities derived from API permissions and updated live; isolated remote failures; auth console as remote.

**Independent Test**: quickstart.md §3 and §5 — navigation lists only permitted modules; remotes load without reload; breaking `beta`'s remote shows an error card only there; `<Can>` and API agree; ability update ≤ 5 s.

### Tests for User Story 3 (MANDATORY) ⚠️

- [X] T058 [P] [US3] Unit tests for `authz` abilities: rules kept only when `requires` is held, `requires` stripped, packed rules per module, subject collision refused at registration, version bump on registry/tenant changes in services/gateway/internal/authz/abilities_test.go
- [X] T059 [P] [US3] Unit tests for `httpapi` `/gateway/v1/me/modules`, `/me/abilities`, `/events` (SSE), `/m/{module}/*` relay (immutable caching for hashed assets, `mf-manifest.json` no-store, unknown module `not_found`, no path traversal) in services/gateway/internal/httpapi/shell_test.go
- [X] T060 [P] [US3] Shell unit tests (Vitest): federation runtime registers remotes from `/me/modules`, error boundary + retry, navigation filtered/ordered, `Ability` provided to remotes and `update()` on SSE events, sign-out clears every module area in services/gateway/shell/tests/unit/{federation.spec.ts,nav.spec.ts,abilities.spec.ts}
- [X] T061 [P] [US3] Fuzz `FuzzAbilityPack` (packing arbitrary validated rules never panics; unpack round-trips) in services/gateway/tests/fuzz/abilities_fuzz_test.go
- [X] T062 [US3] Integration `TestAbilitiesMatchDecisions` (for every registered ability, UI rule presence == API decision), `TestRemoteOrigins` (assets only from current registrations; withdrawn module's remote 404), `TestShellComposition` (Playwright: three modules, navigation, no reload, isolated failure, axe) in services/gateway/tests/integration/shell_test.go and services/gateway/shell/tests/e2e/composition.spec.ts

### Implementation for User Story 3

- [X] T063 [US3] Implement `authz` abilities builder (per-module CASL rules → BatchCheck → packed rules, versioning) in services/gateway/internal/authz/abilities.go
- [X] T064 [US3] Implement shell API handlers (`/me/modules`, `/me/abilities`, `/events` SSE fed by registry/auth events) and the `/m/{module}/*` remote asset relay in services/gateway/internal/httpapi/{shell_api.go,remotes.go,events.go}
- [X] T065 [P] [US3] Shell host: `module-federation.config.ts` shared singletons, `federation/runtime.ts` dynamic registration + `loadRemote('./routes')` route mounting, `RemoteBoundary.vue` error boundary with retry, navigation builder, `casl/ability.ts` live updates from SSE, `./boot` invocation with `{ability, session, api}` in services/gateway/shell/src/{federation/runtime.ts,components/RemoteBoundary.vue,layouts/Default.vue,casl/ability.ts,router/index.ts}
- [X] T066 [P] [US3] Convert the auth console into remote `auth` (`@module-federation/vite` remote config, exposes `./routes` and `./nav`, shared singletons, keeps standalone mode, `/ui/` served by the auth Freya HTTP server in gateway mode) in services/auth/console/{vite.config.ts,module-federation.config.ts,src/remote/{routes.ts,nav.ts}}
- [X] T067 [P] [US3] Hello module remote (Vite MF remote with a list page using `<Can I="create" a="Hello">`) in services/gateway/examples/hello-module/ui/
- [X] T068 [US3] Module author guide (manifest, permissions vs abilities, remote contract, local dev) in services/gateway/docs/module-guide.md

**Checkpoint**: quickstart §3 and §5 pass with auth + hello remotes composed in the shell.

---

## Phase 6: User Story 4 - Operators Observe and Control Registrations (Priority: P2)

**Goal**: Operations API and UI: registrations with health/traffic, drain/undrain, revoke, allow-list management, gateway audit trail; operator-only.

**Independent Test**: quickstart.md §7 (drain/revoke/audit) — register `alpha`; drain → new requests 503; revoke → renewals refused; audit shows the operator; non-operators refused.

### Tests for User Story 4 (MANDATORY) ⚠️

- [X] T069 [P] [US4] Unit tests for `registry` marks (drain: new requests refused while in-flight complete; undrain; revoke: renewal refused, routes withdrawn) and allow-list changes (add/revoke, effect on next registration) in services/gateway/internal/registry/marks_test.go
- [X] T070 [P] [US4] Unit tests for operations handlers (operator role required; each action audited once with operator identity; reason ≥ 10 chars for revoke; traffic counters) in services/gateway/internal/httpapi/ops_test.go
- [X] T071 [P] [US4] Shell unit tests for the operations views (registrations table, drain confirmation, revoke reason validation, allow-list form) in services/gateway/shell/tests/unit/ops.spec.ts
- [X] T072 [US4] Integration `TestOperatorControls` (drain/undrain/revoke/allow-list end to end, non-operator 403, audit rows) in services/gateway/tests/integration/ops_test.go

### Implementation for User Story 4

- [X] T073 [US4] Implement marks and allow-list management in `registry` + `store` (`module_marks`, `allow_list`) with audit `module_drained`/`module_revoked`/`allowlist_changed` in services/gateway/internal/registry/marks.go and services/gateway/internal/store/repos.go
- [X] T074 [US4] Implement operations handlers `/gateway/v1/ops/*` (registrations with health/traffic from Valkey counters, drain/undrain/revoke, allow-list, audit query) in services/gateway/internal/httpapi/ops.go and per-module traffic counters in services/gateway/internal/httpapi/metrics.go
- [X] T075 [P] [US4] Operations views in the shell (`/ops/registrations`, `/ops/allowlist`, `/ops/audit`; operator-only route guards) in services/gateway/shell/src/views/ops/{Registrations.vue,Allowlist.vue,Audit.vue}
- [X] T076 [US4] Operations documentation (bootstrap, allow-list, drain/revoke runbooks, Valkey loss behaviour, key/identity rotation) in services/gateway/docs/operations.md

**Checkpoint**: quickstart §7 (operator part) passes.

---

## Phase 7: User Story 5 - The Platform Degrades Gracefully (Priority: P3)

**Goal**: Bounded waits, circuit breaking with automatic recovery, per-origin/per-route/per-client limits, uniform outage messaging in the shell.

**Independent Test**: quickstart.md §7 (resilience) and §8 — hang `beta`; requests fail within the bound; `beta` bypassed for a cool-down; `alpha` unaffected; recovery automatic; bursts refused with `Retry-After`.

### Tests for User Story 5 (MANDATORY) ⚠️

- [X] T077 [P] [US5] Unit tests for circuit breaking in `health`/dispatcher (timeouts → unhealthy after threshold, open state fails fast, half-open probe, recovery audit) in services/gateway/internal/health/circuit_test.go
- [X] T078 [P] [US5] Unit tests for limits (per-origin and per-route buckets at the edge config, per-client stream caps, `payload_too_large`, `Retry-After`) in services/gateway/internal/httpapi/limits_test.go
- [X] T079 [US5] Integration `TestDegradation` (hanging module bounded, isolation of other modules, automatic recovery, shell outage card via Playwright) and `TestHardening` (oversized bodies/headers, TLS 1.2 and plaintext refused, spoofed `X-Forwarded-For`, security headers on every route class) in services/gateway/tests/integration/resilience_test.go and services/gateway/shell/tests/e2e/outage.spec.ts
- [X] T080 [P] [US5] Benchmark `BenchmarkForward` (p95 overhead < 10 ms at 1,000 concurrency, SC-003) in services/gateway/tests/integration/perf_bench_test.go with the gate in services/gateway/scripts/perf-gate.sh

### Implementation for User Story 5

- [X] T081 [US5] Implement circuit breaking and bounded forwarding (per-module timeout, failure threshold, cool-down, half-open probes; `temporarily_unavailable` fast path) in services/gateway/internal/health/circuit.go and services/gateway/internal/httpapi/dispatch.go
- [X] T082 [P] [US5] Wire edge rate limits per route class and per-client stream/body limits from config in services/gateway/internal/app/app.go and services/gateway/internal/proxy/grpcproxy/streams.go
- [X] T083 [P] [US5] Shell outage handling per module (card with retry, SSE `unhealthy`/`recovered` events, global outage page when the gateway API itself is down) in services/gateway/shell/src/{components/RemoteBoundary.vue,stores/registry.ts}

**Checkpoint**: all five stories independently testable; quickstart §2–§8 pass.

---

## Phase N: Polish & Cross-Cutting Concerns

- [X] T084 [P] Playwright e2e + axe suite across sign-in through the gateway, shell composition, operations screens (SC-010) in services/gateway/shell/tests/e2e/*.spec.ts and services/gateway/shell/playwright.config.ts
- [X] T085 [P] Redaction scan (logs, gateway audit details, error bodies, forwarded headers captured by test modules) in services/gateway/tests/integration/redaction_scan_test.go and services/gateway/scripts/redaction-scan.sh
- [X] T086 [P] Documentation: services/gateway/README.md (overview, run, move-to-own-repo), finalize docs/security-model.md, docs/operations.md, docs/module-guide.md; root README.md section and CHANGELOG.md entries (`transport/http.NewClient`, `services/gateway`, auth gateway mode + RPCs)
- [X] T087 Constitution compliance review recorded in specs/003-application-gateway/checklists/constitution-review.md
- [X] T088 Verify coverage thresholds (`make cover` at root incl. `transport/http`; `make -C services/gateway cover` ≥ 80 % overall, 100 % for internal/{authz,route,identity,manifest}); fix gaps
- [X] T089 Run `gosec`, `staticcheck`, `govulncheck`, `go mod verify` for both modules and `npm audit` for shell + auth console; update services/gateway/docs/dependencies.md
- [X] T090 Run quickstart.md §1–§8 on a clean checkout and record results in specs/003-application-gateway/quickstart-results.md
- [X] T091 Code cleanup and refactoring pass (no behaviour change; tests stay green) across services/gateway and the auth changes

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: no dependencies
- **Foundational (Phase 2)**: depends on Setup — BLOCKS all user stories; T018 (framework client) and T024 (auth RPCs) can proceed in parallel with the gateway packages
- **US1 (P1)**: depends on Foundational — MVP (registration + public forwarding)
- **US2 (P1)**: depends on US1 (route table, forwarding) and T024 (Exchange)
- **US3 (P2)**: depends on US2 (identity, decisions) for abilities; remote loading itself only needs US1
- **US4 (P2)**: depends on US1; the operations UI needs the shell foundation (T029)
- **US5 (P3)**: depends on US1 (dispatcher, health); the shell outage handling needs US3's boundary
- **Polish**: after all desired stories

### User Story Dependencies

- **US1** → foundation only
- **US2** → US1
- **US3** → US1 (+ US2 for abilities)
- **US4** → US1
- **US5** → US1 (+ US3 for the UI part)

### Within Each User Story

- Tests MUST be written and FAIL before implementation (Constitution Principle IV)
- Domain packages before handlers; handlers before shell views; wiring last
- Unit → contract → integration order when running

### Parallel Opportunities

- Setup: T003–T007 in parallel after T001–T002
- Foundational tests T008–T017 all parallel; implementations T019–T021, T023, T024, T026, T028–T030 parallel; T018 (framework) parallel with the service; T022 → T025 → T027 sequential
- US1: T031–T033, T035 parallel; T038, T039, T041 parallel with T036–T037; T040 last
- US2: T042–T047 parallel; T052, T053 parallel with T050–T051; T054–T056 sequential
- After US2: US3, US4 and US5 can be worked concurrently by different developers

---

## Parallel Example: User Story 2

```bash
# Launch all US2 tests together:
Task: "Unit tests for identity in services/gateway/internal/identity/identity_test.go"
Task: "Unit tests for decisions in services/gateway/internal/authz/decide_test.go"
Task: "Unit tests for grpcproxy in services/gateway/internal/proxy/grpcproxy/proxy_test.go"
Task: "Unit tests for grpcweb in services/gateway/internal/proxy/grpcweb/bridge_test.go"
Task: "Fuzz targets in services/gateway/tests/fuzz/ingress_fuzz_test.go"
Task: "Auth gateway mode tests in services/auth/internal/app/gatewaymode_test.go"

# Then implement in parallel where files differ:
Task: "Implement identity in services/gateway/internal/identity/"
Task: "Implement grpcproxy in services/gateway/internal/proxy/grpcproxy/"
Task: "Implement grpcweb in services/gateway/internal/proxy/grpcweb/"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Phase 1 Setup (T001–T007)
2. Phase 2 Foundational (T008–T030) — includes `transport/http.NewClient` and the auth RPCs
3. Phase 3 US1 (T031–T041)
4. **STOP and VALIDATE**: a module registers, its public route is served through the gateway, leases expire and recover (quickstart §2 and §7 lease part)

### Incremental Delivery

1. Setup + Foundational → gateway boots, empty shell, auth in gateway mode
2. US1 → MVP (registration, public forwarding, health)
3. US2 → single entry point with identity and permissions, gRPC/gRPC-web ingress
4. US3 → composed shell with CASL abilities; auth console as a remote
5. US4 + US5 in parallel → operations; resilience and limits
6. Polish → e2e/axe, redaction scan, docs, compliance review, coverage and tooling gates

### Parallel Team Strategy

1. One developer takes `transport/http.NewClient` + auth RPCs/gateway mode while another builds the gateway foundation
2. After US1: developer A → US2 ingress (identity, decisions, gRPC), developer B → US3 shell/federation, developer C → US4 operations; US5 once the dispatcher is stable
3. Module teams can start against `pkg/gatewayclient` and `docs/module-guide.md` as soon as US1 lands
