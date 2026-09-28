---

description: "Task list for 025 KVM console on a separate origin (port 8444)"
---

# Tasks: KVM Console on a Separate Origin (port 8444)

**Input**: Design documents from `specs/025-kvm-console-origin/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: MANDATORY (Constitution IV). In every phase the tests are listed
first and must be written and seen failing before the implementation tasks.
Negative security tests are listed explicitly.

**Paths**: relative to go-tangra-portal-v4 unless prefixed with
`fw:` (go-tangra, branch `025-kvm-console-origin`), `ipam:`
(go-tangra-ipam-v4, branch `025-kvm-console-origin`) or `docker:`
(go-tangra-docker, branch `v4`, local commit only).

**Release tasks** (tags, PR merges, image pins, production) require explicit
user confirmation and are left open.

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup

- [x] T001 Create branch `025-kvm-console-origin` in go-tangra, go-tangra-portal-v4 and go-tangra-ipam-v4 (docker stays on `v4`)
- [x] T002 [P] Add `internal/console` to the 100 % list in `scripts/coverage-gate.sh`

---

## Phase 2: Foundational — framework frame sources (blocks US1)

### Tests first

- [x] T003 [P] fw: `transport/edge/server_test.go` — `TestFrameSources`: default CSP identical to v4.2.1 (no `frame-src`); configured `https://h:8444` and `https://kvm.example.com/` → `frame-src 'self' https://h:8444 https://kvm.example.com` before `frame-ancestors 'none'`; `X-Frame-Options: DENY` and `frame-ancestors 'none'` unchanged; **negative**: `http://h`, `https://h/path`, `https://h?q`, `https://u@h`, `*`, `https://h; script-src *`, `https://h'`, empty string, `https://` → `NewServer` error

### Implementation

- [x] T004 fw: `Config.FrameSources` + `validFrameSource` in `transport/edge/server.go`; emit in `transport/edge/headers.go` (T003)
- [x] T005 [P] fw: CHANGELOG `4.2.2` entry and `docs/configuration.md` (edge frame sources)
- [x] T006 TEMP commit in the portal: `replace github.com/go-tangra/go-tangra/v4 => ../go-tangra` (last commit on the branch; removed at release, T040). Until then, commits before it build only with the local framework (the untracked `go.work` or the TEMP replace)

**Checkpoint**: the portal builds against the local framework with the new field.

---

## Phase 3: User Story 1 — Open a device's KVM console (P1) 🎯 MVP

**Goal**: the console loads in the portal iframe from `https://<host>:8444` and its WebSocket connects.

### Tests first

- [x] T007 [P] [US1] `internal/config/config_test.go`: `console` defaults (disabled, `:8444`, `/bmc/`→`ipam`, cookies `freya_kvm`, 1 h, 64); YAML load of the section and `edge.frame_sources`; `FrameSources()` = edge list + console origin when enabled; **negative**: enabled without `public_origin`, non-https origin, origin with path, origin equal to `public_origin`, origin in `edge.allowed_origins`, missing edge cert/key, prefix `/`, prefix without trailing `/`, prefix under `/api/`, `/gateway/`, `/m/`, prefix with bad chars, empty module, bad module chars, cookie `__Host-session`, invalid cookie name, `session_max` 0 / > 24 h, `max_concurrent` 0 / > 10000, invalid `edge.frame_sources` entry
- [x] T008 [P] [US1] `internal/console/handler_test.go` forwarding: path + query forwarded unchanged to the module backend of the matching prefix over the injected transport; response relayed; `X-Request-Id`, `X-Forwarded-Proto/Host`, `X-Gateway-Module` set; WebSocket upgrade relayed both directions (echo); module inactive / unknown / no backend → 503; backend build error → 503; transport error → 503; deadline → 504; body over limit → 413
- [x] T009 [P] [US1] `internal/console/server_test.go`: TLS 1.3 only (TLS 1.2 client refused), ALPN `http/1.1`, serves the handler, certificate reload picks up a new file, Start/Stop, bad cert path → error
- [x] T010 [P] [US1] ipam: `internal/config/config_test.go` — `kvm.console_origin` accepted (https origin, trailing `/` trimmed) and **negative**: `http://`, path, query, user info, garbage → validation error
- [x] T011 [P] [US1] ipam: `internal/kvm/kvm_test.go` — `StartSession` returns `<origin>/bmc/<id>/?kvmtoken=` with `WithConsoleOrigin`, relative without; first token use sets `freya_kvm` with `Path=/bmc/<id>/`, `Secure`, `HttpOnly`, `SameSite=Strict`, `Max-Age=session`; the cookie keeps working after the token TTL and fails after the session TTL; WebSocket relayed with the session cookie and matching `Origin`

### Implementation

- [x] T012 [US1] `internal/config/config.go`: `Console` section, `Edge.FrameSources`, validation, `FrameSources()` (T007)
- [x] T013 [US1] `internal/console/handler.go`: prefix match on normalised path, registry resolution (active + healthy, round robin), per-backend reverse proxy on a `TransportFactory` (mesh client), request/response header policy, console headers, limits (T008)
- [x] T014 [US1] `internal/console/server.go`: TLS 1.3 / HTTP/1.1 listener with the edge certificate, reload loop, `transport.Server` (T009)
- [x] T015 [US1] `internal/app/app.go`: edge `FrameSources` from config; build and add the console server when enabled (mesh client per module identity, traffic record)
- [x] T016 [US1] ipam: `internal/config/config.go` `KVM.ConsoleOrigin` + validation + `KVMConsoleOrigin()` (T010)
- [x] T017 [US1] ipam: `internal/kvm/kvm.go` options `WithConsoleOrigin`, `WithConsoleSessionTTL`; absolute URL; token → console session exchange; cookie attributes (T011)
- [x] T018 [US1] ipam: `internal/app/app.go` passes console origin and `KVMSession()` to the manager

**Checkpoint**: console URL absolute, listener forwards `/bmc/` incl. WebSocket, console session lasts `session_seconds`.

---

## Phase 4: User Story 2 — Nothing but consoles on the console origin (P1)

### Tests first

- [x] T019 [P] [US2] `internal/console/handler_test.go` **negative**: `/`, `/api/ipam/v1/devices`, `/gateway/v1/me`, `/m/ipam/x.js`, `/bmcx`, `/bmc/../api/`, `/bmc//x`, `%2e%2e` → 404 and zero module calls; portal cookies (`__Host-session`, `__Host-csrf`, `other`) removed, `freya_kvm` kept, `Cookie` absent when nothing allowed; `Authorization`, `Proxy-Authorization`, `Forwarded`, `X-Forwarded-For`, `X-Real-IP`, `X-Freya-Identity`, `X-Gateway-Client`, `X-CSP-Nonce` never reach the module; module `Set-Cookie: __Host-session=…` / `__Host-csrf` / `other` dropped, `freya_kvm` kept; module CSP / XFO / HSTS / COOP / COEP / CORP / Cache-Control replaced; console CSP has `frame-ancestors <portal origin>`, `unsafe-eval`, `wss://<console host>`, no `X-Frame-Options`; 404 responses carry the console headers; concurrency cap → 503; WebSocket closed at `session_max`
- [x] T020 [P] [US2] ipam: `internal/kvm/kvm_test.go` **negative**: replayed start token → 403; token for another device → 403 and not consumed; session cookie on another device path → 403; expired session → 403; WebSocket with foreign `Origin` → 403 when a console origin is configured; BMC `Set-Cookie` never reaches the browser; browser `freya_kvm` and other cookies never reach the BMC (only `SID=`); `Origin` to the BMC rewritten to the BMC origin
- [x] T021 [P] [US2] `internal/app` wiring test (`console_test.go`, no Docker): with the console enabled the edge CSP carries `frame-src 'self' <console origin>`; disabled → no `frame-src` (SC-003)

### Implementation

- [x] T022 [US2] Complete the header/cookie policy in `internal/console/handler.go` (T019)
- [x] T023 [US2] ipam: `internal/kvm/kvm.go` WebSocket `Origin` check, upstream `Set-Cookie` drop, `Cookie` always replaced, `Origin` rewrite, refusal log without token (T020)

**Checkpoint**: SR-001…SR-005 proven by tests.

---

## Phase 5: User Story 3 — Clear state without a console origin (P2)

### Tests first

- [x] T024 [P] [US3] ipam: `ui/tests/unit/bmc.spec.ts` — absolute https `console_url` → iframe with that `src`, `referrerpolicy="no-referrer"`; relative `console_url` → `data-test=kvm-no-origin` "KVM console origin not configured" and no iframe; `http:`/`javascript:` URL → same explanation

### Implementation

- [x] T025 [US3] ipam: `ui/src/views/devices/ipmi-kvm.vue` (T024)

---

## Phase 6: Deployment configuration

- [x] T026 [P] docker: `docker-compose.yaml.example` and `docker-compose.production.yaml.example` publish `${CONSOLE_BIND}:${CONSOLE_PORT:-8444}:8444` on the gateway
- [x] T027 [P] docker: `configs/gateway.yaml` `console:` section; `configs/ipam.yaml` `kvm.console_origin: https://localhost:8444`
- [x] T028 docker: `scripts/prod-init.sh` rewrites `https://localhost:8444` to `https://<PUBLIC_HOST>:<CONSOLE_PORT>` (new input `CONSOLE_PORT`, default 8444), leftovers check includes `localhost:8444`; `.env.example` documents `CONSOLE_PORT`/`CONSOLE_BIND`
- [x] T029 docker: `PRODUCTION.md` — port table (8444 browser-facing when the console is enabled), firewall, certificate reuse, distinct-host option, upgrade steps for an existing `prod/configs`
- [x] T030 [P] fw: `deploy/stack/compose.yaml` publishes 8444; `deploy/stack/configs/gateway.yaml` console section; `deploy/stack/configs/ipam.yaml` `console_origin`

---

## Phase 7: Polish & cross-cutting

- [x] T031 [P] Portal `docs/operations.md` + `docs/security-model.md`: console listener, headers, cookie policy, same-host analysis
- [x] T032 [P] ipam `README.md`: `kvm.console_origin`, session semantics
- [x] T033 fw quality gates: `go vet`, `go test -race ./...`, `make cover`, `make vuln`
- [x] T034 portal quality gates: `go vet`, `go test -race ./...`, `make cover` (incl. `internal/console` 100 %), `make vuln`, `make test-integration`
- [x] T035 ipam quality gates: `go vet`, `go test -race ./...`, `make cover`, `make vuln`, `make test-integration`, UI lint/unit/build
- [x] T036 Security review against research.md STRIDE (cookie allow-lists both ways, path handling, Origin check, CSP) — findings fixed or recorded
- [x] T037 Update spec status and this task list
- [x] T037a [US1] `internal/console/mesh_test.go`: WebSocket relayed over the real mTLS mesh (gateway client ALPN h2 → module `thttp` server hijack) — added during the security review (T036)
- [x] T037b [US2] Security review fix: only `Upgrade: websocket` is relayed (`400 unsupported_upgrade` otherwise)

---

## Phase 8: Release (user confirmation required — NOT executed)

- [ ] T038 fw: PR `025-kvm-console-origin` → `main`, tag `v4.2.2`
- [ ] T039 ipam: PR → `main`, tag `v4.8.0`, image `ghcr.io/go-tangra/go-tangra-ipam:4.8.0`
- [ ] T040 portal: drop the TEMP replace, `go get github.com/go-tangra/go-tangra/v4@v4.2.2`, PR → `main`, tag `v4.4.0`, image
- [ ] T041 docker: bump `GATEWAY_IMAGE=4.4.0`, `IPAM_IMAGE=4.8.0`, push `v4`
- [ ] T042 production: console section in `prod/configs/gateway.yaml`, `kvm.console_origin` in `prod/configs/ipam.yaml`, `CONSOLE_PORT` in `.env`, firewall 8444/tcp, `docker compose up -d gateway ipam`; verify in the browser (node-1 → Power / KVM → Start session)

## Dependencies

- Phase 2 → US1 (portal needs `FrameSources`); ipam tasks (T010, T011, T016–T018, T020, T023–T025) are independent of the framework and the portal.
- US2 extends US1's handler; US3 needs only the ipam UI.
- Release order: T038 → T040; T039 any time; T041 after T039 + T040; T042 last.
