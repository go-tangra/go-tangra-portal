# Implementation Plan: KVM Console on a Separate Origin (port 8444)

**Branch**: `025-kvm-console-origin` | **Date**: 2026-09-28 | **Spec**: [spec.md](spec.md)

## Summary

The framework edge gains a validated `FrameSources` list so the portal shell
may frame one extra origin. The gateway gains an optional **console
listener** (`console:` config) on port 8444: TLS 1.3, HTTP/1.1, the edge's
certificate, serving only configured prefixes (`/bmc/` → `ipam`) and
forwarding them — including WebSocket upgrades — to the module's registered
backend over the pinned mesh client. It forwards only allow-listed cookies,
relays only allow-listed `Set-Cookie`, drops credentials and spoofable
headers and answers with a console CSP whose `frame-ancestors` is the portal
origin. IPAM gains `kvm.console_origin` (absolute console URLs), a
single-use start token exchanged for a device-scoped console session cookie
(`kvm.session_seconds`), a WebSocket `Origin` check and stricter BMC cookie
handling; its UI frames only absolute https console URLs. go-tangra-docker
publishes 8444 and wires the configuration.

## Technical Context

**Language/Version**: Go 1.26 (framework, gateway, ipam), TypeScript/Vue 3 (ipam UI)

**Primary Dependencies**: no new modules. Gateway: stdlib `net/http`,
`net/http/httputil`, `crypto/tls`; framework `transport/http` (mesh client),
`transport/edge`. IPAM: existing `gorilla/websocket`.

**Storage**: none (IPAM console tokens/sessions stay in memory)

**Testing**: `go test -race`; framework edge header tests; gateway console
package tests with an in-process TLS listener, a fake registry and a fake
module (HTTP + WebSocket echo) — negative: 404 outside prefixes, traversal,
inactive module 503, portal cookies stripped, `__Host-*` Set-Cookie dropped,
spoofed forwarding headers dropped, TLS 1.2 refused, over-limit 503/413,
session_max closes the WebSocket; gateway config validation table; app-level
test wiring console + edge frame source; IPAM kvm tests (absolute URL,
single-use token, session cookie attributes, session outlives token TTL,
Origin check, BMC Set-Cookie dropped, browser cookie never reaches BMC);
ipam config validation; vitest for the tab (absolute → iframe, relative →
explanation)

**Target Platform**: Linux containers (freya-stack / production compose)

**Project Type**: framework + gateway + module + deployment

**Constraints**: portal CSP unchanged without frame sources (SC-003); coverage
gates unchanged (portal: `internal/authz`, `internal/route`,
`internal/identity`, `internal/manifest` 100 %; new `internal/console` held
to 100 % as a security package; ipam: existing 100 % list; total ≥ 80 %);
`make vuln` clean.

**Scale/Scope**: one new gateway package (~400 lines), one framework field,
one ipam config key, ~6 ipam behaviour changes, one UI state.

## Constitution Check

*Checked before Phase 0 and after Phase 1 design — all PASS.*

- [x] **I. Secure by Default**: console listener off by default; frame
      sources empty by default (portal CSP unchanged); enabling requires a
      real certificate (no self-signed fallback) and an origin distinct from
      the portal and absent from `allowed_origins`; IPAM without a console
      origin keeps today's relative URL and the UI refuses to frame it.
- [x] **II. Zero Trust**: the listener authenticates nobody and trusts
      nothing from the client; access is the module's single-use token →
      console session; forwarding uses the SPIFFE-pinned mesh client and the
      module's existing policy rule (`gateway-forwards`).
- [x] **III. Boundary Validation**: typed config validated at startup
      (origins, prefixes, module names, cookie names, limits);
      `route.Normalize` on every path; cookie/header allow-lists in both
      directions; IPAM validates `console_origin`; UI checks the URL scheme.
- [x] **IV. Test-First**: tests listed first in every phase; negative tests
      enumerated; `internal/console` at 100 %.
- [x] **V. Observability**: console forwards recorded in the gateway traffic
      view (per module); IPAM keeps the `kvm_session_started` audit row and
      logs refused console requests (without token values).
- [x] **VI. Supply Chain**: no new dependency; `make vuln` in every repo.
- [x] **VII. Simplicity**: one listener, one route map, one frame-source
      list; no new service or container.
- [x] **Threat Model**: STRIDE in [research.md](research.md#stride-threat-model).

## Project Structure

### Documentation

```text
go-tangra-portal-v4/specs/025-kvm-console-origin/
├── spec.md  plan.md  research.md  data-model.md  quickstart.md
├── contracts/{edge-frame-sources.md,console-listener.md,ipam-kvm.md}
├── checklists/requirements.md
└── tasks.md
```

### Source Code

```text
go-tangra (framework, branch 025-kvm-console-origin)
  transport/edge/server.go         # Config.FrameSources + validation in NewServer
  transport/edge/headers.go        # frame-src when configured
  transport/edge/server_test.go    # header + validation tests
  CHANGELOG.md, docs/configuration.md
  deploy/stack/{compose.yaml,configs/gateway.yaml,configs/ipam.yaml}
go-tangra-portal-v4 (branch 025-kvm-console-origin)
  internal/config/config.go(+_test)  # Console section, Edge.FrameSources, validation
  internal/console/                  # NEW: handler.go (forwarding, policy), server.go (TLS listener), tests
  internal/app/app.go                # wiring; console origin → edge frame sources
  README.md / docs/operations.md     # console listener
  go.mod                             # TEMP replace go-tangra => ../go-tangra (last commit)
go-tangra-ipam-v4 (branch 025-kvm-console-origin)
  internal/config/config.go(+_test)  # kvm.console_origin
  internal/kvm/kvm.go(+_test)        # options, absolute URL, token → session, Origin, cookies
  internal/app/app.go                # wiring
  ui/src/views/devices/ipmi-kvm.vue, ui/tests/unit/bmc.spec.ts
  README.md
go-tangra-docker (branch v4, local commit)
  docker-compose.yaml.example, docker-compose.production.yaml.example
  configs/gateway.yaml, configs/ipam.yaml
  scripts/prod-init.sh, PRODUCTION.md, .env.example
```

## Rollout (user-confirmed steps)

1. **go-tangra v4.2.2** — merge, tag (`v4.2.2`).
2. **portal v4.4.0** — replace the TEMP `replace` with
   `github.com/go-tangra/go-tangra/v4 v4.2.2`, merge, tag, image.
3. **ipam v4.8.0** — merge, tag, image (independent of 1–2; without the
   gateway console the UI explains "not configured").
4. **go-tangra-docker** — bump `GATEWAY_IMAGE`/`IPAM_IMAGE`, push v4.
5. **Production** — add the `console:` section to `prod/configs/gateway.yaml`
   and `kvm.console_origin` to `prod/configs/ipam.yaml` (or re-run
   `prod-init.sh` with `FORCE=1`), publish 8444 (`CONSOLE_PORT`), open
   8444/tcp in the firewall, restart gateway and ipam.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| A second public listener in the gateway | Vendor JS must not share the portal origin (D1) | Relaxing the portal CSP exposes the session; a separate proxy container is more to deploy and secure |
| Console listener not built on `edge.Server` | Edge CSRF, deadline and headers break BMC consoles (D3) | A framework "console mode" widens the framework API for one consumer |
