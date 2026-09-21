# services/gateway — application gateway

The only public listener of the platform. Modules stay private on the Freya
channel, register their routes, gRPC methods, API permissions and CASL
abilities with the gateway, and ship their user interface as a Module
Federation remote that the gateway's shell composes.

- Specification: `specs/003-application-gateway/` (spec, plan, research,
  contracts, quickstart, tasks).
- Security model: `docs/security-model.md`. Operations: `docs/operations.md`.
  Module authors: `docs/module-guide.md`. Dependencies: `docs/dependencies.md`.

## Layout

| Path | Purpose |
|------|---------|
| `cmd/gatewaysvc` | binary (`bootstrap` seeds the allow-list) |
| `api/proto/gateway/v1` | `gateway.v1.Registry` (Register / Renew / Deregister / Watch) |
| `api/openapi/gateway.yaml` | shell and operations API under `/gateway/v1` |
| `api/schema/manifest.schema.json` | module manifest contract |
| `internal/registry` | registrations, leases, marks, allow-list, route snapshot |
| `internal/httpapi` | edge handler: dispatcher, shell/ops API, SSE, remote relay |
| `internal/identity`, `internal/authz` | session exchange / bearer verification; permission decisions and CASL abilities |
| `internal/proxy/{httpproxy,grpcproxy,grpcweb}` | forwarding over the pinned mTLS channel |
| `internal/health` | probes and circuit breaking |
| `pkg/gatewayclient` | module SDK (manifest builder, registration loop) |
| `shell/` | Vite + Vue + Vuetify Module Federation host |
| `examples/hello-module` | smallest complete module (API + remote UI) |

## Run locally

```bash
make testca                                   # repository root: dev CA + SVIDs (auth, gateway, hello, …)
cd services/gateway && make compose-up        # TimescaleDB, Valkey, OpenFGA, Mailpit
(cd ../auth && go build -tags console -o bin/authsvc ./cmd/authsvc && \
  ./bin/authsvc bootstrap -config deploy/gateway-mode.yaml -operator-email ops@example.org && \
  ./bin/authsvc -config deploy/gateway-mode.yaml &)
go run ./cmd/gatewaysvc bootstrap -config deploy/dev.yaml \
  -allow "spiffe://example.org/svc/auth=/api/v1,/authorize,/.well-known,/console;auth" \
  -allow "spiffe://example.org/svc/hello=/api/hello;hello"
(cd shell && npm install && npm run build) && go run -tags shell ./cmd/gatewaysvc -config deploy/dev.yaml &
(cd examples/hello-module/ui && npm install && npm run build) && go run -tags ui ./examples/hello-module -config deploy/hello.yaml &
open https://localhost:8443/
```

Build the auth console standalone and as a remote first (`cd ../auth/console &&
npm run build && npm run build:remote`).

## Verify

```bash
make test            # unit + contract
make cover           # coverage gate (≥ 80 %, 100 % for the security packages)
make test-integration   # testcontainers: gateway + auth (subprocess) + test modules
make fuzz            # fuzz targets
make lint vuln       # staticcheck/gosec, govulncheck
make redaction-scan  # no secrets in logs, audit details, error bodies
make perf-gate       # BenchmarkForward p95 overhead
(cd shell && npm run test:unit && npm run lint && npm run build)
```

## Moving to its own repository

The service depends on the framework (`github.com/go-freya/freya`) and on the
auth module's public API (`services/auth/api/proto`, `pkg/authclient`,
`pkg/authmanifest`); both are consumed through `replace` directives in
`go.mod` that become versioned requirements once published. The integration
harness builds the auth service from source (`../auth`); point
`tests/integration` at a released `authsvc` binary instead. The shell and the
example UI are self-contained npm projects.
