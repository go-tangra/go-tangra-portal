# go-tangra-portal

The application gateway of the [go-tangra v4 platform](https://github.com/go-tangra/go-tangra):
the platform's edge, its module registry and the shell UI.

- **Edge.** The gateway is the only public listener. Browsers and API clients talk to it;
  it verifies sessions and bearer tokens with the auth service, decides permissions, and
  forwards HTTP, gRPC and gRPC-Web calls to modules over their pinned mTLS channel.
- **Module registry.** Modules stay private. They register their routes, gRPC methods,
  API permissions and CASL abilities with `gateway.v1.Registry` (Register / Renew /
  Deregister / Watch) under a lease, and only SPIFFE identities on the allow-list may do so.
- **Shell UI.** The gateway embeds the Vue 3 + FlyonUI Module Federation host (`shell/`,
  built on `@go-tangra/ui`), which composes every registered module's UI remote.

Security model: [`docs/security-model.md`](docs/security-model.md).
Operations: [`docs/operations.md`](docs/operations.md).
Module authors: [`docs/module-guide.md`](docs/module-guide.md).
Dependencies: [`docs/dependencies.md`](docs/dependencies.md).
Design history: `specs/003-application-gateway`.

> v4.0.0 replaces the v3 go-tangra portal with this gateway. The v3 portal stays on the
> `v3` branch and its `v3.x` tags (and images).

## Place in the platform

```
go-tangra/go-tangra          platform module + @go-tangra/ui kit
        |
go-tangra-auth  <---->  go-tangra-portal (gateway)  <---->  go-tangra-lcm
                                  ^
        warden, inventory, notification, paperless, deployer, ipam, ticket, asset, dns
        (register through the portal sdk and ship their UI as federated remotes)
```

- Built on `github.com/go-tangra/go-tangra/v4` (mTLS transports, identity, service
  policy, audit, observability).
- Exchanges sessions and verifies tokens through the auth SDK
  (`github.com/go-tangra/go-tangra-auth/sdk/v4`).
- Enrolls for its own SVID with lcm (`github.com/go-tangra/go-tangra-lcm/sdk/v4`).

## Modules in this repository

| Module | Path | Consumers |
|---|---|---|
| `github.com/go-tangra/go-tangra-portal/v4` | `/` | the gateway (`cmd/gatewaysvc`) and `examples/hello-module` |
| `github.com/go-tangra/go-tangra-portal/sdk/v4` | `sdk/` | every module: the `gateway.v1` protobuf API, the manifest schema and `pkg/gatewayclient` (manifest builder, registration loop) |

The gateway builds against the in-repo SDK through
`replace github.com/go-tangra/go-tangra-portal/sdk/v4 => ./sdk`. Modules use the
SDK's published `sdk/vX.Y.Z` tag.

## Layout

| Path | Purpose |
|------|---------|
| `cmd/gatewaysvc` | binary (serve, `bootstrap` seeds the allow-list, `version`) |
| `internal/registry` | registrations, leases, marks, allow-list, route snapshot |
| `internal/httpapi` | edge handler: dispatcher, shell/ops API, SSE, remote relay |
| `internal/identity`, `internal/authz` | session exchange / bearer verification; permission decisions and CASL abilities |
| `internal/proxy/{httpproxy,grpcproxy,grpcweb}` | forwarding over the pinned mTLS channel |
| `internal/health` | probes and circuit breaking |
| `api/openapi/gateway.yaml` | shell and operations API under `/gateway/v1` |
| `sdk/api/proto/gateway/v1`, `sdk/api/schema` | registry API and module manifest contract |
| `shell/` | Module Federation host, embedded with `-tags shell` |
| `examples/hello-module` | smallest complete module (API + remote UI) |
| `deploy` | development compose stack, dev configuration, allow-list policies |
| `tests/{contract,fuzz,integration}` | contract, fuzz and Docker-backed integration suites |

## Build and test

You need Go 1.26, Node 22, Docker (for integration tests and the image), `buf`, and a
GitHub token with `read:packages` to install `@go-tangra/ui` from GitHub Packages.

```bash
go build ./... && go vet ./... && go test -race ./...
(cd sdk && go vet ./... && go test -race ./...)
for d in sdk examples/hello-module internal/proxy/grpcproxy/echov1; do (cd $d && buf lint); done
make test-integration                     # -tags integration, needs Docker and a go-tangra-auth checkout
make lint cover fuzz redaction-scan perf-gate vuln

cd shell
export NODE_AUTH_TOKEN=$(gh auth token)   # shell/.npmrc only references this variable
npm ci && npm run lint && npm run test:unit && npm run build
```

The integration harness runs the auth service as a subprocess. It builds `authsvc` from
a go-tangra-auth checkout: `../go-tangra-auth` next to this repository by default, or the
directory named by `GO_TANGRA_AUTH_DIR`.

The unit coverage gate requires at least 80 % overall and 100 % for the security
packages. Generated code, SQL bindings and wiring are covered by the integration suite.

## Run locally

`deploy/dev.yaml` reads its SVID from `../../.dev/ca`. Create a throw-away CA there with
the platform's development CA tool:

```bash
go run github.com/go-tangra/go-tangra/v4/cmd/freya-devca@v4.0.0 \
  -out ../../.dev/ca -trust-domain example.org -services gateway,auth,hello
make compose-up                           # TimescaleDB, Valkey, OpenFGA, Mailpit
# in a go-tangra-auth checkout: authsvc bootstrap and serve with -config deploy/gateway-mode.yaml, then:
go run ./cmd/gatewaysvc bootstrap -config deploy/dev.yaml \
  -allow "spiffe://example.org/svc/auth=/api/v1,/authorize,/.well-known,/console;auth" \
  -allow "spiffe://example.org/svc/hello=/api/hello;hello"
(cd shell && npm ci && npm run build) && go run -tags shell ./cmd/gatewaysvc -config deploy/dev.yaml &
(cd examples/hello-module/ui && npm ci && npm run build) && go run -tags ui ./examples/hello-module -config deploy/hello.yaml &
open https://localhost:8443/
```

The full platform stack (every service, lcm-issued identities) lives in the platform
repository under `deploy/stack`.

## Container image

The image is `ghcr.io/go-tangra/go-tangra-portal`, built by `.github/workflows/ci.yaml`.
It carries `gatewaysvc` with the embedded shell.

```bash
docker buildx build --secret id=npm_token,env=NODE_AUTH_TOKEN \
  --build-arg APP_VERSION=4.0.0 -t go-tangra-portal:dev .
docker run --rm go-tangra-portal:dev version
```

The image runs `gatewaysvc -config deploy/dev.yaml` as user `app` (uid 10001), with
`deploy/` (configuration and allow-list policies, no key material) at `/app/deploy`.
Deployments mount their own configuration, edge certificate and enrollment token.

## Versioning

- Service releases are tagged `vX.Y.Z`. CI publishes the image as `X.Y.Z`, `X.Y`, `X`
  and `sha-<short>`. There is no `latest` tag.
- The SDK is released separately with `sdk/vX.Y.Z` tags. These tags never build an image.
- v4.0.0 rebuilds the portal as the go-tangra v4 gateway. The v3 portal stays on the
  `v3` branch and its `v3.x` tags.
