# Dependency Justification — services/gateway (Constitution Principle VI)

Go: no modules beyond those already justified for `services/auth` (`github.com/go-tangra/go-tangra/v4`,
`services/auth` for `pkg/authclient`, `grpc`, `valkey-go`, `pgx`, `goose`, `kin-openapi`,
`testcontainers-go` for the tagged suite). The gRPC passthrough proxy and the gRPC-web bridge
are in-house code on grpc-go: the usual libraries (mwitkow/grpc-proxy, improbable-eng/grpc-web)
are archived.

| Shell dependency | Version | Purpose | Alternatives rejected | Maintenance |
|------------------|---------|---------|------------------------|-------------|
| `@module-federation/vite` | ^1.22 | Module Federation host/remote builds for Vite | Rspack toolchain (second bundler) | Active (module-federation org) |
| `@module-federation/enhanced` | ^2.9 | runtime `registerRemotes` / `loadRemote`, manifest protocol | hand-rolled script loading | Active |
| `@casl/ability` | ^7 | UI abilities, `packRules`/`unpackRules`, `update()` | per-module permission helpers | Active |
| `@casl/vue` | ^3 | `Can` component, `useAbility` | manual injection | Active |

Shared with the auth console (pinned by `package-lock.json`, `npm audit --audit-level=high` in CI):
vue 3.5, vuetify 4, vue-router 5, pinia 4, vite 8, typescript 5.9, vitest 5, @playwright/test 1.63 + @axe-core/playwright, openapi-typescript, @mdi/font 7 (icon webfont for `mdi-*` names, bundled: CSP `font-src 'self'`).

## Added during implementation

- `github.com/santhosh-tekuri/jsonschema/v6` (MIT, pure Go, no transitive network access): validates module manifests against the embedded JSON Schema (`api/schema/manifest.schema.json`) so the published contract and the Go validation cannot drift. Deviation from the plan's "no new Go dependencies" recorded here; alternatives (hand-written validation) were rejected because the schema is the contract modules build against.
- `github.com/google/uuid`: UUIDv7 identifiers for allow-list entries and marks (already a transitive dependency).
- `gopkg.in/yaml.v3`: configuration decoding with unknown-field rejection (already used by the framework).
