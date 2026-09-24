# Module author guide

A platform module is a Freya service that (1) serves its API on the Freya
channel, (2) registers a manifest with the application gateway, and (3) ships
its user interface as a Module Federation remote composed by the platform
shell. The example in `examples/hello-module` is the smallest complete module.

## 1. Manifest

Build it with `pkg/gatewayclient` (typed) or hand it to `Register` as
`gateway.v1.Manifest`; the gateway validates it against
`api/schema/manifest.schema.json` plus semantic rules.

| Field | Rules |
|-------|-------|
| `module` | `^[a-z][a-z0-9-]{1,39}$`; must be in the allow-list `names` of your SPIFFE identity |
| `prefixes` | absolute, normalised, ≤ 8, each under a prefix the allow-list grants you; no overlap with other modules |
| `routes[]` | `METHOD /path` under an owned prefix; `{param}` segments and one trailing `{rest...}`; exactly one of `permission` or `public: true` |
| `methods[]` | `/pkg.Service/Method`; same protection rule; `streaming` + `max_stream_duration` for long-lived streams |
| `permissions[]` | every `resource:action` referenced by routes, methods, abilities and nav; the gateway registers them with the auth module for every tenant |
| `abilities[]` | CASL raw rules with `requires: "resource:action"` (conditions limited to `$eq $ne $in $nin $lt $lte $gt $gte $exists`, ≤ 4 KiB); subjects must be unique across modules |
| `remote` | `entry` is always `/m/<module>/mf-manifest.json`; `exposes` ⊆ `./routes ./nav ./boot ./header` |
| `nav[]` | entries shown when the caller holds `requires`; the shell groups them under one menu per module titled `display_name`, placed by the lowest `order` and using the first entry's `icon` |

Bump `version` when the manifest changes; instances with the old manifest
have their renewals refused and re-register.

## 2. API permissions vs UI abilities

- **API permissions** are enforced by the gateway on every request before it
  reaches you: the caller must hold the route's `resource:action` in the
  tenant's policy (auth module `Authorization/BatchCheck`).
- **UI abilities** are CASL rules the shell derives from the same
  permissions: a rule is delivered to the browser only when its `requires`
  permission is held, so `<Can I="create" a="Greeting">` and the API decision
  never disagree. Modules never compute permissions from roles.

## 3. Registering

```go
conn, _ := app.Client(ctx, "gateway")          // Freya channel, mTLS
client, _ := gatewayclient.New(conn, gatewayclient.Options{
    Manifest: manifest, HTTPURL: "https://" + httpEP.Host, GRPCTarget: grpcEP.Host,
})
client.Run(ctx)                                 // Register → Renew every 10 s → Deregister on ctx end
```

Operators allow your identity first:
`gatewaysvc bootstrap -allow "spiffe://<td>/svc/<name>=<prefix>[,<prefix>];<module>"`.

## 4. What you receive

See `specs/003-application-gateway/contracts/forwarding.md`. In short: the
gateway is your mTLS peer; the end user is in `Authorization: Bearer <platform
token>` (verify it with `pkg/authclient`); `X-Request-Id`, `X-Forwarded-Proto/Host`,
`X-Gateway-Module` and the hashed `X-Gateway-Client` are added (plus the plain
`X-Gateway-Client-Addr` on routes declared with `client_address: true`); nothing
else from the public network reaches you. Public routes carry no bearer token.

Who is signed in: `GET /gateway/v1/me` returns `display_name` and `avatar_url`
(gateway-relative; embed it in an `<img>`; empty when the person has none) next
to the effective roles. To show other people of the tenant, call the auth
module's `GET /api/v1/users/{id}` or `POST /api/v1/users/lookup` from the
browser, or `auth.v1.Profiles/Lookup` from your service. Phone numbers are
never available to modules. After changing the signed-in person's profile,
dispatch `window.dispatchEvent(new CustomEvent('freya:session-changed'))` so
the shell refreshes its header.

## 5. The remote (UI)

- Vite + `@module-federation/vite` remote named `<module>`, `filename:
  'remoteEntry.js'`, `manifest: true`, `base: '/m/<module>/'`, shared
  singletons exactly as `shell/module-federation.config.ts` (`vue`,
  `vue-router`, `pinia`, `vuetify`, `@casl/ability`, `@casl/vue`).
- Serve `dist/` under `/ui/` on your Freya HTTP server (manifest `no-store`,
  hashed assets immutable, no `index.html`); the gateway relays `/m/<module>/*`.
- Expose `./routes` (`RouteRecordRaw[]`; absolute paths under your navigation
  root), optionally `./nav`, `./boot({ ability, session, api })` and
  `./header` (a component the shell renders in its app bar with the same
  context as `./boot`; it must render nothing when the person lacks the
  permission it needs and close its connections in `onUnmounted`).
- The shell owns the look: the shared Vuetify singleton carries the Materio
  palette (`shell/src/theme/materio.ts`: purple `primary`, `#f4f5fa` page
  behind white cards, a light/dark switch) and `shell/src/theme/materio.css`
  sets Inter, radii and shadows for every component. Use theme colours
  (`primary`, `success`, …) and Vuetify variants rather than literal colours,
  and reset plain `<button>` elements yourself; nothing needs importing.
- Use `useAbility()` / `<Can>` from `@casl/vue` for every element that mirrors
  an API permission. The shell updates the ability live from
  `GET /gateway/v1/events`.
- Everything is same-origin under the gateway's strict CSP: no remote hosts,
  no inline scripts.

## 6. Local development

1. `make testca` at the repository root (dev CA + SVIDs), start the compose
   stack (`services/gateway/deploy/compose.yaml`).
2. Auth in gateway mode: `authsvc bootstrap -config deploy/gateway-mode.yaml
   -operator-email ops@example.org` then `authsvc -config deploy/gateway-mode.yaml`.
3. Gateway: `gatewaysvc bootstrap -config deploy/dev.yaml -allow ...` then
   `gatewaysvc -config deploy/dev.yaml`.
4. Your module: `go run . -config deploy/hello.yaml` (build the UI first:
   `cd ui && npm run build`, compile with `-tags ui`).
5. Open `https://localhost:8443/`, sign in, your navigation entry appears once
   the caller holds the permission.
