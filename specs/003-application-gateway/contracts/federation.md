# Contract: Module Federation host and remotes, CASL distribution

## Host (shell)

- Built with `@module-federation/vite` as a host; remotes are **not** configured at build
  time. At start the shell calls `GET /gateway/v1/me/modules` and registers each remote
  with `@module-federation/enhanced/runtime` `registerRemotes([{ name, entry }])` where
  `entry` is `/m/<module>/mf-manifest.json` (same origin, relayed by the gateway).
- Shared singletons provided by the shell (`shared` with `singleton: true`): `vue`,
  `vue-router`, `pinia`, `vuetify`, `@casl/ability`, `@casl/vue`. Remotes MUST declare the
  same packages as shared and MUST NOT bundle their own copies.
- The shell provides: Vuetify instance and theme (with CSP nonce), the router, the Pinia
  instance, a `session` store (identity from `/gateway/v1/me`), an `api` helper (fetch with
  CSRF header and error mapping), and one CASL `Ability` via `@casl/vue`'s
  `abilitiesPlugin` (so `useAbility()` and `<Can>` work inside remotes).
- Each remote is mounted in an error boundary; load or render failures show a retry card
  in the module's area only.

## Remote (module UI)

- Built with `@module-federation/vite` as a remote named `<module>`; `filename:
  'mf-manifest.json'` under the module's `/ui/` path on its Freya HTTP server; the gateway
  relays `/m/<module>/*` to it.
- Exposes:
  - `./routes` — default export `RouteRecordRaw[]`; paths are relative to the module's
    navigation root (`/<module>` unless the manifest says otherwise); route `meta.requires`
    may name an API permission for an extra shell-side guard.
  - `./nav` (optional) — default export `() => NavEntry[]` for dynamic entries; static
    entries come from the manifest.
  - `./header` (optional) — default export: a component rendered in the
    shell app bar (props `{ ability, session, api }`) inside its own error
    boundary; it renders nothing without its permission.
  - `./boot` (optional) — default export `(ctx: { ability, session, api }) => void`,
    called once after load.
- Remotes MUST use `useAbility()` / `<Can I="update" a="Order">` for every conditional UI
  element that corresponds to an API permission; they MUST NOT compute permissions from
  roles themselves.

## CASL abilities

- Declared in the manifest as raw rules with `requires: "resource:action"`.
- `GET /gateway/v1/me/abilities` returns, per module, CASL **packed rules** for the rules
  whose `requires` the caller holds (decided by `auth.v1.Authorization/BatchCheck`),
  with `requires` removed. The shell unpacks them into one `Ability`
  (`createMongoAbility`), namespacing nothing: modules own distinct subject names by
  convention (`<Module>.<Subject>` or unique PascalCase subjects); collisions are refused
  at registration.
- Consistency rule: for every `(action, subject)` a remote gates in the UI, the
  corresponding API route/method carries the same `requires` permission; the integration
  suite checks abilities against decisions for every registered ability
  (`TestAbilitiesMatchDecisions`).
- Live updates: the shell listens to `GET /gateway/v1/events` (SSE); on `abilities` or
  `registry` events it refetches and calls `ability.update(rules)`; on `withdrawn` it
  unmounts the module's routes and navigation.
