# Required changes to services/auth (feature 002)

1. **`auth.v1.Sessions/Exchange`** (new RPC, policy: gateway identity only):
   `ExchangeRequest{cookie_secret}` → `ExchangeResponse{identity{user_id, tenant_id,
   session_id, roles, amr, operator}, access_token, expires_at}`. Resolves the session
   exactly like the cookie path (idle/absolute expiry, revocation marks, touch) and mints a
   platform access token for it. Audited as `token_exchanged` (new vocabulary entry).
2. **`auth.v1.Sessions/MintToken`** (gateway identity only): mints a token for an
   already-verified session id (used to refresh before expiry without re-sending the
   cookie). Refused if the session is no longer live.
3. **Gateway mode** (`config.gateway.enabled: true`): the browser API and the console
   assets are served on the Freya HTTP server (mTLS) instead of the edge listener; CSRF and
   security headers are delegated to the gateway; `Set-Cookie` for `__Host-session` is
   still issued by auth and relayed by the gateway; the auth module registers its manifest
   (`internal/gatewayreg`) with prefixes `/api/v1`, `/authorize`, `/.well-known`, remote
   `/m/auth/mf-manifest.json`, permissions it already registers, CASL abilities for its
   console (users, roles, policy, audit, clients, tenants, grants) and navigation entries.
4. **Console as a remote**: `services/auth/console` builds with `@module-federation/vite`
   as remote `auth`, exposing `./routes` and `./nav`; it keeps working standalone (edge
   mode) for local development.
5. **Sessions semantics**: the session cookie now lives on the gateway origin; `allowed
   origins`/CSRF configuration move to the gateway; `GET /api/v1/session` remains for the
   shell's session store via the gateway.
