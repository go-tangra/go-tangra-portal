# Contract: what a module receives from the gateway

## Transport

- HTTP routes: forwarded over the module's Freya HTTP server (mTLS; the gateway pins the
  module's registered SPIFFE ID). gRPC methods: forwarded over the module's Freya gRPC
  server with the gateway as peer. Modules therefore see the **gateway** as the calling
  service (`authn.FromContext` → gateway identity) and the **end user** in the token.

## Identity

- `Authorization: Bearer <platform access token>` (HTTP) / `authorization` metadata
  (gRPC). For browser sessions the gateway obtained the token through
  `auth.v1.Sessions/Exchange`; for machine and gRPC clients it is the client's own token
  after verification. Modules MUST verify it with `pkg/authclient` (`KratosMiddleware` /
  `Middleware`) and MUST NOT trust any other identity signal.
- Public routes: no `Authorization` header is added; a client-supplied one is removed.

## Headers and metadata

- Added: `X-Request-Id` (correlation, also gRPC metadata `x-request-id`),
  `X-Forwarded-Proto: https`, `X-Forwarded-Host: <public host>`,
  `X-Gateway-Module: <module>` (informational).
- Removed from inbound requests: `Authorization` (for session callers, replaced),
  `Cookie` (never forwarded except to the auth module's session routes, see
  auth-changes.md), all `X-Forwarded-*`, `X-Real-IP`, `X-Freya-*`, `Forwarded`, hop-by-hop
  headers. Response headers from modules pass through except `Set-Cookie` (allowed only
  from the auth module), `Content-Security-Policy` and `Strict-Transport-Security`
  (gateway-owned).
- The originating client address is available to modules only as `X-Gateway-Client`
  (hashed, same pseudonym the auth service uses), never raw — except on routes
  the manifest flags `client_address: true`, which additionally receive the
  plain address as `X-Gateway-Client-Addr` (share-link CIDR policies, feature
  005). Every inbound `X-Gateway-*` header is dropped.

## Limits and timeouts

- Body: route `max_body_bytes` or 1 MiB default; headers 8 KiB; per-route timeout or 30 s;
  gRPC message ≤ 4 MiB; per-client concurrent streams ≤ 32; stream lifetime ≤ declared
  `max_stream_duration` (default 10 min).

## Errors returned to clients on the gateway's behalf

`unauthenticated` (401 / `UNAUTHENTICATED`), `forbidden` (403 / `PERMISSION_DENIED`),
`not_found` (404 / `NOT_FOUND`), `temporarily_unavailable` (503 / `UNAVAILABLE`),
`rate_limited` (429 / `RESOURCE_EXHAUSTED`), `csrf` (403), `payload_too_large` (413).
Module errors pass through unchanged.
