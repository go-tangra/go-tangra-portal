# Research: KVM Console on a Separate Origin

**Feature**: 025-kvm-console-origin · **Date**: 2026-09-28

## Findings in the code (verified)

- IPAM mints the console URL relative to the portal:
  `go-tangra-ipam-v4/internal/kvm/kvm.go:123-136` (`StartSession`,
  `consoleURL = "/bmc/" + id + "/?kvmtoken=" + token`).
- IPAM mounts the token-gated proxy on its mesh HTTP mux:
  `internal/httpapi/power.go:221-225` (`RegisterKVM` → `mux.Handle("/bmc/", …)`)
  wired at `internal/app/app.go:256-259`.
- The Power / KVM tab frames it: `ui/src/views/devices/ipmi-kvm.vue:143`
  (`<iframe :src="kvm.console_url">`).
- The gateway never forwards `/bmc/`: IPAM's manifest has no such route, so
  `internal/httpapi/dispatch.go:103-107` hands it to `NotOwned`
  (`internal/httpapi/server.go:193-199`), which serves the shell page.
- Every gateway response gets the edge headers
  (`go-tangra/transport/edge/headers.go:33-57`): CSP with
  `frame-ancestors 'none'` and nonce-only scripts, `X-Frame-Options: DENY`,
  COOP/CORP `same-origin`. The CSP has no `frame-src`, so `default-src 'self'`
  also forbids framing any other origin.
- The module HTTP forwarder refuses protocol upgrades
  (`internal/proxy/httpproxy/proxy.go:172-178`) — the KVM WebSocket could not
  pass the gateway even on the portal origin.
- The edge's request deadline (`transport/edge/server.go:306-318`) would end
  any WebSocket after `limits.request_timeout`, and its CSRF filter
  (`transport/edge/csrf.go:37-93`) refuses mutations from any non-allowed
  `Origin` — the edge server is the wrong host for vendor pages.
- IPAM's KVM cookie holds the start token itself (`kvm.go:249-256`), valid for
  the token TTL (60 s default, 300 s in the dev stack); `kvm.session_seconds`
  exists in config (`internal/config/config.go:124-127`) but is never used.
  After the TTL, asset or reconnect requests fail with 403.
- IPAM relays the BMC's `Set-Cookie` to the browser (no filter in
  `ModifyResponse`, `kvm.go:273-276`) and forwards browser cookies to the BMC
  when no SID is injected (`kvm.go:268-270`).
- IPAM's WebSocket upgrader accepts every `Origin` (`kvm.go:287-292`).
- The mesh HTTP client uses HTTP/1.1 for `Upgrade` requests even with
  `ForceAttemptHTTP2` (Go `net/http` `requiresHTTP1` → `onlyH1`), so a
  `httputil.ReverseProxy` over `thttp.NewClient`'s transport can relay a
  WebSocket to the module; IPAM's handler hijacks and clears deadlines itself.

## Decisions

### D1 — A separate origin, not a relaxed portal policy

**Decision**: consoles are served from `https://<public host>:8444`.
**Rationale**: vendor BMC JavaScript needs `unsafe-inline`/`unsafe-eval`,
blobs and WebSockets. On the portal origin that code could read the portal's
DOM, call its API with the ambient session and read responses. On a different
origin the same-origin policy forbids all three.
**Alternatives rejected**: relaxing the portal CSP (exposes the session);
serving via `/m/ipam/` (same origin); a sandboxed iframe without
`allow-same-origin` (vendor viewers need their own cookies/storage; opaque
origins send `Origin: null` and break the console cookie).

### D2 — Same host, different port: what is and is not isolated

Browsers scope **cookies by host, not port** (RFC 6265 §8.5), so the browser
sends `__Host-session` (HttpOnly) and `__Host-csrf` (readable by script) to
`:8444` too, and scripts on `:8444` see `__Host-csrf` in `document.cookie`.
Analysis:

- *Reading portal data*: impossible — responses from `:443` are cross-origin
  for `:8444` (no CORS is served), and `__Host-session` is HttpOnly.
- *Authenticated mutations (CSRF)*: the edge requires the `X-CSRF-Token`
  header (a custom header ⇒ CORS preflight the portal never answers) **and**
  an `Origin` in `edge.allowed_origins` (`csrf.go:74-87`). `:8444` is
  same-site (`Sec-Fetch-Site: same-site`, not `cross-site`) but its `Origin`
  is not allowed, so the request is refused. Config validation refuses a
  console origin listed in `allowed_origins` (SR-001).
- *Ambient cookies to the console*: stripped by the console listener (D5);
  modules and BMCs never see them.
- *Cookie tossing*: script on `:8444` can **set** cookies for the host
  (`__Host-` prefix only needs `Secure; Path=/`). It cannot overwrite an
  existing HttpOnly cookie from script, but it could plant a
  `__Host-session` when none exists (login fixation) or overwrite
  `__Host-csrf` (the portal then refuses mutations until the shell re-issues
  it — availability only). Residual risk, accepted: the code is the
  operator's own BMC firmware reached with the administrator's credentials;
  the gateway never lets a *module response* set these names (D5). Operators
  who want full cookie isolation set `console.public_origin` to a distinct
  host name (`https://kvm.example.com`) with its own certificate SAN — the
  configuration supports it unchanged.

### D3 — The console listener lives in the gateway, not the framework edge

**Decision**: a new `internal/console` package in the portal: its own
`http.Server` with TLS 1.3, HTTP/1.1 only (WebSockets need HTTP/1.1; the
listener serves only consoles), certificate from `edge.cert_file/key_file`
reloaded every minute.
**Rationale**: the edge's CSRF filter, request deadline and strict headers are
exactly what must not apply here; adding a "console mode" to the framework
edge would widen the framework's public surface for one consumer.
**Alternatives rejected**: reusing `edge.Server` and overriding headers (the
deadline kills the WebSocket and CSRF refuses BMC form posts); a separate
reverse proxy container (another component to secure and deploy).
**Consequence**: the console listener requires cert files in every
environment (no generated self-signed fallback); the dev stacks already mount
`/edge/tls.{crt,key}`.

### D4 — Forwarding reuses the registry and the mesh client

**Decision**: the console handler resolves the module's registered identity
and healthy backends via `registry.Backends`, requires the module to be
`active` (`registry.State`), and forwards with an `httputil.ReverseProxy`
whose transport is `thttp.NewClient(rt, <module SPIFFE ID>)` — the same
pinned mTLS client the module HTTP forwarder uses. Backends are cached per
module/identity/target like the dispatcher's.
**Rationale**: no new trust path; the module's mesh policy already allows the
gateway (`ipam/deploy/policy.yaml`, rule `gateway-forwards`).

### D5 — Cookie and header policy on the console listener

- Request: `Cookie` is rebuilt with only allow-listed names (default
  `freya_kvm`); `Authorization`, `Proxy-Authorization`, `Forwarded`,
  `X-Forwarded-*`, `X-Real-IP`, `X-Request-Id`, `X-CSP-Nonce`, `X-Freya-*`,
  `X-Gateway-*` are removed; the gateway sets `X-Request-Id`,
  `X-Forwarded-Proto: https`, `X-Forwarded-Host: <console host>`,
  `X-Gateway-Module`.
- Response: `Set-Cookie` lines whose name is not allow-listed are dropped;
  upstream `Content-Security-Policy(-Report-Only)`, `X-Frame-Options`, HSTS,
  COOP/COEP/CORP, `Permissions-Policy`, `Cache-Control`, `Pragma`, `Expires`
  are removed and replaced by the console set (D6).

### D6 — Console response headers

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:;
  style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:;
  connect-src 'self' wss://<console host>; worker-src 'self' blob:; frame-src 'self';
  frame-ancestors <portal public origin>; base-uri 'self'; object-src 'none'; form-action 'self'
Strict-Transport-Security: max-age=63072000; includeSubDomains
Referrer-Policy: no-referrer
Cache-Control: no-store
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
```

No `X-Frame-Options` (it cannot express "only the portal"; `frame-ancestors`
supersedes it). No `nosniff` (BMC firmware often serves scripts with a wrong
content type). COOP/CORP `same-origin` do not affect framing (COOP only
governs top-level browsing context groups; CORP applies to no-cors
sub-resources and the portal sets no COEP).

### D7 — Framework: `edge.Config.FrameSources`

**Decision**: a typed list of https origins; when non-empty the edge CSP
gains `frame-src 'self' <origins>`. Each entry is validated at `NewServer`
(https scheme, host, no path/query/fragment/user info, no CSP metacharacters
`;`, `,`, `'`, whitespace). Empty keeps the policy byte-for-byte. Framework
version **v4.2.2** (the gateway is the only consumer; additive field).
**Alternatives rejected**: `CSPExtra` (unvalidated free text; a typo silently
weakens the policy).

### D8 — IPAM: absolute console URL, single-use start token, console session

- `kvm.console_origin` (empty or an https origin, validated) → `StartSession`
  returns `<origin>/bmc/<id>/?kvmtoken=<token>`; empty keeps the relative URL.
- First request carrying a valid `kvmtoken` consumes the token and creates a
  console session (32 random bytes, hex) bound to the same device/host/creds,
  valid `kvm.session_seconds`; the cookie `freya_kvm=<session>` is `Secure`,
  `HttpOnly`, `SameSite=Strict`, `Path=/bmc/<id>/`. Later requests are
  authorised by the cookie only. A replayed token is refused (403).
- `SameSite=Strict` works: the portal (`:443`) and the console (`:8444`) are
  the same site, so the framed page and its WebSocket carry the cookie.
- Upstream (BMC) `Set-Cookie` is dropped; the outgoing `Cookie` is always
  replaced by the server-side BMC session (never the browser's); `Origin`
  sent to the BMC is rewritten to the BMC's own origin.
- WebSocket `Origin` must equal the console origin when one is configured.

### D9 — Limits on the console listener

`console.max_concurrent` (default 64 in-flight requests → 503 beyond),
request deadline `forward.module_timeout` for plain requests,
`console.session_max` (default 1 h, max 24 h) for WebSockets, body limit
`forward.body_bytes`, `ReadHeaderTimeout`/`IdleTimeout`/`MaxHeaderBytes`
from the runtime limits. No per-IP rate limiter: tokens are 192-bit random
and single-use; every refusal costs one module round trip at most.

### D10 — Deployment

- docker: publish `${CONSOLE_BIND}:${CONSOLE_PORT:-8444}:8444` on the gateway
  (dev and production examples); gateway `console` section; IPAM
  `kvm.console_origin: https://localhost:8444` (dev), rewritten by
  `prod-init.sh` to `https://<PUBLIC_HOST>:<CONSOLE_PORT>`.
- Production: open 8444/tcp on the host firewall; the public certificate
  already names `PUBLIC_HOST` (a certificate is not port-specific).

## STRIDE threat model

| Threat | Vector | Mitigation |
|---|---|---|
| **S**poofing | Attacker opens a console without starting a session | IPAM requires a valid single-use start token or a console session cookie bound to the device path (192/256-bit random); the listener itself grants nothing |
| **S**poofing | Cross-site page opens the console WebSocket with the victim's console cookie (CSWSH) | Cookie is `SameSite=Strict` (not sent cross-site); IPAM checks `Origin` equals the console origin (SR-004) |
| **S**poofing | Client forges `X-Forwarded-*`, `X-Gateway-*`, `Authorization` to the module | Stripped by the listener (D5); IPAM's `/bmc/` does not trust them |
| **T**ampering | Console JS (vendor firmware) posts to the portal API | CSRF filter: custom header ⇒ preflight never answered; `Origin :8444` not in `allowed_origins` (refused by config validation if added) |
| **T**ampering | Console JS plants/overwrites host cookies (cookie tossing) | Existing HttpOnly session cannot be overwritten by script; module responses cannot set non-allow-listed names; residual login-fixation risk documented; distinct host name option (D2) |
| **T**ampering | Path traversal / encoded paths to reach other module routes | `route.Normalize` refuses `..`, `//`, control chars; only configured prefixes forwarded; module mux re-checks `/bmc/{id}/…` |
| **R**epudiation | Who opened a console | IPAM audits `kvm_session_started` (actor, device, outcome — feature 024); gateway traffic metrics per module |
| **I**nformation disclosure | Portal session/CSRF cookies reach IPAM or the BMC | Cookie allow-list on the listener (SR-002); IPAM replaces the outgoing Cookie with the BMC SID |
| **I**nformation disclosure | BMC credentials or SID reach the browser | Credentials server-side only; upstream `Set-Cookie` dropped (SR-003) |
| **I**nformation disclosure | Console JS reads portal pages or API responses | Different origin; the portal serves no CORS; `__Host-session` HttpOnly |
| **I**nformation disclosure | Token in URL leaks via Referer/history | `Referrer-Policy: no-referrer` on both origins; token single-use and 60 s |
| **D**enial of service | Many idle connections / slow requests on 8444 | TLS 1.3 handshake timeout, `ReadHeaderTimeout`, `max_concurrent` cap, per-request deadline, WebSocket `session_max`, body limit |
| **D**enial of service | Planted `__Host-csrf` breaks portal mutations | Availability-only; shell re-issues the CSRF cookie on reload; distinct host name removes it |
| **E**levation of privilege | Using the console listener to reach module APIs | Only configured prefixes (`/bmc/` → ipam); every other path 404 before any module contact |
| **E**levation of privilege | Framing the portal from the console origin | Portal keeps `frame-ancestors 'none'` and `X-Frame-Options: DENY` |
