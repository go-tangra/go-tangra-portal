# Feature Specification: KVM Console on a Separate Origin (port 8444)

**Feature Branch**: `025-kvm-console-origin`

**Created**: 2026-09-28

**Status**: Implemented (39/44 tasks; release tasks T038–T042 pending user confirmation)

**Spans**: go-tangra (framework: edge `frame_sources`), go-tangra-portal-v4
(gateway: console listener), go-tangra-ipam-v4 (KVM console origin, session
cookie, UI), go-tangra-docker (port 8444, configs, production notes)

**Input**: Verified live 2026-09-28: IPAM's "Start session" returns
`console_url: "/bmc/<device>/?kvmtoken=…"` and the Power / KVM tab embeds it in
an iframe. The gateway never forwards `/bmc/` to IPAM (the fallback serves the
shell page), and every gateway response carries `frame-ancestors 'none'`,
`X-Frame-Options: DENY` and a nonce-only script policy, so Chrome shows
"refused to connect". The KVM console has never worked end to end in v4.
Decision (user, 2026-09-28): **serve consoles from a separate origin on port
8444**, so the BMC vendor's JavaScript never runs on the portal origin.

## Context

A BMC's HTML5 KVM viewer is third-party firmware JavaScript: it needs inline
scripts, `eval`, blobs and a WebSocket, and it must be framed by the portal.
Relaxing the portal's own Content-Security-Policy for it would expose the
portal session to that code. A browser origin is scheme + host + **port**, so
`https://<public host>:8444` is a different origin from the portal
(`https://<public host>` / `:443`): its scripts cannot read portal pages,
responses or DOM. The console origin gets its own, permissive-enough policy
and may be framed only by the portal.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Open a device's KVM console from the portal (Priority: P1) 🎯 MVP

A platform administrator opens node-1 → Power / KVM → "Start session". The
BMC's HTML5 console appears inside the tab, shows the server's screen and
accepts keyboard input, without the BMC password ever reaching the browser.

**Why this priority**: This is the broken capability.

**Independent Test**: With the console listener enabled and IPAM's console
origin set, starting a session yields an absolute console URL on the console
origin; loading it through the listener reaches IPAM's `/bmc/` proxy, the
BMC page renders in the portal iframe and its WebSocket connects.

**Acceptance Scenarios**:

1. **Given** the console origin is configured, **When** an administrator with
   `kvm:access` starts a session, **Then** the response carries a console URL
   on the console origin (`https://<host>:8444/bmc/<device>/?kvmtoken=…`) and
   the tab embeds it.
2. **Given** that URL, **When** the browser loads it in the portal's iframe,
   **Then** the portal's policy allows framing the console origin, the console
   response allows being framed by the portal origin only, and the BMC page and
   its assets load.
3. **Given** the console page opens its WebSocket (`/bmc/<device>/__kvmws`),
   **Then** it is relayed to IPAM and on to the BMC in both directions for the
   length of the session.
4. **Given** the session is used for longer than the start token's lifetime
   (60 s default), **Then** the console keeps working until the console
   session ends (`kvm.session_seconds`).

---

### User Story 2 - Nothing but consoles on the console origin (Priority: P1)

The console origin serves only the configured console paths. The portal's
cookies never reach IPAM or the BMC, the BMC cannot set portal cookies, and
anything else on port 8444 answers 404.

**Why this priority**: The separate origin exists to contain untrusted
vendor code; leaking portal credentials into it defeats the purpose.

**Independent Test**: Requests to the listener carrying the portal session
and CSRF cookies arrive at the module without them; a module response setting
`__Host-session` is stripped; `/`, `/api/...`, `/gateway/v1/...`, `/m/...`
and traversal paths answer 404 and never reach a module.

**Acceptance Scenarios**:

1. **Given** a request to the console listener, **Then** only cookies on the
   console allow-list (`freya_kvm`) are forwarded; `__Host-session`,
   `__Host-csrf` and every other cookie are removed, as are `Authorization`
   and any client-supplied forwarding headers.
2. **Given** a module response, **Then** only allow-listed cookies are relayed
   and the module's own security headers are replaced by the console policy.
3. **Given** any path outside the configured prefixes, **Then** the listener
   answers 404 without contacting a module.
4. **Given** a request without a valid console token or console session,
   **Then** IPAM refuses it (403) and never contacts the BMC.

---

### User Story 3 - Clear state when the console origin is not configured (Priority: P2)

On a deployment without the console origin, "Start session" shows "KVM
console origin not configured" instead of an iframe that the browser refuses.

**Why this priority**: Older or partial deployments must fail with an
explanation, not a broken frame.

**Independent Test**: With `kvm.console_origin` unset, IPAM returns a relative
console URL (backwards compatible) and the tab shows the explanation and no
iframe.

**Acceptance Scenarios**:

1. **Given** `kvm.console_origin` is unset, **Then** the console URL stays
   relative (unchanged API) and the tab explains that the console origin is not
   configured.
2. **Given** the gateway's console listener is disabled, **Then** the portal's
   policy is unchanged (no frame sources) and port 8444 is not bound.

### Edge Cases

- The console origin is reachable, but IPAM is not registered, is disabled or
  has no healthy instance: the listener answers 503 without detail.
- The start token is used twice (reload of the frame, copy of the URL): the
  second use is refused; the administrator starts a new session.
- Two consoles for two devices open at once: each console session cookie is
  scoped to its device's path and does not replace the other.
- The BMC sets its own cookies: they are dropped by IPAM (the BMC session stays
  server-side) and by the gateway (not allow-listed).
- The portal is served on 443 while the console is on 8444: both use the same
  public certificate (same host name); only the port differs.
- Port 8444 is blocked by a firewall: the iframe fails to load; the operator
  documentation lists 8444 as a required browser-facing port when the console
  is enabled.
- WebSocket requests with a foreign `Origin`: refused by IPAM when the console
  origin is configured.
- A console left open: the WebSocket is closed when the gateway's console
  session limit (`console.session_max`) ends.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The framework edge MUST accept an optional list of additional
  frame sources (`frame_sources`) and, when non-empty, emit
  `frame-src 'self' <sources>` in its Content-Security-Policy; with none, the
  policy MUST be unchanged. All other edge headers MUST be unchanged.
- **FR-002**: The gateway MUST offer an optional console listener
  (`console.enabled`, `console.addr`, `console.public_origin`,
  `console.routes` mapping path prefixes to modules) on its own TLS 1.3 port,
  using the edge's public certificate, and MUST add the console origin to the
  edge's frame sources when enabled.
- **FR-003**: The console listener MUST serve only the configured prefixes and
  forward them — HTTP and WebSocket upgrades — to the owning module's
  registered backend over the authenticated service mesh; every other path
  MUST answer 404.
- **FR-004**: The console listener MUST NOT authenticate users itself (the
  module's console token gates access), MUST forward only allow-listed cookies,
  MUST drop `Authorization` and client-supplied forwarding headers, and MUST
  relay only allow-listed `Set-Cookie` names.
- **FR-005**: Console responses MUST carry a console policy: framing allowed
  only for the portal's public origin (`frame-ancestors`), inline/eval scripts,
  blobs and WebSockets to self allowed, no `X-Frame-Options: DENY`,
  `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, HSTS.
- **FR-006**: IPAM MUST accept `kvm.console_origin`; when set, a started
  session's console URL MUST be absolute on that origin, otherwise relative as
  today.
- **FR-007**: IPAM's start token MUST be single-use: its first use MUST be
  exchanged for a console session (cookie scoped to `/bmc/<device>/`, `Secure`,
  `HttpOnly`, `SameSite=Strict`) valid for `kvm.session_seconds`.
- **FR-008**: The Power / KVM tab MUST embed the console only when the URL is
  absolute on an https origin, and otherwise show "KVM console origin not
  configured".
- **FR-009**: The docker deployment MUST publish port 8444 for the gateway,
  configure the console section, IPAM's console origin, and document the
  firewall and certificate requirements for production.

### Security Requirements

- **SR-001**: The console origin MUST differ from the portal origin and MUST
  NOT be accepted by the portal's CSRF origin check (`edge.allowed_origins`);
  configuration that violates this MUST be refused at startup.
- **SR-002**: Portal cookies (`__Host-session`, `__Host-csrf`, and any
  non-allow-listed cookie) MUST NOT reach a module or a BMC through the console
  listener, and a module MUST NOT be able to set them through it.
- **SR-003**: BMC credentials and the BMC's own session cookie MUST NOT reach
  the browser (IPAM drops upstream `Set-Cookie`, replaces browser cookies with
  the server-side BMC session).
- **SR-004**: When a console origin is configured, IPAM MUST refuse console
  WebSocket upgrades whose `Origin` is not the console origin.
- **SR-005**: The console listener MUST bound request time, WebSocket session
  time, body size and concurrent requests, and MUST use TLS 1.3 only.
- **SR-006**: The analysis of what a same-host, different-port origin can and
  cannot do to the portal (shared cookies, CSRF, cookie tossing) MUST be
  recorded in the STRIDE model with the residual risk.

### Key Entities

- **Console listener configuration**: address, public origin, prefix → module
  routes, cookie allow-list, limits.
- **Console start token**: short-lived, single-use, bound to device + BMC host
  + credentials (IPAM memory).
- **Console session**: random id in the `freya_kvm` cookie, bound to the same
  device binding, valid for `kvm.session_seconds` (IPAM memory).

## Success Criteria *(mandatory)*

- **SC-001**: An administrator sees the BMC console inside the Power / KVM tab
  within 5 seconds of "Start session" (network permitting).
- **SC-002**: 0 portal cookies observed at the module in the console-listener
  tests; 100 % of non-console paths on port 8444 answer 404.
- **SC-003**: The portal's own CSP is byte-for-byte unchanged when no frame
  sources are configured.
- **SC-004**: A console stays usable for at least 15 minutes (beyond the
  start token lifetime).

## Assumptions

- The console origin uses the portal's public host name with port 8444 and the
  same certificate; a distinct host name (e.g. `kvm.example.com`) is also
  supported by configuration and gives full cookie isolation (research D2).
- Only IPAM's `/bmc/` needs the console listener today; the route map is
  generic so other modules can add console prefixes later.
- IPAM runs a single instance (console tokens and sessions are in its memory);
  multi-instance session affinity is out of scope.
- BMC pages must use relative URLs under `/bmc/<device>/` (as today); BMC
  pages that request absolute root paths are out of scope.

## Dependencies

- Feature 024 (BMC credentials from Warden) for the KVM session itself.
- The gateway's registry (module backends) and mesh client.
