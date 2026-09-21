# Feature Specification: Application Gateway

**Feature Branch**: `003-application-gateway`

**Created**: 2026-09-16

**Status**: Draft

**Input**: User description: "Create a new service: an application gateway. The gateway is the only publicly exposed module of the platform. All other modules (services) stay private and register themselves with the application gateway at start-up: they register their routes (HTTP/gRPC endpoints they expose) and the permissions each route requires, via the gateway. The gateway enforces those permissions on every request before forwarding it to the owning module. All modules implement Module Federation (https://module-federation.io/) for their frontends: each module exposes its UI as a federated remote, and the gateway hosts the shell (host application) that loads and composes the modules' UIs, so the whole platform is served from the single public entry point. Place the service under services/ like services/auth; it will later move to its own repository."

## Overview

Today every platform module that wants to be reachable from a browser has to
expose its own public listener, its own console and its own copy of the
authentication and authorization checks. The application gateway replaces that
with one public entry point. Private modules describe themselves to the gateway
when they start — which paths they serve, which permission each path requires,
and where their user interface can be loaded from — and the gateway becomes the
only place where the outside world meets the platform: it terminates public
traffic, identifies the caller, checks the permission the owning module declared
for that path, and only then forwards the request over the private service
channel. The gateway also serves the platform's single web application: a shell
that discovers the registered modules and composes their federated user
interfaces into one navigation, so users experience one product while teams keep
deploying their modules independently.

The authentication service (`002-tenant-auth-service`) is the first module to
live behind the gateway: it provides the user identities, sessions and
permission decisions the gateway relies on, and its console becomes a federated
remote like every other module's UI.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A Module Registers Itself and Its Routes (Priority: P1)

A module team deploys a private module. On start-up the module presents its
service identity to the gateway and registers a manifest: a unique module name,
the path prefix it owns, each route it serves with the permission required to
call it (or an explicit "public" marker for routes that need no signed-in user),
and the location of its federated user interface. The gateway validates the
manifest, refuses anything that overlaps with another module's paths or names,
records who registered it, and starts forwarding matching public requests to the
module. When the module stops or stops renewing its registration, the gateway
withdraws its routes.

**Why this priority**: Without registration there is nothing to route; it is
the contract every other module builds on.

**Independent Test**: Start the gateway and one private test module; the module
registers two routes (one protected, one public); requests to the public route
are forwarded and answered, requests to unregistered paths return "not found",
and stopping the module removes its routes within the lease period.

**Acceptance Scenarios**:

1. **Given** a private module with a valid service identity, **When** it registers a manifest with a unique name and prefix, **Then** the gateway accepts it, confirms the registration and forwards requests under that prefix to the module.
2. **Given** a module registered under `/orders`, **When** another module tries to register `/orders` or `/orders/reports`, **Then** the second registration is refused with a conflict and nothing changes for the first module.
3. **Given** a registered module, **When** it stops renewing its registration for longer than the lease period, **Then** its routes are withdrawn, requests to them return "temporarily unavailable", and the withdrawal is audited.
4. **Given** a caller that is not a recognised private module (no service identity, or an identity the gateway's policy does not allow to register), **When** it attempts to register, **Then** the request is refused and audited.
5. **Given** a manifest that declares a route without a permission and without the explicit public marker, **When** it is submitted, **Then** it is refused as invalid — every route must state how it is protected.

---

### User Story 2 - End Users Reach the Platform Through One Entry Point (Priority: P1)

A user opens the platform's single address. If they are not signed in, the
gateway's shell sends them through the platform sign-in (provided by the
authentication module) and brings them back. Every request the user's browser
then makes to a module route is checked by the gateway: the user must be signed
in, and must hold the permission the module declared for that route in their
tenant; only then is the request forwarded, together with the verified identity,
to the owning module. Refusals are uniform and audited; the module never sees a
request the user was not allowed to make.

**Why this priority**: This is the security purpose of the gateway — one
enforcement point in front of every module.

**Independent Test**: With the authentication module and one test module
registered, sign in as a user with permission `reports:read` but not
`reports:export`; a request to the route requiring `reports:read` succeeds, one
requiring `reports:export` is refused with the platform's standard "forbidden"
answer, an unauthenticated request is redirected (browser) or refused (API), and
each refusal appears once in the audit trail.

**Acceptance Scenarios**:

1. **Given** an anonymous browser, **When** it opens a protected page, **Then** it is taken to sign-in and, after signing in, returned to the page it asked for.
2. **Given** a signed-in user holding the required permission, **When** they call a protected route, **Then** the request reaches the owning module with the user's identity (user, tenant, roles) attached and the answer is returned unchanged.
3. **Given** a signed-in user lacking the required permission, **When** they call the route, **Then** the gateway refuses with the standard "forbidden" answer without contacting the module, and audits the refusal with user, tenant, route and permission.
4. **Given** a route marked public, **When** an anonymous caller uses it, **Then** it is forwarded without an identity check but still subject to the gateway's rate limits and size limits.
5. **Given** a permission that was just revoked from the user, **When** they retry within a few seconds, **Then** the request is refused (changes propagate within the platform's stated bound).
6. **Given** a user of tenant A, **When** they call a route with identifiers belonging to tenant B, **Then** the gateway forwards only tenant A's verified identity; the module (already tenant-guarded) answers "not found", and no data of tenant B is exposed.

---

### User Story 3 - The Shell Composes Module User Interfaces (Priority: P2)

A user signed in to the shell sees one navigation built from the registered
modules: each module contributes its entries (title, path, required permission)
and the shell shows only the entries the user may use. Selecting an entry loads
that module's federated interface into the shell without a full page reload;
shared foundations (design system, session, API access helpers) are provided once
by the shell. A module whose interface fails to load shows an isolated error in
its own area while the rest of the platform keeps working.

**Why this priority**: It turns many module UIs into one product; it depends on
registration (US1) and identity (US2) being in place.

**Independent Test**: Register two test modules with federated UIs; the
navigation shows entries filtered by the user's permissions; opening each
renders its UI inside the shell; making one module's UI unreachable shows an
error card for that module only, and the other continues to work.

**Acceptance Scenarios**:

1. **Given** three registered modules and a user permitted to use two, **When** the shell loads, **Then** the navigation lists exactly those two modules' entries in the declared order.
2. **Given** a user on module A's page, **When** they navigate to module B, **Then** B's interface appears without a full reload and the address bar reflects B's path.
3. **Given** module C's interface cannot be loaded, **When** the user opens it, **Then** an error message is shown in C's area with a retry action, and modules A and B remain usable.
4. **Given** a module's interface receives the shared session, **When** the user signs out anywhere, **Then** every module area returns to the signed-out state and protected calls stop.
5. **Given** a module deploys a new version of its interface, **When** users next navigate to it, **Then** they receive the new version without the shell being redeployed.

---

### User Story 4 - Operators Observe and Control Registrations (Priority: P2)

A platform operator opens the gateway's operations area and sees every
registered module: name, identity, routes and permissions, interface location,
health, last renewal, and recent traffic and refusal counts. The operator can
drain a module (stop sending it new requests while in-flight ones finish),
revoke a registration outright, and pin which service identities may register at
all. Every change is audited.

**Why this priority**: Operability of a single choke point matters, but the
platform is usable without the operations view.

**Independent Test**: Register a test module; the operations view lists it with
its routes; draining it makes new requests return "temporarily unavailable"
while the module still answers direct in-flight calls; revoking removes it; both
actions appear in the audit trail with the operator's identity.

**Acceptance Scenarios**:

1. **Given** registered modules, **When** an operator opens the registrations view, **Then** each module's manifest, health and last renewal time are shown.
2. **Given** a healthy module, **When** the operator drains it, **Then** new requests to its routes receive "temporarily unavailable" and the module's registration is marked draining.
3. **Given** a drained module, **When** the operator revokes it, **Then** its routes disappear, its next renewal is refused, and the revocation is audited.
4. **Given** a non-operator user, **When** they try to reach the operations view or its actions, **Then** they are refused.

---

### User Story 5 - The Platform Degrades Gracefully (Priority: P3)

When a module is slow or down, the gateway protects the rest of the platform:
requests to that module fail fast after a bounded time, the module is marked
unhealthy and temporarily bypassed, and users see a clear "temporarily
unavailable" message in that module's area; when the module recovers, traffic
resumes automatically. The gateway itself limits how much traffic and how large
requests it accepts from the public network.

**Why this priority**: Important for production quality but not for delivering
the first working platform.

**Independent Test**: Make a test module hang; requests to it fail within the
bound, subsequent requests are refused immediately for a cool-down, other
modules are unaffected, and the module is served again after it answers health
checks.

**Acceptance Scenarios**:

1. **Given** a module that stops answering, **When** users call its routes, **Then** they receive "temporarily unavailable" within the configured bound and the module is marked unhealthy.
2. **Given** an unhealthy module, **When** it starts answering health checks again, **Then** traffic resumes without operator action and the recovery is recorded.
3. **Given** a burst of requests from one origin beyond the public limits, **When** the burst continues, **Then** excess requests are refused with a retry hint while other origins are unaffected.

---

### Edge Cases

- Two instances of the same module register simultaneously: the gateway treats them as one module with several backends and load-balances; manifests must match, otherwise the later one is refused.
- A module re-registers with a changed manifest (new routes, changed permissions): the new manifest replaces the old atomically; in-flight requests complete under the old rules.
- A module declares a permission that is not registered in the authentication module: the registration is accepted but the route is treated as unreachable ("forbidden" for everyone) until the permission exists, and the mismatch is surfaced to operators.
- The authentication module itself is unavailable: protected routes are refused ("temporarily unavailable"), public routes and the shell's outage page keep working; nothing is forwarded on stale decisions beyond the platform's stated bound.
- A request path matches no module: "not found" without revealing which prefixes exist.
- Identity headers arriving from the public network: the gateway strips any caller-supplied identity information before adding its own verified identity.
- Very large uploads or slow clients: refused or cut off at the gateway's limits before any module is involved.
- A federated interface and its module's API are versioned independently and become incompatible: the module area shows its own error; the shell and other modules are unaffected.
- A gRPC client opens a stream and its permission is revoked mid-stream: the stream is closed with the standard "forbidden" status within the propagation bound; new calls are refused.
- A machine client presents a token issued for a different audience (for example a token meant for a module-to-module call): refused as `unauthenticated`, audited once per call.
- The gateway restarts: modules renew their registrations and are routable again within the lease period; the shell shows "temporarily unavailable" for modules not yet re-registered.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The gateway MUST be the only platform component that accepts connections from the public network; all other modules MUST be reachable solely through the private service channel.
- **FR-002**: Modules MUST register with the gateway at start-up by presenting their service identity and a manifest containing: module name, owned path prefix, routes (path pattern, method, required permission or explicit public marker), federated interface location and navigation entries.
- **FR-003**: The gateway MUST validate manifests (unique name, non-overlapping prefix, every route protected or explicitly public, well-formed permission references) and refuse invalid or conflicting registrations with a specific reason.
- **FR-004**: Registrations MUST be leases: modules renew them periodically; a registration whose lease expires is withdrawn automatically.
- **FR-005**: The gateway MUST forward public requests to the module owning the matching prefix over the private service channel, with the module's identity verified, and return the module's response unchanged apart from gateway-controlled headers.
- **FR-006**: Before forwarding a protected route, the gateway MUST establish the caller's identity (user, tenant, roles) from the platform authentication module and verify the caller holds the route's required permission in their tenant.
- **FR-007**: The gateway MUST attach the verified identity to forwarded requests in a form modules can trust and MUST remove any identity claims supplied by the public caller.
- **FR-008**: Refusals MUST use the platform's uniform answers (`unauthenticated`, `forbidden`, `not_found`, `temporarily_unavailable`, `rate_limited`) without revealing registered prefixes, module names or internal addresses.
- **FR-009**: Public routes MUST be forwarded without an identity check but MUST remain subject to rate and size limits.
- **FR-010**: Permission changes made in the authentication module MUST take effect at the gateway within the platform's propagation bound (5 seconds).
- **FR-011**: The gateway MUST serve the platform shell at the public entry point; the shell MUST build its navigation from registered modules' entries filtered by the user's permissions.
- **FR-012**: Each module MUST expose its user interface as a federated remote; the shell MUST load module interfaces on demand and provide shared foundations (design system, session, API helpers) exactly once.
- **FR-013**: The shell MUST isolate module interface failures to the failing module's area and offer retry.
- **FR-014**: Module interfaces MUST be served to browsers through the gateway (no direct public access to module interface assets).
- **FR-015**: Operators MUST be able to list registrations with manifest, health, last renewal and traffic/refusal counts, drain a module, revoke a registration, and manage the allow-list of identities permitted to register.
- **FR-016**: The gateway MUST health-check registered modules, bound the time it waits for a module, mark modules unhealthy after repeated failures, bypass them for a cool-down and resume automatically on recovery.
- **FR-017**: The gateway MUST apply per-origin and per-route rate limits and request size limits before forwarding.
- **FR-018**: Every registration, renewal refusal, withdrawal, drain, revocation, allow-list change, permission refusal and identity refusal MUST be audited with actor, subject and reason.
- **FR-019**: Operators MUST be able to observe request volume, latency, refusal counts and module health per module.
- **FR-020**: The gateway MUST support several instances of the same module (same manifest) and distribute requests among them.
- **FR-021**: Sign-in, sign-out and session handling MUST work through the gateway's public address so that users never need to contact a module directly.
- **FR-022**: The gateway MUST expose, to modules and operators, a machine-readable description of the registration manifest so modules can be built against it.
- **FR-023**: The gateway MUST serve three kinds of public clients: browsers using the shell and its federated module interfaces (session-based); machine clients calling modules' HTTP routes with platform access tokens; and external clients calling modules' registered service methods over gRPC and gRPC-web through the gateway. Modules declare service methods in their manifest exactly like HTTP routes — each method with its required permission or the explicit public marker — and the same enforcement, limits, audit and error vocabulary apply to all three kinds.
- **FR-024**: For machine and gRPC clients the gateway MUST establish identity from the platform access token (verified without contacting the authentication module on every call, and honouring revocations within the propagation bound) and MUST refuse calls whose token is missing, expired, revoked, issued for another audience or lacking the route's permission.
- **FR-025**: Streaming service methods MUST be forwarded with the permission decided once at stream start; a permission revoked during a long-lived stream MUST terminate the stream within the propagation bound.

### Security Requirements *(mandatory — Constitution: Development Workflow)*

- **Trust boundaries crossed**: public HTTPS ingress (browsers, machine HTTP clients and external gRPC/gRPC-web clients) → gateway; gateway → private modules over the mutually authenticated service channel; gateway → authentication module for identity and decisions.
- **Data classification**: session credentials, access tokens and API credentials (secret), user identity claims (PII: user id, tenant, roles), module manifests (internal), audit records (internal, tenant-scoped).
- **Authentication/Authorization**: browsers by platform session; machine and gRPC clients by platform access token bound to the gateway audience; module registration and forwarding by service identity under the gateway's policy; permission checks per route via the authentication module's decisions; operations area restricted to platform operators.
- **Threat scenarios**: a rogue or compromised module registering another module's paths to intercept traffic; identity header injection from the public network; confused-deputy calls where the gateway forwards a request the user may not make; enumeration of internal modules through error responses; denial of service through slow or oversized requests; stale permission decisions after revocation; token replay or audience confusion by machine clients; resource exhaustion through long-lived streams; malicious federated interface code loaded into the shell.
- **SR-001**: Only service identities on the gateway's allow-list MAY register, and a module MAY register only prefixes and names not owned by another identity; conflicts MUST be refused and audited.
- **SR-002**: The gateway MUST strip caller-supplied identity information and MUST convey the verified identity to modules in a form modules can verify as originating from the gateway.
- **SR-003**: No protected route MAY be forwarded without a positive permission decision; unavailability of the decision source MUST fail closed.
- **SR-004**: Error answers MUST NOT reveal registered prefixes, module names, internal addresses or whether a user exists.
- **SR-005**: The gateway MUST apply the platform's browser protections (strict content security policy that admits only interfaces of registered modules, CSRF protection for state-changing calls, secure cookies, security headers) to the shell and every forwarded browser route.
- **SR-006**: Federated interfaces MUST only be loaded from locations declared in a current registration and served through the gateway; the shell MUST refuse any other origin.
- **SR-007**: Credentials, tokens and session identifiers MUST never appear in gateway logs, audit records or error bodies.
- **SR-008**: Rate limits, request size limits and per-module time bounds MUST be enforced before any module is contacted.
- **SR-009**: Access tokens accepted from machine and gRPC clients MUST be verified for signature, issuer, audience, expiry and revocation; the number of concurrent streams and their lifetime per client MUST be bounded.

### Key Entities

- **Module registration**: a module's presence at the gateway — module name, registering service identity, manifest, lease expiry, health state (healthy, unhealthy, draining, revoked), backend instances.
- **Manifest**: what a module declares — owned prefix, routes, federated interface location, navigation entries, version.
- **Route**: a path pattern and method under a module's prefix with its protection: a required permission (`resource:action`) or the explicit public marker.
- **Navigation entry**: title, path and required permission a module contributes to the shell's navigation, with ordering.
- **Federated interface**: the loadable user interface a module exposes and the shared foundations it expects from the shell.
- **Allow-list entry**: a service identity permitted to register, with the prefixes it may claim.
- **Forwarded identity**: the verified caller identity (user, tenant, roles, session) the gateway attaches to a request.
- **Audit event**: registration, renewal refusal, withdrawal, drain, revocation, allow-list change, permission or identity refusal — with actor, subject, reason and correlation.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A new module becomes routable within 10 seconds of starting, with no gateway redeployment or configuration change.
- **SC-002**: 100 % of requests to protected routes without the required permission are refused before reaching a module, across a test matrix covering every registered route.
- **SC-003**: The gateway adds no more than 10 ms at the 95th percentile to a forwarded request under 1,000 concurrent users.
- **SC-004**: A permission revoked in the authentication module is enforced at the gateway within 5 seconds.
- **SC-005**: A module's routes are withdrawn within one lease period (30 seconds) of the module stopping, and restored within 10 seconds of it returning.
- **SC-006**: When one module is unavailable, requests to every other module keep succeeding at their normal rate, and users see the outage only inside that module's area.
- **SC-007**: A user signs in once and uses interfaces from at least three modules without signing in again or reloading the page.
- **SC-008**: 0 % of gateway error responses reveal internal names, addresses or prefixes in a scan of the negative test matrix.
- **SC-009**: 100 % of registrations, withdrawals, drains, revocations and refusals in the test matrix produce exactly one audit event.
- **SC-011**: An external gRPC client with a valid token completes a registered unary call and a streaming call through the gateway; the same client with a revoked token is refused within 5 seconds, and a client with a token for another audience is refused on the first call.
- **SC-010**: The shell passes accessibility checks (no serious or critical issues) with three modules loaded, and first render of the shell completes within 3 seconds on a standard connection.

## Assumptions

- The gateway is built on the platform framework and reuses its private service channel, service identities and policy for module registration and forwarding; modules are already reachable to the gateway over that channel.
- End-user identity, sessions, tokens and permission decisions come from the authentication module (`002-tenant-auth-service`); the gateway does not store users or permissions itself, only registrations.
- The authentication module is itself registered behind the gateway; its browser console is converted into a federated remote as part of this feature, and its sign-in flow is reached through the gateway's public address.
- Machine and external gRPC clients obtain access tokens from the authentication module's client-application flow; API key issuance is out of scope.
- Public traffic is HTTPS (HTTP/1.1 and HTTP/2, the latter also carrying gRPC and gRPC-web); the platform's existing browser protections (edge listener, CSP with nonces, CSRF double-submit, security headers, rate limits) are applied by the gateway.
- Registration leases renew every 10 seconds and expire after 30 seconds without renewal; these values are configurable.
- Permission references use the platform's `resource:action` form and are registered in the authentication module by the same module that declares them in its manifest.
- Each module team owns its federated interface and its navigation entries; the shell owns layout, navigation, session state and the outage/error experience.
- Tenancy is inherited from the authenticated user; the gateway never lets a request act in a tenant other than the caller's.
- Module interface assets are served through the gateway from the module's private location; a content delivery network is out of scope for v1.
- The service is placed under `services/gateway` and structured to move to its own repository later, like `services/auth`.
