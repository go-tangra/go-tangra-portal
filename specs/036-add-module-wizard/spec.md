# Feature Specification: Add-Module Wizard (gateway module catalogue, phase 3)

**Feature Branch**: `036-add-module-wizard`
**Created**: 2026-10-10
**Status**: Draft
**Input**: Gateway module catalogue design, phase 3: pick a module from the
catalogue; the gateway mints a join token (up to 24 h) and adds the
allow-list entry; it renders a join bundle whose `.env` and module config are
filled from the gateway's own configuration; install progress shows live.

## Context

Installing sms-gw on a remote host on 2026-10-09 took most of a day: about a
dozen core values typed by hand, one of them (`GATEWAY_ISSUER`) wrong, a
30-minute token that expired twice, and an allow-list entry added separately.
Phase 2 (035) gives the gateway each module's verified bundle. This feature
turns it into a download that runs as is.

Decisions (2026-10-10): the join bundle includes the module's config
template with known values filled in (for asterisk, `binding.tenant_id`);
`min_core` only warns; only platform-tenant administrators add modules.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Download a ready-to-run join bundle (Priority: P1) 🎯 MVP

An administrator picks sms-gw on the Modules page, clicks **Add**, fills in
the host-specific inputs the module declares (advertise host, bind IP, …) and
downloads `sms-gw-join.zip`. On the remote host they unzip it and run
`docker compose up -d`. Nothing else is typed.

**Why this priority**: This is the outcome the catalogue exists for.

**Independent Test**: Download a bundle for a module with a verified entry;
the zip contains compose, `.env` with every core value equal to the
gateway's own (issuer, trust domain, enrolment URL, discovery targets, mesh
CA, tenant), the rendered config with no unresolved `${…}`, a fresh join
token, and generated local store passwords; `preflight` inside the bundle
passes its offline checks.

**Acceptance Scenarios**:

1. **Given** a verified entry for sms-gw, **When** an administrator submits
   the host inputs, **Then** a zip is returned once (`no-store`) with every
   file rendered; `GATEWAY_ISSUER` equals the gateway's `auth.issuer`.
2. **Given** a required host input is missing or invalid, **Then** 400 names
   the input and nothing is minted.
3. **Given** the core is older than the entry's `min_core`, **Then** the
   wizard warns but the download still works.
4. **Given** a non-administrator, **Then** 403 and nothing is minted.

---

### User Story 2 - Token and allow-list in one step (Priority: P1)

The bundle's join token is valid for up to 24 hours (default 24 h, chosen in
the wizard), single use, and authorises only that module's SPIFFE id. Minting
it adds (or keeps) the allow-list entry for the module's SPIFFE id with the
prefixes and names from the catalogue entry.

**Why this priority**: The two manual steps that failed most on 2026-10-09.

**Independent Test**: After a download, the allow-list has an active entry
for `spiffe://<td>/svc/<module>` with the entry's prefixes and names; the
token's expiry is the chosen lifetime; using it twice fails at lcm.

**Acceptance Scenarios**:

1. **Given** no allow-list entry, **When** a bundle is generated, **Then** one
   is created with the entry's prefixes and names, audited.
2. **Given** an identical active entry, **Then** it is kept (no duplicate).
3. **Given** an active entry with different prefixes or names, **Then** 409
   with both versions; nothing is changed or minted (an administrator
   resolves it on the allow-list page).
4. **Given** a lifetime above 24 h, **Then** 400.

---

### User Story 3 - Watch the install (Priority: P2)

After the download, the wizard shows live progress for that module: **token
used** → **registered** → **active**, with the time of each step, and the
last refusal reason if registration was refused.

**Why this priority**: Turns "it doesn't show up" into a visible step.

**Independent Test**: With the wizard open, consuming the token marks "token
used"; the module registering marks "registered" then "active".

**Acceptance Scenarios**:

1. **Given** a downloaded bundle, **When** the token is consumed at lcm,
   **Then** the step "token used" is marked within 10 s.
2. **When** the module registers, **Then** "registered" and "active" are
   marked from the registry's live events.
3. **When** a registration is refused (e.g. identity not allowed), **Then**
   the reason is shown.

### Edge Cases

- The module's entry has no bundle (not migrated): Add is not offered.
- The entry's bundle digest does not match the stored bundle: 503, nothing
  minted.
- Auth unreachable: 503, nothing minted, no allow-list change.
- The allow-list is written before minting; if the mint then fails, the
  entry stays (it is valid on its own and audited) and the request answers
  503.
- Two administrators add the same module at once: both bundles work; the
  allow-list keeps one entry; the first token used wins (each token is
  separate and single use).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Auth MUST mint enrolment tokens with a lifetime up to 24 h when
  asked (default unchanged: 10 min; the current 30 min cap rises to 24 h);
  a request above 24 h MUST be refused, not silently shortened.
- **FR-002**: Auth MUST report whether an enrolment token (by JTI) has been
  consumed, to the gateway only.
- **FR-003**: `POST /gateway/v1/ops/catalogue/{module}/join` MUST, for an
  administrator: validate host inputs against the entry; ensure the
  allow-list entry; mint a token for exactly `spiffe://<td>/svc/<module>`;
  render and return the bundle zip; audit `module_join_bundle` without the
  token or secrets.
- **FR-004**: Rendering MUST substitute `${NAME}` placeholders in the
  entry's declared template files with: core values from the gateway's
  configuration, host inputs, generated values (store passwords, local TLS
  material) and the token; any placeholder left unresolved MUST fail the
  request (500 is never returned to the client: 503 `temporarily_unavailable`
  with the detail logged).
- **FR-005**: `GET /gateway/v1/ops/catalogue/{module}/join/{id}` MUST return
  the install progress (token used, registered, active, last refusal) for a
  bundle generated by this gateway, for 24 h.
- **FR-006**: The console MUST offer **Add** on available modules (and on
  down modules: re-install), a form for the declared host inputs and the
  token lifetime, the download, and the live progress.

### Security Requirements *(mandatory)*

- **Trust boundaries crossed**: browser → gateway (admin); gateway → auth
  (mesh mTLS); download to an operator's machine.
- **Data classification**: the bundle carries credentials: the join token,
  generated store passwords and local TLS keys.
- **Authentication/Authorization**: platform-tenant administrators; auth's
  mint and status RPCs only for the gateway's SPIFFE id.
- **Threat scenarios**: bundle leakage (token, passwords); token replay;
  allow-list widening by a crafted entry; template injection through host
  inputs; log or audit leakage of secrets.
- **SR-001**: The response MUST carry `Cache-Control: no-store`; nothing in
  the bundle except the entry and the progress record is kept by the gateway.
- **SR-002**: Token, passwords and keys MUST NOT appear in logs or audit.
- **SR-003**: Host inputs MUST match each input's declared pattern; values
  MUST NOT contain newlines, `$` or quotes, and are written to `.env` quoted.
- **SR-004**: The allow-list entry MUST use only the entry's declared prefixes
  and names, which MUST be under `/api/<module>`, `/m/<module>` or
  `/<module>` and equal `<module>` respectively.
- **SR-005**: The token MUST name only the module's own SPIFFE id.

### Key Entities

- **Host input**: declared in the entry (key, label, pattern, default).
- **Join bundle**: the rendered zip; never stored.
- **Join record**: id, module, JTI, minted by, expires; kept 24 h for progress.

## Success Criteria *(mandatory)*

- **SC-001**: Installing a pilot module on a new host needs only the zip and
  `docker compose up -d`.
- **SC-002**: Every core value in a generated `.env` equals the gateway's
  configuration (tested).
- **SC-003**: The 2026-10-09 failures (wrong issuer, expired token, missing
  allow-list entry) cannot occur with a generated bundle (tested).

## Assumptions

- Pilot modules: sms-gw and asterisk (phase 2 pilots).
- The gateway knows its public origin, `auth.issuer`, trust domain, mesh CA
  bundle and the mesh addresses modules use (new `catalogue.join` config
  block for the addresses remote hosts reach).

## Dependencies

- 035-catalogue-sources (verified entries and bundles).
- go-tangra-auth: 24 h join tokens and token status RPC.
