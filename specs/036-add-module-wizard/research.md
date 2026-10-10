# Research: Add-Module Wizard

## R1. Token lifetime up to 24 h

**Decision**: auth's `maxEnrollLifetime` rises from 30 min to 24 h; a request
above the maximum is refused (`InvalidArgument`) instead of being silently
replaced by the 10-minute default (today's behaviour hid the cap). The
default stays 10 min, so `authsvc mint-enrollment-token` and other callers
are unchanged.

**Safety**: tokens stay single-use (JTI burned in `enrollment_jti`, pruned
only after expiry, so a 24 h token is protected for its whole life) and name
exact SPIFFE paths.

## R2. "Token used" progress

**Decision**: new auth RPC `auth.v1.Enrollment/TokenStatus(jti) →
{consumed, consumed_at}` reading `enrollment_jti`; policy allows only the
gateway's SPIFFE id. The gateway reads the JTI from the token it just minted
(it parses its own token's payload without trusting it for anything else).

**Alternative**: lcm events (rejected: lcm has no event channel to the
gateway; auth already holds the ledger).

## R3. Rendering

**Decision**: `${NAME}` placeholders in the files listed by the entry's
`bundle.templates`; names `[A-Z][A-Z0-9_]*`; values from the core map, host
inputs and generated secrets. Unknown placeholders fail rendering (never
written half-rendered). Non-template files are copied as they are. `.env` is
generated from all values (quoted), so compose files can also use `${NAME}`.

## R4. Local secrets

**Decision**: the gateway generates the bundle's store passwords
(`GEN_PASSWORD_1..4`, 24 random bytes hex) and a local CA plus a server
certificate for `LOCAL_TLS_HOSTS` (declared by the entry) with
`crypto/x509` (ECDSA P-256, 10 years CA, 2 years leaf), writes them into
`private/` in the zip, and keeps nothing.

**Threat**: the zip carries secrets; it is returned once with `no-store`,
only to administrators, audited without them.

## R5. Core values

From gateway configuration: `TRUST_DOMAIN` (trust domain), `GATEWAY_ISSUER`
(`auth.issuer`), `LCM_ENROLL_URL` (`catalogue.join.enroll_url`, default
`<public_origin>/api/lcm/v1/enroll`), `AUTH_GRPC`, `GATEWAY_GRPC`, `LCM_GRPC`
(`catalogue.join.*`: the addresses remote hosts reach), `MESH_TENANT_ID`
(default `00000000-0000-0000-0000-000000000001`), mesh CA (the gateway's own
trust bundle), `MODULE_VERSION`, `MODULE_IMAGE`.

## R6. Progress record

Join records (id, module, jti, minted_by, created_at, expires_at) live in
the gateway Postgres for 24 h after expiry (table `catalogue_joins`). Progress
= auth TokenStatus + registry state + the last `registration_refused` audit
event for the module since the join.

## STRIDE

| Threat | Mitigation |
|---|---|
| Spoofing: non-admin downloads a bundle | admin gate before any side effect |
| Tampering: crafted entry widens allow-list | SR-004 prefix scope enforced again at join time |
| Tampering: host input injects YAML/env | SR-003 patterns, no newline/`$`/quotes, quoted `.env` |
| Repudiation | `module_join_bundle` audit (module, admin, jti, expiry) |
| Information disclosure | no-store; token, passwords, keys never logged/audited |
| DoS | entry bundle size limits (phase 2), one mint per request |
| Elevation | token names only `spiffe://<td>/svc/<module>`; TokenStatus only for the gateway |
