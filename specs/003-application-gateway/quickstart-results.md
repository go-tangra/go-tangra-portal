# Quickstart results — 003 Application Gateway

**Run**: 2026-09-16 on the development workstation (4 cores, Docker, Go 1.26, Node 22, Google Chrome).
Stack: `services/gateway/deploy/compose.yaml` (TimescaleDB, Valkey, OpenFGA, Mailpit), auth in
gateway mode (`deploy/gateway-mode.yaml`), gateway (`-tags shell`), hello module (`-tags ui`).

| § | Scenario | Result |
|---|----------|--------|
| 1 | Build + gates: `make test`, `make cover` (89.1 % total; authz/route/identity/manifest 100 %), `make lint` (vet, staticcheck, gosec), `make vuln`, `npm run test:unit`/`lint`/`build` for the shell, `npm audit --omit=dev` = 0 | ✅ |
| 2 | Bootstrap auth (gateway mode) and the gateway allow-list; start auth, gateway, hello: `registration_accepted` for `auth` and `hello` within seconds; `GET /` serves the shell, `/api/v1/session` → 401 through the gateway, `/api/hello` → 200, `/m/auth/mf-manifest.json` and `/m/hello/mf-manifest.json` → 200, `/api/nowhere` → `not_found` | ✅ |
| 3 | One entry point, one sign-in: accept the operator invitation and sign in through the gateway (`/api/v1/*` relayed with cookies), `GET /gateway/v1/me` reports the session identity, `/me/modules` lists auth + hello with permitted navigation, `/me/abilities` returns the operator's packed CASL rules; Playwright: sign-in (with TOTP enrolment), shell composition, no reload between remotes, isolated remote failure, sign-out everywhere, axe | ✅ (API + e2e: 4/4 Playwright specs pass against the live stack, `PW_CHANNEL=chrome`) |
| 4 | Permission matrix (integration `TestPermissionMatrix`, `TestHeaderInjectionAndErrorHygiene`, `TestTokenMatrix`): public/anonymous/without/with permission, body limits, forwarded identity, error hygiene | ✅ |
| 5 | Abilities vs decisions (`TestAbilitiesMatchDecisions`), remote origins (`TestRemoteOrigins`) | ✅ |
| 6 | gRPC and gRPC-web ingress, revocation terminating streams, decision outage failing closed (`TestGRPCIngressAndBridge`, `TestDecisionOutageFailsClosed`, `TestSigninThroughGateway`) | ✅ |
| 7 | Leases (`TestRegistrationLifecycle`, `TestPrefixHijackAndUnknownIdentity`), drain/undrain/revoke/allow-list with audit (`TestOperatorControls`), degradation and hardening (`TestDegradation`, `TestHardening`) | ✅ |
| 8 | Redaction scan (`TestRedaction`: gateway log, audit details, error bodies, module-observed headers); performance gate | ✅ redaction / ⚠️ perf (below) |

## Performance (SC-003)

`BenchmarkForward` at 1,000 concurrent clients on this 4-core workstation: p95 via gateway
952 ms, p95 direct 761 ms, i.e. ~190 ms added p95 — far above the 10 ms target, but the
direct path itself saturates the machine at that concurrency (the target assumes a sized
environment). The benchmark and `scripts/perf-gate.sh` are in place; SC-003 remains to be
confirmed on production-class hardware.

## Notes

- Sign-out through the gateway revealed two defects, both fixed: the dev Valkey ACL users
  lacked channel permissions (`&*`), so the auth service's revocation publish failed and
  sign-out returned 500; and the shell's catch-all route was public, so an anonymous browser
  on a module path stayed on "not found" instead of going to sign-in.

- The platform tenant requires a second factor: the first sign-in enrols TOTP (the e2e
  helper computes codes); machine clients use access tokens minted from the session.
- Bearer tokens carry no operator flag; operations screens need the browser session.
