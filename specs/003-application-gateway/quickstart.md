# Quickstart — Application Gateway

## Prerequisites

Go 1.26, Node 22, Docker with compose; `make testca` at the repository root with
`-services auth,gateway,hello`.

## 1. Stack and gates

```bash
make -C services/gateway compose-up          # TimescaleDB, Valkey, OpenFGA, mailpit
make -C services/gateway lint cover fuzz     # vet, staticcheck, gosec, coverage gate (100 % on internal/{authz,route,identity,manifest})
(cd services/gateway/shell && npm ci && npm run lint && npm run test:unit)
```

## 2. Start auth (gateway mode), the gateway and the example module

```bash
(cd services/auth && ./bin/authsvc bootstrap -config deploy/gateway-mode.yaml -operator-email ops@example.org && ./bin/authsvc -config deploy/gateway-mode.yaml)
(cd services/gateway && go run ./cmd/gatewaysvc bootstrap -config deploy/dev.yaml -allow spiffe://example.org/svc/auth=/api/v1,/authorize,/.well-known -allow spiffe://example.org/svc/hello=/api/hello)
(cd services/gateway && go run ./cmd/gatewaysvc -config deploy/dev.yaml)
(cd services/gateway/examples/hello-module && go run . )
```

Expected: gateway log shows `registration_accepted module=auth` and `module=hello`
within 10 s (SC-001); `GET https://localhost:8443/gateway/v1/me/modules` (after sign-in)
lists both.

## 3. One entry point, one sign-in (US2, US3)

Open https://localhost:8443/ → redirected to the auth remote's sign-in → accept the
operator invitation from mailpit, enrol TOTP → shell home shows navigation with **Auth**
and **Hello** entries. Navigate between them without reload (SC-007). Sign out anywhere →
every module area returns to signed-out.

## 4. Permission matrix (US2, SC-002)

```bash
go test -tags integration ./services/gateway/tests/integration -run 'TestPermissionMatrix|TestHeaderInjection|TestErrorHygiene' -v
```

Expected: every protected route/method refused without the permission before any module
is contacted; injected identity headers stripped; no error body names a module or prefix.

## 5. API and UI agree (CASL)

In the shell, as a user with `hello:read` but not `hello:write`: the Hello page shows
the list and hides the "Create" button (`<Can I="create" a="Hello">`); `curl` to
`POST /api/hello` with the same user's token → 403 `forbidden`. Grant `hello:write` in
the auth console → within 5 s the button appears (SSE refetch) and the POST succeeds
(SC-004; `TestAbilitiesMatchDecisions`).

## 6. Machine and gRPC clients (FR-023)

```bash
TOKEN=$(curl -sk -b cookies https://localhost:8443/api/v1/session/token | jq -r .access_token)
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8443/api/hello
grpcurl -insecure -H "authorization: Bearer $TOKEN" localhost:8443 hello.v1.Hello/Say
```

Expected: 200 / OK with the permission, 403 / PERMISSION_DENIED without; a token with
`aud` of another client → 401 / UNAUTHENTICATED; gRPC-web (`TestGRPCWebBridge`) round-trips
unary and server-streaming calls; a revoked token ends a running stream within 5 s
(`TestStreamTermination`).

## 7. Leases, drain, revoke, resilience (US1, US4, US5)

Stop the hello module → routes withdrawn within 30 s, its area shows "temporarily
unavailable", Auth keeps working (SC-005, SC-006). Start it again → routable within 10 s.
Operations → Registrations: drain hello (new requests 503, in-flight complete), revoke
(renewals refused), audit shows both with the operator identity (SC-009).

## 8. Performance and hygiene gates

```bash
services/gateway/scripts/perf-gate.sh        # p95 overhead < 10 ms at 1,000 concurrency (SC-003)
make -C services/gateway redaction-scan      # cookies/tokens absent from logs, audit, errors
(cd services/gateway/shell && npm run test:e2e)   # Playwright + axe with three modules (SC-010)
```

## Done when

§1–§8 pass on a clean checkout; results recorded in `quickstart-results.md`.
