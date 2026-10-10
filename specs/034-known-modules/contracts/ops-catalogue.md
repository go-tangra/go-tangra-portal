# Contract: Ops catalogue endpoints

Declared in `api/openapi/gateway.yaml`. All responses use the gateway error
envelope (`{"reason": …, "detail"?: …}`).

## GET /gateway/v1/ops/catalogue

Who: platform-tenant member with an operator role or an administrator role.

200:

```json
{
  "can_manage": true,
  "items": [
    {
      "module": "sms-gw",
      "display_name": "SMS Gateway",
      "identity": "spiffe://infra.verax.net/svc/sms-gw",
      "state": "down",
      "registered": false,
      "instances": 0,
      "build_versions": [],
      "last_version": "4.2.0",
      "first_seen_at": "2026-10-09T10:06:16Z",
      "last_seen_at": "2026-10-10T08:55:02Z",
      "expected": true
    }
  ]
}
```

`state` ∈ `active`, `draining`, `unhealthy`, `revoked`, `down`, `stopped`.
Items are sorted by module. A module registered now but not yet recorded is
still listed from the live registry. When the known-module store cannot be
read, the answer is still 200 with `"partial": true` and only the registered
modules.

## PATCH /gateway/v1/ops/catalogue/{module}

Who: platform-tenant administrator. Cookie-bearing calls carry the CSRF
header, enforced by the edge as for every ops mutation.

Body: `{"expected": false}` (required, boolean, no other properties).

| Status | When |
|---|---|
| 204 | updated; audit `known_module_expected` |
| 400 `validation_failed` | bad module name or body |
| 403 `forbidden` | not an administrator (audited `permission_refused`) |
| 404 `not_found` | module unknown or forgotten |
| 503 `temporarily_unavailable` | store error |

## DELETE /gateway/v1/ops/catalogue/{module}

Who: platform-tenant administrator (CSRF as above).

| Status | When |
|---|---|
| 204 | forgotten; audit `known_module_forgotten` |
| 400 `validation_failed` | bad module name |
| 403 `forbidden` | not an administrator (audited `permission_refused`) |
| 404 `not_found` | module unknown or already forgotten |
| 409 `conflict` | module is registered now |
| 503 `temporarily_unavailable` | store error |

`{module}`: `^[a-z0-9][a-z0-9-]{0,62}$`.
