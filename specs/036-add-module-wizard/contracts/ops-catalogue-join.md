# Contract: join endpoints (gateway) and TokenStatus (auth)

## POST /gateway/v1/ops/catalogue/{module}/join

Administrator only. Body:

```json
{ "inputs": { "MODULE_ADVERTISE_HOST": "sms-gw.example.com", "MODULE_BIND_IP": "10.0.0.5" }, "ttl_hours": 24 }
```

`ttl_hours`: 1–24 (default 24). `inputs`: exactly the entry's `host_inputs`
keys, each matching its pattern.

| Status | Body |
|---|---|
| 200 | `application/zip`, `Content-Disposition: attachment; filename="<module>-join.zip"`, headers `X-Join-Id`, `X-Join-Expires`; `Cache-Control: no-store` |
| 400 `validation_failed` | `detail.param` = input key or `ttl_hours` |
| 403 | not an administrator |
| 404 | no verified entry with a bundle for the module |
| 409 `conflict` | an active allow-list entry for the module's SPIFFE id differs |
| 503 | auth unreachable, bundle digest mismatch, rendering failure |

Zip layout: `<module>/` + bundle files rendered; `<module>/.env`;
`<module>/private/enrollment.token` (0600); `<module>/private/mesh-ca.pem`;
generated TLS files under `<module>/private/tls/` when declared.

## GET /gateway/v1/ops/catalogue/{module}/join/{id}

Administrator only. `{ "id", "module", "created_at", "expires_at",
"token_used": bool, "token_used_at"?, "registered": bool, "state"?,
"last_refusal"?: {"reason","at"} }`. 404 after 24 h past expiry.

## auth.v1.Enrollment/TokenStatus

`TokenStatusRequest{ jti }` → `TokenStatusResponse{ consumed bool,
consumed_at Timestamp }`. Unknown JTI → `consumed=false`. Caller must be the
gateway (policy).
