# Contract: Gateway console listener (`console:`)

Listener: `console.addr` (default `:8444`), TLS 1.3 only, ALPN `http/1.1`,
certificate = `edge.cert_file`/`edge.key_file` (reloaded every minute).

## Routing

| Request path | Result |
|---|---|
| refused by `route.Normalize` (`..`, `//`, control chars, > 2 KiB) | `404` |
| starts with a configured prefix (e.g. `/bmc/`) | forwarded to that module |
| anything else (incl. `/`, `/api/…`, `/gateway/v1/…`, `/m/…`) | `404`, no module contacted |

Forwarding: module state must be `active` and have a healthy instance,
else `503 {"reason":"temporarily_unavailable"}`. The path and query are
forwarded unchanged. `Connection: Upgrade` / `Upgrade: websocket` requests
are relayed (HTTP/1.1 to the module) for at most `console.session_max`.
Plain requests: deadline `forward.module_timeout` (`504` on expiry), body
limit `forward.body_bytes` (`413`). More than `console.max_concurrent`
in-flight requests: `503`.

## Request headers to the module

| Header | Treatment |
|---|---|
| `Cookie` | rebuilt with allow-listed names only (`console.cookies`, default `freya_kvm`); removed when none |
| `Authorization`, `Proxy-Authorization` | removed |
| `Forwarded`, `X-Forwarded-*`, `X-Real-IP`, `X-Request-Id`, `X-CSP-Nonce`, `X-Freya-*`, `X-Gateway-*` | removed |
| `X-Request-Id` | set (correlation id) |
| `X-Forwarded-Proto` / `X-Forwarded-Host` | `https` / console host |
| `X-Gateway-Module` | module name |

## Response headers to the browser

| Header | Value |
|---|---|
| `Set-Cookie` | only allow-listed names relayed |
| `Content-Security-Policy` | console policy (research D6), `frame-ancestors <portal public origin>` |
| `X-Frame-Options` | absent |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` |
| `Referrer-Policy` | `no-referrer` |
| `Cache-Control` | `no-store` |
| `Cross-Origin-Opener-Policy` / `-Resource-Policy` | `same-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=(), usb=()` |

Upstream CSP, CSP-Report-Only, XFO, HSTS, COOP, COEP, CORP,
Permissions-Policy, Cache-Control, Pragma and Expires are discarded.
