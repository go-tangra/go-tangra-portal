# Contract: IPAM KVM console (go-tangra-ipam-v4)

## `POST /api/ipam/v1/devices/{id}/kvm-session` (unchanged route and auth)

`201 {"token": "<48 hex>", "console_url": "<url>"}`

- `kvm.console_origin` set: `console_url = <origin>/bmc/<device>/?kvmtoken=<token>`
- unset: `console_url = /bmc/<device>/?kvmtoken=<token>` (as before)

gRPC `DeviceService` KVM session: same URL rule.

## `/bmc/{device}/…` (module mesh HTTP; reached via the gateway console listener)

| Request | Result |
|---|---|
| `?kvmtoken=<valid, unused, same device>` | token consumed; console session created; `Set-Cookie: freya_kvm=<64 hex>; Path=/bmc/<device>/; Max-Age=<session_seconds>; HttpOnly; Secure; SameSite=Strict`; BMC page proxied |
| `?kvmtoken=<used/expired/unknown/other device>` | `403` (no BMC contact) |
| cookie `freya_kvm=<live session for this device>` | proxied |
| cookie for another device / expired | `403` |
| `/bmc/{device}/__kvmws` upgrade with a live session and `Origin` = console origin (or any `Origin` when no console origin is configured) | relayed to the BMC WebSocket |
| upgrade with a foreign `Origin` while a console origin is configured | `403` |

To the BMC: `Cookie` is always exactly the server-side `SID=…`; `Referer`
removed; `Origin` (when present) rewritten to `https://<bmc host>`.
From the BMC: `Set-Cookie` and `X-Frame-Options` removed.

## UI (`ipmi-kvm.vue`)

- `console_url` is an absolute `https:` URL → `<iframe src referrerpolicy="no-referrer" allow="fullscreen">`.
- otherwise → alert `KVM console origin not configured` (`data-test=kvm-no-origin`), no iframe.
