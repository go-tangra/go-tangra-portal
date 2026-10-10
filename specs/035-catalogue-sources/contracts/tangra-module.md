# Contract: `tangra-module.yaml` and `catalogue-entry.json`

Shared Go types: `github.com/go-tangra/go-tangra/v4/catalogue`.

## tangra-module.yaml (schema 1), at the module repository root

```yaml
schema: 1
module: sms-gw                      # ^[a-z0-9][a-z0-9-]{0,62}$; the manifest module name
display_name: SMS Gateway
category: Communications            # free text, ≤ 40 chars
summary: Hermes SMS API, carrier receipts, callbacks and tenant management.   # ≤ 200 chars
image: ghcr.io/go-tangra/go-tangra-sms-gw   # no tag; the release version is the tag
routes:                             # allow-list scope (phase 3)
  prefixes: [/api/sms-gw, /m/sms-gw, /sms-gw]
  names: [sms-gw]
min_core: { gateway: 4.9.0, auth: 4.10.0 }   # optional; warns only
bundle:
  dir: deploy/bundle                # packed into bundle.zip
  templates: [compose.yaml, config.yaml]     # files with ${NAME} placeholders
host_inputs:                        # asked in the add-module wizard (phase 3)
  - key: MODULE_ADVERTISE_HOST
    label: Host name other modules use to reach it
    pattern: '^[a-z0-9][a-z0-9.-]{0,252}$'
  - key: MODULE_BIND_IP
    label: Private IP its mesh ports bind to
    pattern: '^(\d{1,3}\.){3}\d{1,3}$'
docs: https://github.com/go-tangra/go-tangra-sms-gw#readme   # optional
```

Unknown keys are refused. `routes.prefixes` must be `/api/<module>`,
`/m/<module>`, `/<module>` or under them; `routes.names` must be `[<module>]`.

## catalogue-entry.json (written by the action, attached to the release)

```json
{
  "schema": 1,
  "module": "sms-gw",
  "version": "4.3.0",
  "repository": "go-tangra/go-tangra-sms-gw",
  "display_name": "SMS Gateway",
  "category": "Communications",
  "summary": "…",
  "image": "ghcr.io/go-tangra/go-tangra-sms-gw",
  "routes": { "prefixes": ["/api/sms-gw", "/m/sms-gw", "/sms-gw"], "names": ["sms-gw"] },
  "permissions": ["providers:read", "…"],
  "min_core": { "gateway": "4.9.0", "auth": "4.10.0" },
  "bundle": { "templates": ["compose.yaml", "config.yaml"], "sha256": "…", "size": 4096 },
  "host_inputs": [ { "key": "MODULE_ADVERTISE_HOST", "label": "…", "pattern": "…" } ],
  "docs": "…"
}
```

Release assets: `catalogue-entry.json`, `bundle.zip` and
`catalogue.sigstore.json`, one attestation whose in-toto subjects are both files.

## Placeholders available to templates (phase 3)

Core (from the gateway): `TRUST_DOMAIN`, `GATEWAY_ISSUER`, `LCM_ENROLL_URL`,
`AUTH_GRPC`, `GATEWAY_GRPC`, `LCM_GRPC`, `MESH_TENANT_ID`, `MODULE_VERSION`,
`MODULE_IMAGE`. Generated: `GEN_PASSWORD_1`…`GEN_PASSWORD_4` (48 hex),
`LOCAL_CA_PEM` file, `LOCAL_TLS_CERT`/`KEY` files. Host inputs by key. Files
`private/enrollment.token` and `private/mesh-ca.pem` are written by the gateway.
