# Contract: catalogue sources endpoints (gateway)

All under `/gateway/v1/ops/catalogue`; changes require a platform-tenant
administrator (403 otherwise, audited `permission_refused`).

| Method and path | Body | Result |
|---|---|---|
| `GET /sources` | | `{sources:[{repo,module,last_checked_at,last_error}], allowed_owners:[…]}` (operators may read) |
| `POST /sources` | `{repo:"owner/repo"}` | 201; 400 bad name or owner not allowed; 409 exists; refresh starts |
| `DELETE /sources/{owner}/{repo}` | | 204; entries stay (installed modules keep their entry) |
| `POST /sources/{owner}/{repo}/refresh` | | 200 `{module, version, outcome, error?}` (synchronous, ≤ 30 s) |
| `PUT /allowed-owners` | `{owners:["go-tangra"]}` | 204; 400 bad owner names or empty |
| `POST /upload` | multipart: `entry`, `bundle`, `attestation` | 201 `{module, version}`; 400 verification failure (reason) |

`owner`/`repo`: `^[A-Za-z0-9][A-Za-z0-9-]{0,38}$` / `^[A-Za-z0-9._-]{1,100}$`.
Upload parts are size-limited as polling (entry 256 KiB, bundle 8 MiB,
attestation 64 KiB).
