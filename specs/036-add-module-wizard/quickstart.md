# Quickstart: Add-Module Wizard

1. Modules › sms-gw › Add: fill advertise host and bind IP, keep 24 h.
2. Download `sms-gw-join.zip`; on the module host: `unzip`, `cd sms-gw`,
   `docker compose run --rm sms-gw preflight -config /app/config.yaml`,
   `docker compose up -d`.
3. The wizard shows token used, registered, active.
4. Allow-list has the sms-gw entry; `.env` GATEWAY_ISSUER equals the
   gateway's auth.issuer.
