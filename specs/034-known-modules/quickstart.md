# Quickstart: Known Modules

Validates the feature end to end on a stack with the gateway and one module.

1. Start the gateway (migration 0005 applies at start) and a module, e.g.
   sms-gw. Open **Gateway operations › Modules**: sms-gw is `active`, with its
   build version, first seen and last seen.
2. Stop sms-gw (`docker compose stop sms-gw`). Within about a minute Modules
   shows sms-gw as `down`, last version unchanged, last seen ≈ when it stopped.
   Registrations no longer lists it.
3. Restart the gateway. sms-gw is still listed as `down`.
4. As an administrator, switch **Expected** off: sms-gw shows `stopped`; the
   audit log has `known_module_expected`. As an operator without `owner` or
   `admin`, the switch is not shown and the API answers 403.
5. Start sms-gw again: it shows `active`, first-seen unchanged.
6. Stop sms-gw, then **Forget** it as an administrator: it disappears; audit
   has `known_module_forgotten`. Forget on a running module answers 409.
7. Start sms-gw: it reappears as `active` and expected.

Database check:

```sql
SELECT module, last_version, last_seen_at, expected, forgotten_at FROM known_modules ORDER BY module;
```
