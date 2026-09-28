# Quickstart: KVM console on port 8444

## Development stack (go-tangra-docker, branch v4)

`configs/gateway.yaml`:

```yaml
console:
  enabled: true
  addr: 0.0.0.0:8444
  public_origin: https://localhost:8444
  routes: { "/bmc/": ipam }
```

`configs/ipam.yaml`: `kvm: { token_ttl_seconds: 300, session_seconds: 3600, console_origin: https://localhost:8444 }`

The compose file publishes `8444:8444` on the gateway. Open
`https://localhost:8444/` once and accept the development certificate (same
certificate as 8443), then in the portal: IPAM → Devices → node-1 → Power / KVM
→ Start session.

Checks:

```sh
curl -sk -o /dev/null -w '%{http_code}\n' https://localhost:8444/            # 404
curl -sk -o /dev/null -w '%{http_code}\n' https://localhost:8444/api/ipam/v1/devices  # 404
curl -sk -o /dev/null -w '%{http_code}\n' https://localhost:8444/bmc/x/?kvmtoken=bad  # 403 (from ipam)
curl -skI https://localhost:8443/ | grep -i content-security   # frame-src 'self' https://localhost:8444
```

## Production

1. `.env`: `CONSOLE_PORT=8444` (default) and optionally `CONSOLE_BIND`.
2. `prod/configs/gateway.yaml`: the `console:` block with
   `public_origin: https://<PUBLIC_HOST>:8444` (prod-init.sh writes it with
   `FORCE=1`; otherwise add by hand).
3. `prod/configs/ipam.yaml`: `kvm.console_origin: https://<PUBLIC_HOST>:8444`.
4. Firewall: allow 8444/tcp from administrators' networks.
5. The public certificate in `prod/edge/` is reused (same host name).
6. Restart `gateway` and `ipam`.
