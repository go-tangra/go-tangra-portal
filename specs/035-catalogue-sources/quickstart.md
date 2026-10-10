# Quickstart: Catalogue Sources

1. Tag a pilot module (sms-gw). The release carries `catalogue-entry.json`,
   `bundle.zip` and their `.sigstore.json` files;
   `gh attestation verify bundle.zip -R go-tangra/go-tangra-sms-gw` succeeds.
2. As an administrator, Modules › Sources › add `go-tangra/go-tangra-sms-gw`.
   sms-gw shows its latest version and summary.
3. Add `someone/elsewhere`: refused (owner not allowed).
4. With sms-gw running an older build, the row shows update available.
