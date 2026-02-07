# LCM Service Functional Tests

This directory contains functional tests for the LCM (Lifecycle Management) service, including:

- Client registration with mTLS
- Issuer creation (self-signed and ACME)
- Certificate request flow with async processing
- DNS challenge support for ACME

## Prerequisites

1. **Running LCM Server**: The tests connect to a running LCM server
2. **CA Certificate**: The server's CA certificate for TLS verification
3. **Shared Secret**: For client registration (configured per-tenant)
4. **DNS Provider Credentials**: For ACME DNS challenge tests (Let's Encrypt)

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `LCM_TEST_SERVER` | Server address (default: `localhost:9100`) | No |
| `LCM_TEST_CA_FILE` | Path to CA certificate file | Yes |
| `LCM_TEST_SHARED_SECRET` | Shared secret for registration | Yes |
| `LCM_TEST_CONFIG` | Path to DNS config file (default: `testdata/dns_config.yaml`) | No |
| `LCM_TEST_CLIENT_CERT` | Path to client certificate (for issuer/cert tests) | For some tests |
| `LCM_TEST_CLIENT_KEY` | Path to client private key (for issuer/cert tests) | For some tests |
| `LCM_TEST_ISSUER_NAME` | Existing issuer name to use | No |
| `LCM_TEST_OUTPUT_DIR` | Directory to save issued certificates | No |

### DNS Configuration File

Copy `testdata/dns_config.example.yaml` to `testdata/dns_config.yaml` and configure:

```yaml
# ACME configuration
acme:
  endpoint: "https://acme-staging-v02.api.letsencrypt.org/directory"
  email: "admin@example.com"

# DNS provider configuration
dns_provider:
  name: "cloudflare"
  config:
    DnsApiToken: "your-cloudflare-api-token"

# Test domain configuration
test_domain:
  domain: "test.example.com"
  dns_names:
    - "test.example.com"
    - "*.test.example.com"

# Test timeouts
timeouts:
  dns_propagation: 300
  certificate_issuance: 600
  poll_interval: 5
```

## Supported DNS Providers

- `cloudflare` - Cloudflare DNS
- `route53` - AWS Route 53
- `gcloud` - Google Cloud DNS
- `digitalocean` - DigitalOcean DNS
- `pdns` - PowerDNS
- `acmedns` - acme-dns
- And more...

Run `lcm-client issuer dns-providers` to see all available providers and their configuration requirements.

## Running Tests

### All Tests

```bash
# Set required environment variables
export LCM_TEST_CA_FILE=/path/to/ca.crt
export LCM_TEST_SHARED_SECRET=your-shared-secret

# Run all functional tests
go test -v ./app/lcm/service/test/functional/...
```

### Specific Test Suites

```bash
# Client registration only
go test -v -run TestClientRegistration ./app/lcm/service/test/functional/...

# Issuer creation only (requires mTLS client cert)
export LCM_TEST_CLIENT_CERT=/path/to/client.crt
export LCM_TEST_CLIENT_KEY=/path/to/client.key
go test -v -run TestIssuerCreation ./app/lcm/service/test/functional/...

# Certificate request flow (requires mTLS and DNS config)
go test -v -run TestCertificateRequestFlow ./app/lcm/service/test/functional/...

# End-to-end flow
go test -v -run TestEndToEndFlow ./app/lcm/service/test/functional/...
```

### Using the Test Runner Script

```bash
# Make script executable
chmod +x app/lcm/service/test/scripts/run_tests.sh

# Run tests
./app/lcm/service/test/scripts/run_tests.sh
```

## Test Flow

1. **Client Registration**
   - Generates ECDSA key pair
   - Registers client with shared secret
   - Polls for certificate approval
   - Downloads mTLS certificate

2. **Issuer Creation**
   - Creates self-signed issuer
   - Creates ACME issuer with Let's Encrypt
   - Lists DNS providers
   - Lists created issuers

3. **Certificate Request**
   - Submits certificate request (async)
   - Polls job status until completion
   - Downloads issued certificate
   - Validates certificate details

## Troubleshooting

### "client authentication required"
You need to set `LCM_TEST_CLIENT_CERT` and `LCM_TEST_CLIENT_KEY` for tests that require mTLS authentication (issuer creation, certificate requests).

### "DNS propagation failed"
Check that your DNS provider credentials are correct and the domain is properly configured.

### "certificate issuance timeout"
ACME certificate issuance can take up to 15 minutes for DNS challenges. Increase `certificate_issuance` timeout in config.

### "issuer not found"
Either create an issuer first using `TestIssuerCreation` or set `LCM_TEST_ISSUER_NAME` to an existing issuer.

## Security Notes

- Never commit `dns_config.yaml` with real credentials
- Use Let's Encrypt staging for testing
- Keep test certificates separate from production
- Rotate test shared secrets regularly
