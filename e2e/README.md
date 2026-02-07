# E2E Test Suite

End-to-end tests for the complete LCM (Certificate Lifecycle Management) stack.

## Overview

This test suite validates the entire certificate lifecycle using **mTLS authentication**. After the initial client registration, all operations use the client certificate for authentication - no username/password required.

**Test Flow:**
1. **Client Registration** - Register with LCM server, obtain client certificate
2. **Issuer Creation** - Create certificate issuers via mTLS
3. **Certificate Request** - Request certificates via mTLS
4. **Certificate Download** - Download issued certificates via mTLS
5. **Nginx Installation** - Install certificates in nginx

## Quick Start

```bash
# 1. Copy the example environment file
cp .env.example .env

# 2. Edit .env with your configuration (optional for basic tests)
vim .env

# 3. Run the tests
./scripts/run-e2e.sh
```

## Architecture

All client operations use mTLS authentication with the certificate obtained during registration:

```
┌─────────────────────────────────────────────────────────────┐
│                     E2E Test Environment                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐         mTLS          ┌──────────────┐   │
│  │  nginx-lcm   │◀──────────────────────▶│ lcm-service  │   │
│  │  (test client)│    (client cert)      │   (gRPC)     │   │
│  └──────────────┘                        └──────────────┘   │
│         │                                       │           │
│         │ local                                 │ internal  │
│         │ install                               │           │
│         ▼                                       ▼           │
│  ┌──────────────┐                        ┌──────────────┐   │
│  │    nginx     │                        │   postgres   │   │
│  │  (SSL/TLS)   │                        │    redis     │   │
│  └──────────────┘                        └──────────────┘   │
│                                                              │
│  ┌──────────────┐    For debugging:                         │
│  │   frontend   │◀──────────────────────▶│admin-service │   │
│  │ :8080 (opt)  │                        │   :7788      │   │
│  └──────────────┘                        └──────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

### Basic Configuration (Self-Signed Tests)

For basic tests using self-signed certificates, the defaults work out of the box:

```bash
# .env (defaults are fine for basic tests)
LCM_SHARED_SECRET=e2e-test-secret
LCM_CLIENT_ID=nginx-e2e-test
TEST_DOMAIN=e2e-test.example.com
```

### ACME Configuration (Real Certificates)

To test with real ACME certificates (Let's Encrypt):

```bash
# .env
SKIP_ACME_TESTS=false
ACME_EMAIL=your-email@example.com
ACME_ENDPOINT=https://acme-staging-v02.api.letsencrypt.org/directory

# Cloudflare DNS for DNS-01 challenges
CLOUDFLARE_API_TOKEN=your-cloudflare-api-token
CLOUDFLARE_ZONE_ID=your-zone-id
TEST_DOMAIN=real-domain-you-control.com
```

## Test Runner Options

```bash
# Run all tests with clean start
./scripts/run-e2e.sh

# Run without cleaning volumes (faster for re-runs)
./scripts/run-e2e.sh --no-clean

# Run without rebuilding images
./scripts/run-e2e.sh --no-build

# Start services but don't run tests (for manual testing)
./scripts/run-e2e.sh --no-tests

# Keep services running after tests
./scripts/run-e2e.sh --keep-running

# Run only specific tests
./scripts/run-e2e.sh --filter "nginx"

# Combine options
./scripts/run-e2e.sh --no-clean --no-build --filter "certificate"
```

## Manual Testing

After starting services with `--keep-running`:

```bash
# View logs
docker compose -f docker-compose.e2e.yaml logs -f

# Access nginx-lcm container
docker compose -f docker-compose.e2e.yaml exec nginx-lcm bash

# Run tests manually
docker compose -f docker-compose.e2e.yaml exec nginx-lcm /e2e/test-full-flow.sh

# Run specific test with verbose output
docker compose -f docker-compose.e2e.yaml exec nginx-lcm /e2e/test-full-flow.sh --filter "issuer" --verbose

# Access frontend for debugging (http://localhost:8080)
# Default login: admin / Admin@123456

# Stop and cleanup
docker compose -f docker-compose.e2e.yaml down -v
```

## Test Flow Details

### 1. Prerequisites
- Check nginx is running
- Check LCM client is installed
- Check LCM server is reachable

### 2. LCM Client Registration
```bash
lcm-client register \
  --server lcm-service:9100 \
  --client-id nginx-e2e-test \
  --secret e2e-test-secret
```
This obtains:
- Client certificate (`~/.lcm-client/nginx-e2e-test.crt`)
- Client private key (`~/.lcm-client/nginx-e2e-test.key`)
- CA certificate (`~/.lcm-client/ca.crt`)

### 3. Issuer Creation (via mTLS)
```bash
lcm-client issuer create \
  --server lcm-service:9100 \
  --cert ~/.lcm-client/nginx-e2e-test.crt \
  --key ~/.lcm-client/nginx-e2e-test.key \
  --ca ~/.lcm-client/ca.crt \
  --name my-issuer \
  --type self-signed \
  ...
```

### 4. Certificate Request (via mTLS)
```bash
lcm-client job request \
  --server lcm-service:9100 \
  --cert ~/.lcm-client/nginx-e2e-test.crt \
  --key ~/.lcm-client/nginx-e2e-test.key \
  --ca ~/.lcm-client/ca.crt \
  --issuer my-issuer \
  --cn example.com \
  ...
```

### 5. Certificate Download (via mTLS)
```bash
lcm-client job result \
  --server lcm-service:9100 \
  --cert ~/.lcm-client/nginx-e2e-test.crt \
  --key ~/.lcm-client/nginx-e2e-test.key \
  --ca ~/.lcm-client/ca.crt \
  --job-id <job-id> \
  --output-dir ~/.lcm-client/live/example.com
```

### 6. Nginx SSL Installation
```bash
lcm-client nginx install \
  --cert-name example.com \
  --http2 \
  --hsts
```

## Troubleshooting

### Services not starting

```bash
# Check service logs
docker compose -f docker-compose.e2e.yaml logs lcm-service
docker compose -f docker-compose.e2e.yaml logs admin-service

# Check service health
docker compose -f docker-compose.e2e.yaml ps
```

### Registration fails

```bash
# Check LCM service logs
docker compose -f docker-compose.e2e.yaml logs lcm-service | grep -i error

# Verify shared secret matches
grep shared_secret configs/lcm/lcm.yaml
```

### Certificate not being issued

```bash
# Check job status
docker compose -f docker-compose.e2e.yaml exec nginx-lcm \
  lcm-client job status --job-id <job-id> \
  --server lcm-service:9100 \
  --cert ~/.lcm-client/nginx-e2e-test.crt \
  --key ~/.lcm-client/nginx-e2e-test.key \
  --ca ~/.lcm-client/ca.crt
```

### Nginx installation fails

```bash
# Check nginx config
docker compose -f docker-compose.e2e.yaml exec nginx-lcm nginx -t

# Check nginx logs
docker compose -f docker-compose.e2e.yaml exec nginx-lcm cat /var/log/nginx/error.log
```

## Files

```
e2e/
├── docker-compose.e2e.yaml    # Full stack compose file
├── .env.example               # Environment template
├── .env                       # Your configuration (gitignored)
├── configs/                   # Service configurations
│   ├── admin/                 # Admin service config
│   ├── lcm/                   # LCM service config
│   └── deployer/              # Deployer service config
├── scripts/
│   ├── run-e2e.sh            # Main test runner
│   └── test-full-flow.sh     # Test script (runs in nginx-lcm)
└── README.md                  # This file
```

## Authentication Flow

```
                    ┌─────────────────────┐
                    │   1. Registration   │
                    │   (shared secret)   │
                    └──────────┬──────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────┐
│                     LCM Service                           │
│  - Validates shared secret                               │
│  - Issues client certificate                             │
│  - Returns certificate + CA cert                         │
└──────────────────────────────────────────────────────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ 2. All subsequent   │
                    │    operations use   │
                    │    mTLS (client     │
                    │    certificate)     │
                    └─────────────────────┘
```

No API keys, no passwords after registration - just certificate-based authentication.
