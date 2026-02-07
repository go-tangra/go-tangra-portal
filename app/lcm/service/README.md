# LCM - Lifecycle Certificate Manager

LCM is an enterprise-grade certificate lifecycle management service that provides automated certificate issuance, renewal, and distribution with mTLS authentication, multi-tenancy support, and event-driven notifications.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Server Configuration](#server-configuration)
- [Client CLI](#client-cli)
- [API Reference](#api-reference)
- [Webhooks](#webhooks)
- [Daemon Mode & Hooks](#daemon-mode--hooks)
- [Certificate Storage](#certificate-storage)
- [Multi-Tenancy](#multi-tenancy)
- [DNS Providers](#dns-providers)
- [Security](#security)
- [Development](#development)

## Overview

LCM provides a complete solution for managing X.509 certificates in distributed systems. It supports both self-signed CAs for internal PKI and ACME (Let's Encrypt) for public certificates.

**Key Use Cases:**
- Automated mTLS certificate distribution for microservices
- IoT device certificate provisioning
- Internal PKI infrastructure
- Let's Encrypt certificate automation with DNS challenges

## Features

### Certificate Management
- **Automatic CA Generation**: Self-signed root CA created on first startup
- **Async Certificate Issuance**: Job-based processing with status tracking
- **Auto-Approval Mode**: Puppet-style automatic certificate signing
- **Certificate Renewal**: Automated renewal with configurable intervals
- **Revocation Support**: RFC 5280 compliant revocation with reason codes

### Multi-Issuer Support
- **Self-Signed Issuers**: Local CA with ECDSA/RSA key types
- **ACME Issuers**: Let's Encrypt integration with HTTP/DNS challenges
- **Multiple Concurrent Issuers**: Per-tenant or per-use-case issuers

### Security
- **mTLS Authentication**: Client certificate-based authentication
- **Audit Logging**: Cryptographically signed audit trail
- **HMAC Webhook Signatures**: Secure webhook payload verification
- **Tenant Isolation**: Complete resource separation per tenant

### Integration
- **gRPC & REST APIs**: Full-featured APIs with OpenAPI documentation
- **Real-time Streaming**: Server-push certificate updates via gRPC streaming
- **Webhooks**: HTTP callbacks for certificate lifecycle events
- **Deploy Hooks**: Execute scripts on certificate updates (Bash, Lua, JavaScript)
- **Redis Pub/Sub**: Event-driven architecture for async processing

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        LCM Server                                │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   gRPC API  │  │  REST API   │  │   Admin Gateway (HTTP)  │  │
│  └──────┬──────┘  └──────┬──────┘  └────────────┬────────────┘  │
│         │                │                      │                │
│  ┌──────┴────────────────┴──────────────────────┴──────────┐    │
│  │                    Service Layer                         │    │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐           │    │
│  │  │LcmClient   │ │Certificate │ │Mtls        │           │    │
│  │  │Service     │ │JobService  │ │CertService │  ...      │    │
│  │  └────────────┘ └────────────┘ └────────────┘           │    │
│  └─────────────────────────┬────────────────────────────────┘    │
│                            │                                      │
│  ┌─────────────────────────┴────────────────────────────────┐    │
│  │                    Data Layer (ENT ORM)                   │    │
│  │  Certificates │ Clients │ Issuers │ Jobs │ AuditLogs     │    │
│  └─────────────────────────┬────────────────────────────────┘    │
│                            │                                      │
├────────────────────────────┼────────────────────────────────────┤
│  External Dependencies     │                                      │
│  ┌──────────┐  ┌──────────┴───┐  ┌──────────────────────────┐   │
│  │PostgreSQL│  │    Redis     │  │  ACME (Let's Encrypt)    │   │
│  │ /MySQL   │  │  (pub/sub)   │  │  + DNS Providers         │   │
│  └──────────┘  └──────────────┘  └──────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                        LCM Client                                │
├─────────────────────────────────────────────────────────────────┤
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌───────────┐  │
│  │  register  │  │   status   │  │  download  │  │   daemon  │  │
│  └────────────┘  └────────────┘  └────────────┘  └───────────┘  │
│         │                │               │              │        │
│  ┌──────┴────────────────┴───────────────┴──────────────┴───┐   │
│  │                    Storage Layer                          │   │
│  │  ~/.lcm-client/live/<cert>/  │  ~/.lcm-client/renewal/   │   │
│  └───────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Start the Server

```bash
# Navigate to the service directory
cd app/lcm/service

# Configure the service
cp configs/lcm.yaml.example configs/lcm.yaml
# Edit configs/lcm.yaml with your settings

# Build and run
go build -o lcm-server ./cmd/server
./lcm-server
```

### 2. Register a Client

```bash
# Build the client
go build -o lcm-client ./cmd/client

# Register with the server (generates key pair and requests certificate)
./lcm-client register \
  --server localhost:9100 \
  --secret "your-shared-secret" \
  --hostname "my-service.example.com"
```

### 3. Run in Daemon Mode

```bash
# Start daemon to sync certificates and listen for updates
./lcm-client daemon \
  --server localhost:9100 \
  --deploy-hook "/path/to/reload-service.sh"
```

## Server Configuration

### Main Configuration (`configs/lcm.yaml`)

```yaml
# LCM service configuration
data_dir: ./data                      # Directory for certificates and keys
default_validity_days: 365            # Default certificate validity
auto_approve_certificates: true       # Auto-sign mode (like Puppet)
auto_generate_ca: true                # Auto-create self-signed CA on startup
shared_secret: "changeme"             # Shared secret for client registration
ca_cert_path: "./data/ca/ca.crt"      # CA certificate path
ca_key_path: "./data/ca/ca.key"       # CA private key path

# Event notification configuration (Redis pub/sub)
events:
  enabled: true
  topic_prefix: "lcm"

# Webhook notification configuration
webhooks:
  enabled: false
  timeout_seconds: 30
  worker_count: 2
  retry:
    max_attempts: 3
    initial_delay_ms: 1000
    max_delay_ms: 60000
    backoff_multiplier: 2.0
  endpoints:
    - name: "primary"
      url: "https://example.com/webhooks/lcm"
      enabled: true
      event_types:
        - "certificate.issued"
        - "certificate.failed"
        - "renewal.completed"
      secret: "hmac-signing-secret"
      headers:
        Authorization: "Bearer token"
```

### Server Configuration (`configs/server.yaml`)

```yaml
server:
  grpc:
    addr: "0.0.0.0:9100"
    timeout: 10s
    middleware:
      enable_logging: true
      enable_recovery: true
      enable_validate: true

  rest:
    addr: "0.0.0.0:8000"
    timeout: 10s
    enable_swagger: true
    cors:
      origins: ["*"]
      methods: [GET, POST, PUT, DELETE, OPTIONS]
```

## Client CLI

The `lcm-client` CLI provides commands for certificate management operations.

### Global Flags

```bash
--server string       Server address (default "localhost:9100")
--config-dir string   Config directory (default "~/.lcm")
--client-id string    Client identifier (default: machine ID)
--cert string         Client certificate path
--key string          Private key path
--ca string           CA certificate path
```

### Commands

#### `register` - Initial Client Registration

```bash
lcm-client register [flags]

Flags:
  --secret string     Shared secret for authentication (required)
  --hostname string   Certificate hostname (default: system hostname)
  --dns strings       Additional DNS names (can be repeated)
  --ip strings        Additional IP addresses (can be repeated)
  --key-size int      RSA key size: 2048 or 4096 (default 2048)

Example:
  lcm-client register \
    --server lcm.example.com:9100 \
    --secret "registration-secret" \
    --hostname "api.example.com" \
    --dns "api-internal.example.com" \
    --ip "10.0.0.5"
```

#### `status` - Check Certificate Request Status

```bash
lcm-client status --request-id <uuid>

Example:
  lcm-client status --request-id "550e8400-e29b-41d4-a716-446655440000"
```

#### `download` - Download Issued Certificate

```bash
lcm-client download --request-id <uuid>

Example:
  lcm-client download --request-id "550e8400-e29b-41d4-a716-446655440000"
```

#### `daemon` - Run as Background Daemon

```bash
lcm-client daemon [flags]

Flags:
  --deploy-hook string         Path to bash script for certificate deployment
  --deploy-script-hook string  Path to Lua (.lua) or JavaScript (.js) deploy script
  --hook-timeout duration      Hook execution timeout (default 5m)
  --sync-interval duration     Fallback sync interval (default 1h)
  --one-shot                   Sync once and exit (don't stream)

Example:
  # With bash hook
  lcm-client daemon --deploy-hook "/etc/lcm/hooks/reload-nginx.sh"

  # With Lua hook
  lcm-client daemon --deploy-script-hook "/etc/lcm/hooks/deploy.lua"

  # One-shot sync
  lcm-client daemon --one-shot
```

## API Reference

### gRPC Services

#### LcmClientService (Public)
Client registration and certificate operations.

| Method | Description |
|--------|-------------|
| `RegisterLcmClient` | Register new client and request certificate |
| `GetRequestStatus` | Check certificate request status |
| `DownloadClientCertificate` | Download issued certificate with public key verification |
| `ListClientCertificates` | List all certificates for authenticated client |
| `StreamCertificateUpdates` | Real-time certificate update notifications |

#### LcmCertificateJobService
Async certificate job management.

| Method | Description |
|--------|-------------|
| `RequestCertificate` | Submit certificate request (returns job ID) |
| `GetJobStatus` | Poll job status |
| `GetJobResult` | Get certificate + private key on completion |
| `ListJobs` | List jobs for client |
| `CancelJob` | Cancel pending job |

#### LcmMtlsCertificateService (Admin)
Certificate administration.

| Method | Description |
|--------|-------------|
| `ListMtlsCertificates` | List certificates with filters |
| `GetMtlsCertificate` | Get certificate by serial/fingerprint |
| `IssueMtlsCertificate` | Direct certificate issuance |
| `RevokeMtlsCertificate` | Revoke certificate with reason |
| `RenewMtlsCertificate` | Renew existing certificate |
| `DownloadMtlsCertificate` | Download PEM bundle |

#### LcmIssuerService (Admin)
Issuer configuration management.

| Method | Description |
|--------|-------------|
| `ListIssuers` | List configured issuers |
| `GetIssuerInfo` | Get issuer details |
| `CreateIssuer` | Create self-signed or ACME issuer |
| `UpdateIssuer` | Update issuer configuration |
| `DeleteIssuer` | Delete issuer |
| `ListDnsProviders` | List available DNS providers |

#### AuditLogService
Audit trail queries.

| Method | Description |
|--------|-------------|
| `ListAuditLogs` | Query audit logs with filters |
| `GetAuditLog` | Get specific audit entry |
| `GetAuditStats` | Get aggregated statistics |

### Certificate Status Lifecycle

```
Registration Flow:
  PENDING → PROCESSING → ISSUED
                      → FAILED
                      → CANCELLED

Certificate States:
  ACTIVE → EXPIRED
        → REVOKED
        → SUSPENDED
```

## Webhooks

LCM can send HTTP POST notifications to configured endpoints when certificate events occur.

### Event Types

| Event | Description |
|-------|-------------|
| `certificate.requested` | Certificate request submitted |
| `certificate.processing` | Certificate issuance started |
| `certificate.issued` | Certificate successfully issued |
| `certificate.failed` | Certificate issuance failed |
| `certificate.cancelled` | Certificate request cancelled |
| `renewal.scheduled` | Renewal job scheduled |
| `renewal.started` | Renewal processing started |
| `renewal.completed` | Certificate successfully renewed |
| `renewal.failed` | Certificate renewal failed |

### Webhook Payload Format

```json
{
  "id": "evt_abc123",
  "type": "certificate.issued",
  "source": "lcm-service",
  "timestamp": "2025-01-20T10:30:00Z",
  "tenant_id": 1,
  "data": {
    "job_id": "job-uuid",
    "client_id": "my-client",
    "issuer_name": "default-ca",
    "serial_number": "1234567890",
    "common_name": "api.example.com",
    "dns_names": ["api.example.com"],
    "issued_at": "2025-01-20T10:30:00Z",
    "expires_at": "2026-01-20T10:30:00Z"
  }
}
```

### HTTP Headers

```
Content-Type: application/json
X-Webhook-ID: evt_abc123
X-Webhook-Event: certificate.issued
X-Webhook-Signature: sha256=<hmac-signature>
X-Webhook-Timestamp: 1705747800
```

### Signature Verification

The webhook signature is computed as:

```
signature = HMAC-SHA256(secret, timestamp + "." + payload)
```

Example verification (Go):

```go
func verifySignature(payload []byte, timestamp, signature, secret string) bool {
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write([]byte(timestamp + "." + string(payload)))
    expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
    return hmac.Equal([]byte(expected), []byte(signature))
}
```

## Daemon Mode & Hooks

The daemon mode provides continuous certificate synchronization with deploy hook support.

### How Daemon Mode Works

1. Connects to LCM server using mTLS
2. Performs initial sync of all client certificates
3. Subscribes to real-time certificate updates via gRPC streaming
4. Downloads new/renewed certificates to local storage
5. Executes deploy hooks after each certificate update
6. Falls back to periodic sync if streaming disconnects

### Deploy Hooks

#### Bash Scripts (`--deploy-hook`)

```bash
#!/bin/bash
# /etc/lcm/hooks/reload-nginx.sh

echo "Certificate updated: $LCM_CERT_NAME"
echo "Certificate path: $LCM_CERT_PATH"
echo "Private key path: $LCM_KEY_PATH"

# Reload nginx to pick up new certificate
systemctl reload nginx

# Or for Apache
# systemctl reload apache2

# Or restart a Docker container
# docker restart my-app
```

#### Environment Variables Passed to Hooks

| Variable | Description |
|----------|-------------|
| `LCM_HOOK_TYPE` | Hook type (deploy, pre-renewal, post-renewal) |
| `LCM_CERT_NAME` | Certificate name |
| `LCM_CERT_PATH` | Path to certificate file |
| `LCM_KEY_PATH` | Path to private key file |
| `LCM_CHAIN_PATH` | Path to CA chain file |
| `LCM_FULLCHAIN_PATH` | Path to fullchain file (cert + chain) |
| `LCM_COMMON_NAME` | Certificate common name |
| `LCM_DNS_NAMES` | Comma-separated DNS names |
| `LCM_IP_ADDRESSES` | Comma-separated IP addresses |
| `LCM_SERIAL_NUMBER` | Certificate serial number |
| `LCM_EXPIRES_AT` | Certificate expiry (RFC3339) |
| `LCM_IS_RENEWAL` | "true" if renewal, "false" otherwise |

#### Lua Scripts (`--deploy-script-hook`)

```lua
-- /etc/lcm/hooks/deploy.lua

log("Certificate updated: " .. LCM_CERT_NAME)
log("Common name: " .. LCM_COMMON_NAME)
log("Expires at: " .. LCM_EXPIRES_AT)

-- Using the context object
log("DNS names: " .. table.concat(LCM_CONTEXT.dnsNames, ", "))

-- Execute shell command
local output, err = exec("systemctl reload nginx")
if err then
    log("Failed to reload nginx: " .. err)
else
    log("Nginx reloaded successfully")
end

-- Read and write files
local content = readFile("/etc/myapp/config.yaml")
writeFile("/etc/myapp/cert-info.txt", "Serial: " .. LCM_SERIAL_NUMBER)

-- Check if file exists
if fileExists("/etc/myapp/ssl/cert.pem") then
    log("SSL cert exists")
end

-- Get environment variable
local home = getEnv("HOME")
```

#### JavaScript Scripts (`--deploy-script-hook`)

```javascript
// /etc/lcm/hooks/deploy.js

log("Certificate updated: " + LCM_CERT_NAME);
log("Renewal: " + LCM_IS_RENEWAL);

// Access context object
log("DNS names: " + LCM_CONTEXT.dnsNames.join(", "));

// Execute shell command
var result = exec("systemctl reload nginx");
log("Reload output: " + result);

// File operations
var config = readFile("/etc/myapp/config.yaml");
writeFile("/tmp/cert-info.txt", "Serial: " + LCM_SERIAL_NUMBER);

if (fileExists("/etc/myapp/ssl/cert.pem")) {
    log("Certificate file exists");
}
```

### Built-in Functions for Lua/JavaScript

| Function | Description |
|----------|-------------|
| `exec(command)` | Execute shell command, returns output |
| `readFile(path)` | Read file contents |
| `writeFile(path, content)` | Write content to file |
| `fileExists(path)` | Check if file exists |
| `getEnv(key)` | Get environment variable |
| `log(message)` | Print log message |

## Certificate Storage

### Certbot-like Directory Structure

The daemon stores certificates in a structure compatible with certbot:

```
~/.lcm-client/
├── live/
│   └── <cert-name>/
│       ├── cert.pem       # Client certificate
│       ├── privkey.pem    # Private key (mode 0600)
│       ├── chain.pem      # CA certificate chain
│       └── fullchain.pem  # Certificate + chain concatenated
└── renewal/
    └── <cert-name>.json   # Certificate metadata
```

### Metadata File Format

```json
{
  "name": "api.example.com",
  "common_name": "api.example.com",
  "serial_number": "1234567890ABCDEF",
  "fingerprint": "SHA256:...",
  "issued_at": "2025-01-20T10:00:00Z",
  "expires_at": "2026-01-20T10:00:00Z",
  "last_updated": "2025-01-20T10:00:00Z",
  "issuer_name": "default-ca",
  "dns_names": ["api.example.com", "api-internal.example.com"],
  "ip_addresses": ["10.0.0.5"],
  "renewal_count": 0,
  "last_hook_execution": "2025-01-20T10:00:05Z"
}
```

## Multi-Tenancy

LCM supports complete tenant isolation for multi-tenant deployments.

### Tenant Features

- **Resource Isolation**: Certificates, clients, and issuers are tenant-scoped
- **Tenant ID in Certificates**: Extracted from client certificate organization
- **Event Routing**: Events include tenant context for proper routing
- **Audit Segregation**: Audit logs are filterable by tenant

### Tenant Configuration

Tenant ID is typically embedded in the client certificate's organization field during registration and automatically extracted during mTLS authentication.

## DNS Providers

LCM supports multiple DNS providers for ACME DNS-01 challenges:

| Provider | Configuration Keys |
|----------|-------------------|
| Cloudflare | `CF_API_TOKEN` or `CF_API_KEY`, `CF_API_EMAIL` |
| AWS Route53 | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` |
| Google Cloud DNS | `GCE_PROJECT`, `GCE_SERVICE_ACCOUNT_FILE` |
| DigitalOcean | `DO_AUTH_TOKEN` |
| PowerDNS | `PDNS_API_URL`, `PDNS_API_KEY` |
| Hurricane Electric | `HURRICANE_TOKENS` |
| ACME-DNS | `ACME_DNS_API_BASE`, `ACME_DNS_STORAGE_PATH` |
| CloudDNS | `CLOUDDNS_CLIENT_ID`, `CLOUDDNS_EMAIL`, `CLOUDDNS_PASSWORD` |
| EasyDNS | `EASYDNS_TOKEN`, `EASYDNS_KEY` |
| HTTP Request | `HTTPREQ_ENDPOINT`, `HTTPREQ_MODE` |

### Creating an ACME Issuer with DNS Challenge

```bash
# Via gRPC or REST API
POST /api/v1/issuers
{
  "name": "letsencrypt-prod",
  "issuer_type": "acme",
  "acme_config": {
    "server_url": "https://acme-v02.api.letsencrypt.org/directory",
    "email": "admin@example.com",
    "challenge_type": "dns",
    "dns_provider": "cloudflare",
    "dns_config": {
      "CF_API_TOKEN": "your-cloudflare-token"
    }
  }
}
```

## Security

### mTLS Authentication

All authenticated endpoints require a valid client certificate issued by a trusted CA.

```
Client                                Server
  │                                      │
  │──── TLS Handshake ──────────────────>│
  │<─── Server Certificate ──────────────│
  │──── Client Certificate ─────────────>│
  │<─── Verification Success ────────────│
  │                                      │
  │──── gRPC Request + Client Cert ─────>│
  │     (CN extracted as Client ID)      │
  │<─── Response ────────────────────────│
```

### Audit Trail Integrity

Each audit log entry includes a cryptographic hash for tamper detection:

```
log_hash = SHA256(operation + client_dn + timestamp + request_id + status)
```

### Private Key Protection

- Private keys are stored with mode 0600 (owner read/write only)
- Keys never leave the client in daemon mode
- Server-generated keys are transmitted once via encrypted gRPC

## Development

### Project Structure

```
app/lcm/service/
├── cmd/
│   ├── client/          # CLI client
│   │   ├── cmd/         # Cobra commands
│   │   │   ├── daemon/  # Daemon mode
│   │   │   ├── download/
│   │   │   ├── register/
│   │   │   └── status/
│   │   └── internal/
│   │       ├── hook/    # Deploy hooks (Bash, Lua, JS)
│   │       ├── machine/ # Machine ID detection
│   │       └── storage/ # Certbot-like storage
│   └── server/          # gRPC/REST server
├── internal/
│   ├── biz/             # Business logic
│   ├── bootstrap/       # Service initialization
│   ├── cert/            # Certificate utilities
│   ├── conf/            # Configuration
│   ├── data/            # Data layer (ENT ORM)
│   ├── event/           # Redis pub/sub events
│   ├── server/          # Server setup
│   ├── service/         # gRPC service implementations
│   └── webhook/         # Webhook delivery
├── pkg/
│   ├── client/          # Client connection utilities
│   ├── crypto/          # Cryptographic operations
│   ├── dns/             # DNS provider registry
│   └── middleware/      # gRPC middleware
├── configs/             # Configuration files
├── data/                # Runtime data (certs, keys)
└── test/                # Functional tests
```

### Building

```bash
# Build server
go build -o lcm-server ./cmd/server

# Build client
go build -o lcm-client ./cmd/client

# Run tests
go test ./...

# Run functional tests
cd test && go test -v ./...
```

### Proto Generation

```bash
# From repository root
make api

# Or directly
buf generate
```

### Dependencies

- **Go 1.20+**
- **PostgreSQL/MySQL** - Primary database
- **Redis** - Pub/sub for events
- **github.com/go-kratos/kratos/v2** - Microservice framework
- **entgo.io/ent** - Entity framework ORM
- **github.com/go-acme/lego/v4** - ACME client
- **github.com/tx7do/go-scripts** - Lua/JS script execution

## License

[License information here]
