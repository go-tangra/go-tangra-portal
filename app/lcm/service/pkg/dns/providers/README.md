# DNS Providers

This directory contains DNS challenge providers for Let's Encrypt ACME challenges. Each provider wraps the corresponding provider from the [lego](https://github.com/go-acme/lego) library to provide a consistent configuration interface.

## Available Providers

| Provider | Description | Package |
|----------|-------------|---------|
| **ACME-DNS** | Uses external ACME-DNS server for DNS-01 challenges | `acmedns` |
| **Cloudflare** | Cloudflare DNS API | `cloudflare` |
| **CloudDNS** | CloudDNS API | `clouddns` |
| **DigitalOcean** | DigitalOcean DNS API | `digitalocean` |
| **EasyDNS** | EasyDNS API | `easydns` |
| **Google Cloud DNS** | Google Cloud DNS API | `gcloud` |
| **Hurricane Electric** | Hurricane Electric Free DNS | `hurricane` |
| **HTTP Request** | Generic HTTP endpoint for DNS operations | `httpreq` |
| **PowerDNS** | PowerDNS Authoritative Server API | `pdns` |
| **Route53** | Amazon Route53 DNS API | `route53` |

## Usage Pattern

All providers follow the same pattern:

```go
import "github.com/menta2k/lcm/pkg/dns/providers/{provider}"

config := &{provider}.ChallengeProviderConfig{
    // Provider-specific configuration
}

provider, err := {provider}.NewChallengeProvider(config)
if err != nil {
    // Handle error
}

// Use provider with ACME client
```

## Provider-Specific Configuration

### ACME-DNS

```json
{
  "apiBase": "https://auth.acme-dns.io",
  "allowList": ["example.com", "*.example.com"],
  "storagePath": "/path/to/storage",
  "storageBaseUrl": "https://storage.example.com"
}
```

### Cloudflare

```json
{
  "dnsApiToken": "your-api-token",
  "zoneApiToken": "your-zone-token",
  "dnsPropagationTimeout": 120,
  "dnsTTL": 300
}
```

### CloudDNS

```json
{
  "clientId": "your-client-id",
  "email": "your-email@example.com",
  "password": "your-password",
  "dnsPropagationTimeout": 120,
  "dnsTTL": 300
}
```

### DigitalOcean

```json
{
  "authToken": "your-do-token",
  "baseUrl": "https://api.digitalocean.com",
  "dnsPropagationTimeout": 120,
  "dnsTTL": 300
}
```

### EasyDNS

```json
{
  "token": "your-api-token",
  "key": "your-api-key",
  "endpoint": "https://api.easydns.com",
  "dnsPropagationTimeout": 120,
  "dnsTTL": 300
}
```

### Google Cloud DNS

```json
{
  "project": "your-gcp-project-id",
  "serviceAccountKey": "{...service-account-json...}",
  "zoneId": "your-dns-zone-id",
  "dnsPropagationTimeout": 120,
  "dnsTTL": 300
}
```

### Hurricane Electric

```json
{
  "credentials": {
    "example.com": "token1",
    "subdomain.example.com": "token2"
  },
  "dnsPropagationTimeout": 120
}
```

### HTTP Request

```json
{
  "endpoint": "https://your-dns-api.example.com/dns",
  "mode": "RAW",
  "username": "api-user",
  "password": "api-password",
  "dnsPropagationTimeout": 120
}
```

### PowerDNS

```json
{
  "apiKey": "your-api-key",
  "host": "http://your-pdns-server:8081",
  "serverName": "localhost",
  "apiVersion": 1,
  "dnsPropagationTimeout": 120,
  "dnsTTL": 300
}
```

### Route53

```json
{
  "accessKeyId": "your-access-key",
  "secretAccessKey": "your-secret-key",
  "region": "us-east-1",
  "hostedZoneId": "Z1234567890ABC",
  "dnsPropagationTimeout": 120,
  "dnsTTL": 300
}
```

## Common Configuration Options

Most providers support these common configuration options:

- `dnsPropagationTimeout`: Time to wait for DNS propagation (seconds)
- `dnsPollingInterval`: Interval between DNS checks (seconds)
- `dnsTTL`: TTL for DNS records (seconds)

## Authentication

### API Keys/Tokens
Most providers require API keys or tokens:
- **Cloudflare**: API token with Zone:Edit permissions
- **DigitalOcean**: Personal access token with write permissions
- **Route53**: AWS access key with Route53 permissions

### Service Account Authentication
Some providers support multiple authentication methods:

**Google Cloud DNS**:
- Service account key (JSON)
- Service account file path
- Application default credentials

### HTTP Authentication
**HTTP Request provider**:
- Basic authentication (username/password)
- Custom endpoints for DNS operations

## Security Best Practices

1. **Use least-privilege access**: Grant only necessary permissions
2. **Rotate credentials regularly**: Update API keys/tokens periodically
3. **Store credentials securely**: Use secure credential storage
4. **Monitor API usage**: Track DNS API calls for anomalies
5. **Validate configurations**: Ensure proper validation of all inputs

## Error Handling

All providers implement consistent error handling:

- **Configuration errors**: Invalid or missing required parameters
- **Authentication errors**: Invalid credentials or permissions
- **Network errors**: Connection timeouts or DNS propagation failures
- **API errors**: Provider-specific API error responses

## Testing

Each provider includes comprehensive unit tests covering:
- Configuration validation
- Error scenarios
- Authentication methods
- Parameter handling

Run tests for all providers:
```bash
go test ./pkg/dns/providers/... -v
```

## Contributing

When adding a new DNS provider:

1. Create a new directory under `pkg/dns/providers/{provider}`
2. Implement the `ChallengeProviderConfig` struct
3. Implement the `NewChallengeProvider` function
4. Add comprehensive unit tests
5. Update this README with provider documentation
6. Ensure the provider follows the established patterns

## Documentation

Each provider directory contains:
- Implementation file (`{provider}.go`)
- Unit tests (`{provider}_test.go`)
- README with provider-specific documentation (for complex providers)

For detailed provider-specific documentation, see the individual provider directories.