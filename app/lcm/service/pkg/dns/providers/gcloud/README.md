# Google Cloud DNS Provider

This package provides a DNS challenge provider for Let's Encrypt ACME challenges using Google Cloud DNS.

## Configuration

The Google Cloud DNS provider supports multiple authentication methods:

### 1. Service Account Key (Recommended for production)

```json
{
  "project": "your-gcp-project-id",
  "serviceAccountKey": "{\"type\":\"service_account\",\"project_id\":\"your-project\",...}",
  "zoneId": "your-dns-zone-id",
  "dnsPropagationTimeout": 120,
  "dnsTTL": 300
}
```

### 2. Service Account File

```json
{
  "project": "your-gcp-project-id",
  "serviceAccountFile": "/path/to/service-account.json",
  "zoneId": "your-dns-zone-id"
}
```

### 3. Application Default Credentials

```json
{
  "project": "your-gcp-project-id"
}
```

This method uses the default credentials from:
- `GOOGLE_APPLICATION_CREDENTIALS` environment variable
- gcloud CLI credentials
- Compute Engine service account (when running on GCE)

## Configuration Options

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `project` | string | Yes | Google Cloud Project ID |
| `zoneId` | string | No | DNS zone ID (auto-detected if not provided) |
| `serviceAccountFile` | string | No | Path to service account JSON file |
| `serviceAccountKey` | string | No | Service account JSON key content |
| `allowPrivateZone` | bool | No | Allow using private DNS zones (default: false) |
| `impersonateServiceAccount` | string | No | Service account email to impersonate |
| `dnsPropagationTimeout` | int32 | No | DNS propagation timeout in seconds (default: 180) |
| `dnsPollingInterval` | int32 | No | DNS polling interval in seconds (default: 2) |
| `dnsTTL` | int32 | No | TTL for DNS records in seconds (default: 120) |
| `debug` | bool | No | Enable debug logging (default: false) |

## Authentication Methods

### Service Account Key (Recommended)

1. Create a service account in Google Cloud Console
2. Grant the following IAM roles to the service account:
   - `DNS Administrator` or `dns.admin`
3. Create and download a JSON key for the service account
4. Use the JSON content in the `serviceAccountKey` field

### Service Account File

Same as above, but store the JSON key in a file and reference the file path in `serviceAccountFile`.

### Application Default Credentials

For development or when running on Google Cloud infrastructure:

1. Install and configure gcloud CLI: `gcloud auth application-default login`
2. Or when running on Compute Engine, the instance service account will be used automatically

## Required Google Cloud Permissions

The service account or authenticated user needs the following permissions:

- `dns.changes.create`
- `dns.changes.get`
- `dns.managedZones.list`
- `dns.resourceRecordSets.create`
- `dns.resourceRecordSets.delete`
- `dns.resourceRecordSets.list`

These are included in the predefined `DNS Administrator` role.

## Usage Example

```go
import (
    "github.com/menta2k/lcm/pkg/dns/providers/gcloud"
)

config := &gcloud.ChallengeProviderConfig{
    Project:               "my-gcp-project",
    ServiceAccountKey:     serviceAccountJSON,
    DnsPropagationTimeout: 120,
    DnsTTL:                300,
    Debug:                 false,
}

provider, err := gcloud.NewChallengeProvider(config)
if err != nil {
    // Handle error
}

// Use provider with ACME client
```

## Troubleshooting

### Common Issues

1. **Authentication Error**: Ensure the service account has proper DNS permissions
2. **Zone Not Found**: Verify the project ID and zone configuration
3. **Propagation Timeout**: Increase `dnsPropagationTimeout` for slow DNS propagation
4. **Private Zones**: Set `allowPrivateZone: true` if using Cloud DNS private zones

### Debug Mode

Enable debug mode to see detailed logging:

```json
{
  "project": "your-project",
  "debug": true
}
```

This will output detailed information about DNS operations and API calls.