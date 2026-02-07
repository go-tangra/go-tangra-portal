# DNS Provider Registry

A comprehensive DNS provider registry system for ACME DNS-01 challenge providers using the [lego](https://github.com/go-acme/lego) library.

## Overview

This package provides a centralized registry for DNS providers that can be used for ACME DNS-01 challenges. It includes support for multiple popular DNS providers and allows easy configuration and instantiation of providers.

## Supported Providers

- **ACME-DNS**: External DNS server for DNS-01 challenges
- **Cloudflare**: Cloudflare DNS API
- **CloudDNS**: CloudDNS API 
- **DigitalOcean**: DigitalOcean DNS API
- **EasyDNS**: EasyDNS API
- **Google Cloud DNS**: Google Cloud DNS API
- **Hurricane Electric**: Hurricane Electric Free DNS
- **HTTP Request**: Generic HTTP endpoint for DNS operations
- **PowerDNS**: PowerDNS Authoritative Server API
- **Route53**: Amazon Route53 DNS API

## Usage

### Basic Usage

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/menta2k/lcm/pkg/dns"
    // Import to register all providers
    _ "github.com/menta2k/lcm/pkg/dns/init"
)

func main() {
    // List all available providers
    providers := dns.ListProviders()
    fmt.Printf("Available providers: %v\n", providers)
    
    // Get a provider with configuration
    config := map[string]string{
        "dnsApiToken": "your-cloudflare-token",
        "dnsTTL": "300",
    }
    
    provider, err := dns.GetProvider("cloudflare", config)
    if err != nil {
        log.Fatal(err)
    }
    
    // Use the provider for DNS-01 challenges
    // provider implements the challenge.Provider interface
}
```

### Provider Information

```go
// Get information about a specific provider
info, err := dns.GetProviderInfo("cloudflare")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Provider: %s\n", info.Name)
fmt.Printf("Description: %s\n", info.Description)
fmt.Printf("Required Fields: %v\n", info.RequiredFields)
fmt.Printf("Optional Fields: %v\n", info.OptionalFields)

// Get information about all providers
allInfo := dns.GetAllProviderInfo()
for name, info := range allInfo {
    fmt.Printf("%s: %s\n", name, info.Description)
}
```

## Provider Configuration

### Cloudflare

```go
config := map[string]string{
    "dnsApiToken": "your-api-token",        // Required
    "zoneApiToken": "zone-api-token",       // Optional
    "dnsPropagationTimeout": "120",         // Optional (seconds)
    "dnsTTL": "300",                        // Optional (seconds)
}
```

### DigitalOcean

```go
config := map[string]string{
    "authToken": "your-auth-token",         // Required
    "baseUrl": "https://api.digitalocean.com", // Optional
    "dnsPropagationTimeout": "120",         // Optional (seconds)
    "dnsPollingInterval": "10",            // Optional (seconds)
    "dnsTTL": "300",                        // Optional (seconds)
}
```

### Google Cloud DNS

```go
config := map[string]string{
    "project": "your-gcp-project",          // Required
    "serviceAccountFile": "/path/to/sa.json", // Optional
    "serviceAccountKey": "base64-encoded-key", // Optional
    "zoneId": "your-zone-id",               // Optional
    "allowPrivateZone": "false",            // Optional (boolean)
    "impersonateServiceAccount": "sa@project.iam.gserviceaccount.com", // Optional
    "dnsPropagationTimeout": "120",         // Optional (seconds)
    "dnsPollingInterval": "10",            // Optional (seconds)
    "dnsTTL": "300",                        // Optional (seconds)
    "debug": "false",                       // Optional (boolean)
}
```

### Route53

```go
config := map[string]string{
    "accessKeyId": "your-access-key",       // Required
    "secretAccessKey": "your-secret-key",   // Required
    "region": "us-east-1",                  // Required
    "hostedZoneId": "Z1D633PJN98FT9",      // Optional
    "dnsPropagationTimeout": "120",         // Optional (seconds)
    "dnsTTL": "300",                        // Optional (seconds)
}
```

### PowerDNS

```go
config := map[string]string{
    "apiKey": "your-api-key",               // Required
    "host": "http://localhost:8081",        // Required
    "serverName": "localhost",              // Optional
    "apiVersion": "1",                      // Optional (integer)
    "dnsPropagationTimeout": "120",         // Optional (seconds)
    "dnsPollingInterval": "10",            // Optional (seconds)
    "dnsTTL": "300",                        // Optional (seconds)
}
```

### Hurricane Electric

```go
config := map[string]string{
    "credentials": `{"example.com": "token123"}`, // Required (JSON map)
    "dnsPropagationTimeout": "120",         // Optional (seconds)
    "dnsPollingInterval": "10",            // Optional (seconds)
    "dnsSequenceInterval": "1",            // Optional (seconds)
}
```

### HTTP Request

```go
config := map[string]string{
    "endpoint": "http://localhost:8080/dns", // Required
    "mode": "RFC2136",                      // Optional
    "username": "user",                     // Optional
    "password": "pass",                     // Optional
    "dnsPropagationTimeout": "120",         // Optional (seconds)
    "dnsPollingInterval": "10",            // Optional (seconds)
}
```

### EasyDNS

```go
config := map[string]string{
    "token": "your-token",                  // Required
    "key": "your-key",                      // Required
    "endpoint": "https://api.easydns.com",  // Optional
    "dnsPropagationTimeout": "120",         // Optional (seconds)
    "dnsPollingInterval": "10",            // Optional (seconds)
    "dnsSequenceInterval": "1",            // Optional (seconds)
    "dnsTTL": "300",                        // Optional (seconds)
}
```

### CloudDNS

```go
config := map[string]string{
    "clientId": "your-client-id",           // Required
    "email": "your-email@example.com",      // Required
    "password": "your-password",            // Required
    "dnsPropagationTimeout": "120",         // Optional (seconds)
    "dnsPollingInterval": "10",            // Optional (seconds)
    "dnsTTL": "300",                        // Optional (seconds)
}
```

### ACME-DNS

```go
config := map[string]string{
    "apiBase": "https://auth.acme-dns.io",  // Optional
    "allowList": "example.com,test.com",    // Optional (comma-separated)
    "storagePath": "/var/lib/acme-dns",     // Optional
    "storageBaseUrl": "https://auth.acme-dns.io", // Optional
}
```

## Configuration Helpers

The registry provides helper functions for parsing configuration values:

```go
import "github.com/menta2k/lcm/pkg/dns/registry"

// String values with defaults
value := registry.GetString(config, "key", "default-value")

// Integer values with defaults
intValue, err := registry.GetInt32(config, "key", 100)

// Boolean values with defaults
boolValue, err := registry.GetBool(config, "key", false)

// String slices (comma-separated values)
slice := registry.GetStringSlice(config, "key")

// JSON maps
jsonMap, err := registry.GetJSONMap(config, "key")
```

## Error Handling

The registry provides detailed error messages for common configuration issues:

```go
provider, err := dns.GetProvider("cloudflare", config)
if err != nil {
    if strings.Contains(err.Error(), "is not registered") {
        // Provider not found
    } else if strings.Contains(err.Error(), "configuration validation failed") {
        // Missing or invalid configuration
    } else if strings.Contains(err.Error(), "failed to create provider") {
        // Provider creation failed (usually auth issues)
    }
}
```

## Testing

Run the comprehensive test suite:

```bash
go test ./pkg/dns/registry -v
```

The tests cover:
- Provider registration verification
- Configuration validation
- Provider instantiation with valid configs
- Error handling for invalid configs
- Configuration helper functions

## Architecture

The registry system consists of:

- **Registry Package** (`pkg/dns/registry`): Core registration and provider management
- **Init Package** (`pkg/dns/init`): Provider registration on import  
- **Provider Packages** (`pkg/dns/providers/*`): Individual provider implementations
- **Main DNS Package** (`pkg/dns`): Public API wrapper

This architecture avoids import cycles while providing a clean, easy-to-use interface.