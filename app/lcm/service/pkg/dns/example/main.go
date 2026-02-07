package main

import (
	"fmt"
	"log"
	"os"

	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns"
	// Import to register all providers
	_ "github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/dns/init"
)

func main() {
	fmt.Println("DNS Provider Registry Example")
	fmt.Println("=============================")
	
	// Example 1: List all available providers
	fmt.Println("\n1. Available Providers:")
	providers := dns.ListProviders()
	for i, provider := range providers {
		fmt.Printf("   %d. %s\n", i+1, provider)
	}
	
	// Example 2: Get provider information
	fmt.Println("\n2. Provider Information:")
	exampleProviders := []string{"cloudflare", "route53", "digitalocean", "gcloud"}
	
	for _, providerName := range exampleProviders {
		info, err := dns.GetProviderInfo(providerName)
		if err != nil {
			log.Printf("Error getting info for %s: %v", providerName, err)
			continue
		}
		
		fmt.Printf("\n   %s:\n", info.Name)
		fmt.Printf("     Description: %s\n", info.Description)
		fmt.Printf("     Required Fields: %v\n", info.RequiredFields)
		fmt.Printf("     Optional Fields: %v\n", info.OptionalFields)
	}
	
	// Example 3: Create providers with different configurations
	fmt.Println("\n3. Provider Creation Examples:")
	
	// Cloudflare example
	if token := os.Getenv("CLOUDFLARE_DNS_API_TOKEN"); token != "" {
		fmt.Println("\n   Creating Cloudflare provider...")
		config := map[string]string{
			"dnsApiToken": token,
			"dnsTTL": "300",
			"dnsPropagationTimeout": "120",
		}
		
		provider, err := dns.GetProvider("cloudflare", config)
		if err != nil {
			log.Printf("   Error creating Cloudflare provider: %v", err)
		} else {
			fmt.Printf("   ✓ Cloudflare provider created successfully (type: %T)\n", provider)
		}
	} else {
		fmt.Println("   Cloudflare: Set CLOUDFLARE_DNS_API_TOKEN environment variable to test")
	}
	
	// Route53 example
	if accessKey := os.Getenv("AWS_ACCESS_KEY_ID"); accessKey != "" {
		fmt.Println("\n   Creating Route53 provider...")
		config := map[string]string{
			"accessKeyId": accessKey,
			"secretAccessKey": os.Getenv("AWS_SECRET_ACCESS_KEY"),
			"region": "us-east-1",
			"dnsTTL": "300",
		}
		
		provider, err := dns.GetProvider("route53", config)
		if err != nil {
			log.Printf("   Error creating Route53 provider: %v", err)
		} else {
			fmt.Printf("   ✓ Route53 provider created successfully (type: %T)\n", provider)
		}
	} else {
		fmt.Println("   Route53: Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables to test")
	}
	
	// Google Cloud DNS example
	if project := os.Getenv("GCP_PROJECT"); project != "" {
		fmt.Println("\n   Creating Google Cloud DNS provider...")
		config := map[string]string{
			"project": project,
			"dnsTTL": "300",
			"debug": "false",
		}
		
		// Add service account file if available
		if saFile := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); saFile != "" {
			config["serviceAccountFile"] = saFile
		}
		
		provider, err := dns.GetProvider("gcloud", config)
		if err != nil {
			log.Printf("   Error creating Google Cloud DNS provider: %v", err)
		} else {
			fmt.Printf("   ✓ Google Cloud DNS provider created successfully (type: %T)\n", provider)
		}
	} else {
		fmt.Println("   Google Cloud DNS: Set GCP_PROJECT environment variable to test")
	}
	
	// Example 4: Error handling demonstration
	fmt.Println("\n4. Error Handling Examples:")
	
	// Invalid provider name
	fmt.Println("\n   Testing invalid provider name...")
	_, err := dns.GetProvider("nonexistent", map[string]string{})
	if err != nil {
		fmt.Printf("   Expected error: %v\n", err)
	}
	
	// Missing required configuration
	fmt.Println("\n   Testing missing required configuration...")
	_, err = dns.GetProvider("cloudflare", map[string]string{})
	if err != nil {
		fmt.Printf("   Expected error: %v\n", err)
	}
	
	// Invalid configuration values
	fmt.Println("\n   Testing invalid configuration values...")
	invalidConfig := map[string]string{
		"dnsApiToken": "invalid-token",
		"dnsTTL": "not-a-number", // This should cause parsing issues
	}
	_, err = dns.GetProvider("cloudflare", invalidConfig)
	if err != nil {
		fmt.Printf("   Provider creation error (expected with invalid token): %v\n", err)
	}
	
	// Example 5: Advanced configuration patterns
	fmt.Println("\n5. Advanced Configuration Examples:")
	
	// Hurricane Electric with JSON credentials
	fmt.Println("\n   Hurricane Electric with JSON credentials:")
	hurricaneConfig := map[string]string{
		"credentials": `{"example.com": "token123", "test.com": "token456"}`,
		"dnsPropagationTimeout": "180",
		"dnsPollingInterval": "15",
	}
	
	_, err = dns.GetProvider("hurricane", hurricaneConfig)
	if err != nil {
		fmt.Printf("   Error (expected without valid credentials): %v\n", err)
	} else {
		fmt.Println("   ✓ Hurricane Electric provider configuration validated")
	}
	
	// HTTP Request provider
	fmt.Println("\n   HTTP Request provider:")
	httpConfig := map[string]string{
		"endpoint": "https://dns-api.example.com/v1/records",
		"mode": "RFC2136",
		"username": "api-user",
		"password": "api-password",
		"dnsPropagationTimeout": "300",
	}
	
	_, err = dns.GetProvider("httpreq", httpConfig)
	if err != nil {
		fmt.Printf("   Error (expected without valid endpoint): %v\n", err)
	} else {
		fmt.Println("   ✓ HTTP Request provider configuration validated")
	}
	
	// Example 6: Get all provider info at once
	fmt.Println("\n6. All Provider Information:")
	allInfo := dns.GetAllProviderInfo()
	fmt.Printf("   Total providers: %d\n", len(allInfo))
	
	for name, info := range allInfo {
		fmt.Printf("   %s: %d required, %d optional fields\n", 
			name, len(info.RequiredFields), len(info.OptionalFields))
	}
	
	fmt.Println("\n=============================")
	fmt.Println("Example completed successfully!")
	fmt.Println("")
	fmt.Println("To test with real credentials, set the following environment variables:")
	fmt.Println("- CLOUDFLARE_DNS_API_TOKEN")
	fmt.Println("- AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
	fmt.Println("- GCP_PROJECT and GOOGLE_APPLICATION_CREDENTIALS")
}