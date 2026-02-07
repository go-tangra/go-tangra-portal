package issuer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/protobuf/types/known/emptypb"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/client"
)

var dnsProvidersCmd = &cobra.Command{
	Use:   "dns-providers",
	Short: "List available DNS providers for DNS challenges",
	Long: `List all available DNS providers that can be used for ACME DNS challenges.

Each provider has required and optional configuration fields that must be
provided when creating an issuer with DNS challenge type.

Example:
  lcm-client issuer dns-providers
`,
	RunE: runDnsProviders,
}

func init() {
	Command.AddCommand(dnsProvidersCmd)
	Command.AddCommand(dnsProviderCmd)
}

func runDnsProviders(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverAddr := viper.GetString("server")
	certFile := viper.GetString("cert")
	keyFile := viper.GetString("key")
	caFile := viper.GetString("ca")

	fmt.Printf("Connecting to server '%s'...\n", serverAddr)

	// Create mTLS connection
	conn, err := client.CreateMTLSConnection(serverAddr, certFile, keyFile, caFile)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Create gRPC client
	grpcClient := lcmV1.NewLcmIssuerServiceClient(conn)

	// List DNS providers
	resp, err := grpcClient.ListDnsProviders(ctx, &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("failed to list DNS providers: %w", err)
	}

	if len(resp.Providers) == 0 {
		fmt.Println("No DNS providers available.")
		return nil
	}

	fmt.Printf("\nAvailable DNS Providers (%d):\n\n", len(resp.Providers))
	for _, provider := range resp.Providers {
		printDnsProviderSummary(provider)
	}

	fmt.Println("Use 'lcm-client issuer dns-provider <name>' to see detailed configuration for a specific provider.")

	return nil
}

func printDnsProviderSummary(provider *lcmV1.DnsProviderInfo) {
	fmt.Printf("  %s\n", provider.Name)
	if provider.Description != "" {
		fmt.Printf("    Description: %s\n", provider.Description)
	}
	if len(provider.RequiredFields) > 0 {
		fmt.Printf("    Required:    %s\n", strings.Join(provider.RequiredFields, ", "))
	}
	fmt.Println()
}

var dnsProviderCmd = &cobra.Command{
	Use:   "dns-provider <name>",
	Short: "Get details about a specific DNS provider",
	Long: `Get detailed information about a specific DNS provider, including
all required and optional configuration fields.

Example:
  lcm-client issuer dns-provider cloudflare
  lcm-client issuer dns-provider route53
`,
	Args: cobra.ExactArgs(1),
	RunE: runDnsProvider,
}

func runDnsProvider(cmd *cobra.Command, args []string) error {
	providerName := args[0]

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverAddr := viper.GetString("server")
	certFile := viper.GetString("cert")
	keyFile := viper.GetString("key")
	caFile := viper.GetString("ca")

	fmt.Printf("Connecting to server '%s'...\n", serverAddr)

	// Create mTLS connection
	conn, err := client.CreateMTLSConnection(serverAddr, certFile, keyFile, caFile)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Create gRPC client
	grpcClient := lcmV1.NewLcmIssuerServiceClient(conn)

	// Get DNS provider info
	resp, err := grpcClient.GetDnsProviderInfo(ctx, &lcmV1.GetDnsProviderInfoRequest{
		Name: providerName,
	})
	if err != nil {
		return fmt.Errorf("failed to get DNS provider info: %w", err)
	}

	fmt.Printf("\nDNS Provider: %s\n", resp.Name)
	fmt.Println(strings.Repeat("-", 40))

	if resp.Description != "" {
		fmt.Printf("Description: %s\n\n", resp.Description)
	}

	if len(resp.RequiredFields) > 0 {
		fmt.Println("Required Configuration Fields:")
		for _, field := range resp.RequiredFields {
			fmt.Printf("  - %s\n", field)
		}
		fmt.Println()
	}

	if len(resp.OptionalFields) > 0 {
		fmt.Println("Optional Configuration Fields:")
		for _, field := range resp.OptionalFields {
			fmt.Printf("  - %s\n", field)
		}
		fmt.Println()
	}

	// Print example usage
	fmt.Println("Example Usage:")
	fmt.Printf("  lcm-client issuer create \\\n")
	fmt.Printf("    --name my-acme-issuer \\\n")
	fmt.Printf("    --type acme \\\n")
	fmt.Printf("    --acme-email admin@example.com \\\n")
	fmt.Printf("    --acme-endpoint https://acme-v02.api.letsencrypt.org/directory \\\n")
	fmt.Printf("    --acme-challenge-type DNS \\\n")
	fmt.Printf("    --acme-provider %s \\\n", resp.Name)
	for _, field := range resp.RequiredFields {
		fmt.Printf("    --acme-provider-config %s=<value> \\\n", field)
	}
	fmt.Println()

	return nil
}
