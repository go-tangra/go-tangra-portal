package issuer

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/client"
)

var getCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Get details of an issuer",
	Long: `Get detailed information about a specific certificate issuer.

Example:
  lcm-client issuer get my-issuer
`,
	Args: cobra.ExactArgs(1),
	RunE: runGet,
}

func runGet(cmd *cobra.Command, args []string) error {
	issuerName := args[0]

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverAddr := viper.GetString("server")
	certFile := viper.GetString("cert")
	keyFile := viper.GetString("key")
	caFile := viper.GetString("ca")

	fmt.Printf("Getting issuer '%s' from server '%s'...\n", issuerName, serverAddr)

	// Create mTLS connection
	conn, err := client.CreateMTLSConnection(serverAddr, certFile, keyFile, caFile)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Create gRPC client
	grpcClient := lcmV1.NewLcmIssuerServiceClient(conn)

	// Get issuer
	resp, err := grpcClient.GetIssuerInfo(ctx, &lcmV1.GetIssuerInfoRequest{
		IssuerName: issuerName,
	})
	if err != nil {
		return fmt.Errorf("failed to get issuer: %w", err)
	}

	printIssuerDetails(resp.Issuer)

	return nil
}

func printIssuerDetails(issuer *lcmV1.IssuerInfo) {
	status := "UNKNOWN"
	if issuer.Status != nil {
		status = issuer.Status.String()
	}

	fmt.Printf("\nIssuer Details:\n")
	fmt.Printf("  Name:        %s\n", issuer.Name)
	fmt.Printf("  Type:        %s\n", issuer.Type)
	fmt.Printf("  Status:      %s\n", status)
	if issuer.Description != "" {
		fmt.Printf("  Description: %s\n", issuer.Description)
	}
	if issuer.CreateTime != nil {
		fmt.Printf("  Created:     %s\n", issuer.CreateTime.AsTime().Format(time.RFC3339))
	}
	if issuer.UpdateTime != nil {
		fmt.Printf("  Updated:     %s\n", issuer.UpdateTime.AsTime().Format(time.RFC3339))
	}

	if len(issuer.Config) > 0 {
		fmt.Printf("\n  Configuration:\n")
		for key, value := range issuer.Config {
			fmt.Printf("    %s: %s\n", key, value)
		}
	}
}
