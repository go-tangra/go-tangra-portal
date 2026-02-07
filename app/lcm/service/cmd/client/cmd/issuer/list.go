package issuer

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/protobuf/types/known/emptypb"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/client"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all issuers",
	Long: `List all certificate issuers for your tenant.

Example:
  lcm-client issuer list
`,
	RunE: runList,
}

func runList(cmd *cobra.Command, args []string) error {
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

	// List issuers
	resp, err := grpcClient.ListIssuers(ctx, &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("failed to list issuers: %w", err)
	}

	if len(resp.Issuers) == 0 {
		fmt.Println("No issuers found.")
		return nil
	}

	fmt.Printf("\nFound %d issuer(s):\n\n", len(resp.Issuers))
	for _, issuer := range resp.Issuers {
		printIssuerSummary(issuer)
	}

	return nil
}

func printIssuerSummary(issuer *lcmV1.IssuerInfo) {
	status := "UNKNOWN"
	if issuer.Status != nil {
		status = issuer.Status.String()
	}

	fmt.Printf("  Name:        %s\n", issuer.Name)
	fmt.Printf("  Type:        %s\n", issuer.Type)
	fmt.Printf("  Status:      %s\n", status)
	if issuer.Description != "" {
		fmt.Printf("  Description: %s\n", issuer.Description)
	}
	if issuer.CreateTime != nil {
		fmt.Printf("  Created:     %s\n", issuer.CreateTime.AsTime().Format(time.RFC3339))
	}
	fmt.Println()
}
