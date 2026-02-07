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

var (
	forceDelete bool
)

var deleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete an issuer",
	Long: `Delete a certificate issuer.

Warning: This will permanently delete the issuer and its configuration.
Any certificates already issued by this issuer will remain valid until expiry.

Example:
  lcm-client issuer delete my-issuer
  lcm-client issuer delete my-issuer --force
`,
	Args: cobra.ExactArgs(1),
	RunE: runDelete,
}

func init() {
	deleteCmd.Flags().BoolVarP(&forceDelete, "force", "f", false, "Skip confirmation prompt")
}

func runDelete(cmd *cobra.Command, args []string) error {
	issuerName := args[0]

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverAddr := viper.GetString("server")
	certFile := viper.GetString("cert")
	keyFile := viper.GetString("key")
	caFile := viper.GetString("ca")

	// Confirm deletion unless --force is used
	if !forceDelete {
		fmt.Printf("Are you sure you want to delete issuer '%s'? (y/N): ", issuerName)
		var confirm string
		if _, err := fmt.Scanln(&confirm); err != nil || (confirm != "y" && confirm != "Y") {
			fmt.Println("Deletion cancelled.")
			return nil
		}
	}

	fmt.Printf("Deleting issuer '%s' from server '%s'...\n", issuerName, serverAddr)

	// Create mTLS connection
	conn, err := client.CreateMTLSConnection(serverAddr, certFile, keyFile, caFile)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Create gRPC client
	grpcClient := lcmV1.NewLcmIssuerServiceClient(conn)

	// Delete issuer
	_, err = grpcClient.DeleteIssuer(ctx, &lcmV1.DeleteIssuerRequest{
		Name: issuerName,
	})
	if err != nil {
		return fmt.Errorf("failed to delete issuer: %w", err)
	}

	fmt.Printf("Issuer '%s' deleted successfully.\n", issuerName)

	return nil
}
