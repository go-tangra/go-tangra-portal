package status

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/cmd/client/internal/machine"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/client"
)

var requestID string

// Command is the status command
var Command = &cobra.Command{
	Use:   "status",
	Short: "Check the status of a certificate request",
	Long: `Check the status of a pending certificate request.

Use this command after registration if your certificate is pending approval.

Example:
  lcm-client status --request-id abc123-def456
`,
	RunE: runStatus,
}

func init() {
	Command.Flags().StringVar(&requestID, "request-id", "", "Request ID to check (required)")
	_ = Command.MarkFlagRequired("request-id")
}

func runStatus(c *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clientID := getClientID()
	serverAddr := viper.GetString("server")

	fmt.Printf("Checking status for request '%s'...\n", requestID)

	// Connect to server (TLS without client cert)
	conn, err := client.CreateTLSConnectionWithoutClientCert(serverAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	// Create gRPC client
	grpcClient := lcmV1.NewLcmClientServiceClient(conn)

	// Send status request
	req := &lcmV1.GetRequestStatusRequest{
		RequestId: requestID,
		ClientId:  clientID,
	}

	resp, err := grpcClient.GetRequestStatus(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}

	// Display status
	fmt.Println("\n--- Certificate Request Status ---")
	fmt.Printf("Request ID: %s\n", requestID)
	fmt.Printf("Client ID:  %s\n", clientID)
	fmt.Printf("Status:     %s\n", statusToString(resp.GetStatus()))

	if resp.Message != nil && *resp.Message != "" {
		fmt.Printf("Message:    %s\n", *resp.Message)
	}

	if resp.CreateTime != nil {
		fmt.Printf("Created:    %s\n", resp.CreateTime.AsTime().Format(time.RFC3339))
	}
	if resp.UpdateTime != nil {
		fmt.Printf("Updated:    %s\n", resp.UpdateTime.AsTime().Format(time.RFC3339))
	}
	if resp.RevokeTime != nil {
		fmt.Printf("Revoked:    %s\n", resp.RevokeTime.AsTime().Format(time.RFC3339))
	}

	// Provide next steps based on status
	fmt.Println()
	switch resp.GetStatus() {
	case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_ISSUED:
		fmt.Println("Certificate is ready! Download it with:")
		fmt.Printf("  lcm-client download --request-id %s\n", requestID)
	case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_PENDING:
		fmt.Println("Certificate is still pending approval. Check again later.")
	case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_REVOKED:
		fmt.Println("Certificate has been revoked. You may need to re-register.")
	}

	return nil
}

func statusToString(status lcmV1.ClientCertificateStatus) string {
	switch status {
	case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_ISSUED:
		return "ISSUED"
	case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_PENDING:
		return "PENDING"
	case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_REVOKED:
		return "REVOKED"
	case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_UNKNOWN:
		return "UNKNOWN"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", status)
	}
}

func getClientID() string {
	id := viper.GetString("client-id")
	if id == "" {
		id = machine.GetClientID()
	}
	return id
}
