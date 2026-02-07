package job

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/client"
)

var jobIDStatus string

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get the status of a certificate job",
	Long: `Get the current status of a certificate job.

Example:
  lcm-client job status --job-id 550e8400-e29b-41d4-a716-446655440000
`,
	RunE: runStatus,
}

func init() {
	statusCmd.Flags().StringVar(&jobIDStatus, "job-id", "", "Job ID to check status (required)")
	_ = statusCmd.MarkFlagRequired("job-id")
}

func runStatus(c *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get configuration
	configDir := expandPath(viper.GetString("config-dir"))
	clientID := getClientID()
	serverAddr := viper.GetString("server")

	// Set certificate paths
	certFile := viper.GetString("cert")
	if certFile == "" {
		certFile = filepath.Join(configDir, fmt.Sprintf("%s.crt", clientID))
	}
	keyFile := viper.GetString("key")
	if keyFile == "" {
		keyFile = filepath.Join(configDir, fmt.Sprintf("%s.key", clientID))
	}
	caFile := viper.GetString("ca")
	if caFile == "" {
		caFile = filepath.Join(configDir, "ca.crt")
	}

	fmt.Printf("Checking job status from server '%s'...\n", serverAddr)

	// Connect with mTLS
	conn, err := client.CreateMTLSConnection(serverAddr, certFile, keyFile, caFile)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	// Create gRPC client
	grpcClient := lcmV1.NewLcmCertificateJobServiceClient(conn)

	// Build request
	req := &lcmV1.GetJobStatusRequest{
		JobId: jobIDStatus,
	}

	// Send request
	resp, err := grpcClient.GetJobStatus(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to get job status: %w", err)
	}

	// Display result
	fmt.Printf("\nJob Status:\n")
	fmt.Printf("  Job ID: %s\n", resp.GetJobId())
	fmt.Printf("  Status: %s\n", resp.GetStatus().String())
	fmt.Printf("  Issuer: %s (%s)\n", resp.GetIssuerName(), resp.GetIssuerType())
	fmt.Printf("  Common Name: %s\n", resp.GetCommonName())

	if len(resp.GetDnsNames()) > 0 {
		fmt.Printf("  DNS Names: %v\n", resp.GetDnsNames())
	}
	if len(resp.GetIpAddresses()) > 0 {
		fmt.Printf("  IP Addresses: %v\n", resp.GetIpAddresses())
	}

	if resp.GetCreatedAt() != nil {
		fmt.Printf("  Created At: %s\n", resp.GetCreatedAt().AsTime().Format(time.RFC3339))
	}
	if resp.GetCompletedAt() != nil {
		fmt.Printf("  Completed At: %s\n", resp.GetCompletedAt().AsTime().Format(time.RFC3339))
	}
	if resp.ErrorMessage != nil && *resp.ErrorMessage != "" {
		fmt.Printf("  Error: %s\n", *resp.ErrorMessage)
	}

	// Suggest next command based on status
	switch resp.GetStatus() {
	case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_COMPLETED:
		fmt.Printf("\nJob completed! Get the result with:\n")
		fmt.Printf("  lcm-client job result --job-id %s\n", jobIDStatus)
	case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PENDING, lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PROCESSING:
		fmt.Printf("\nJob is still processing. Check again later.\n")
	case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_FAILED:
		fmt.Printf("\nJob failed. Check the error message above.\n")
	}

	return nil
}
