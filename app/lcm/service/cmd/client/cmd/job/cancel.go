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

var jobIDCancel string

var cancelCmd = &cobra.Command{
	Use:   "cancel",
	Short: "Cancel a pending certificate job",
	Long: `Cancel a pending certificate job.

Note: Only jobs with PENDING status can be cancelled.

Example:
  lcm-client job cancel --job-id 550e8400-e29b-41d4-a716-446655440000
`,
	RunE: runCancel,
}

func init() {
	cancelCmd.Flags().StringVar(&jobIDCancel, "job-id", "", "Job ID to cancel (required)")
	_ = cancelCmd.MarkFlagRequired("job-id")
}

func runCancel(c *cobra.Command, args []string) error {
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

	fmt.Printf("Cancelling job '%s' on server '%s'...\n", jobIDCancel, serverAddr)

	// Connect with mTLS
	conn, err := client.CreateMTLSConnection(serverAddr, certFile, keyFile, caFile)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	// Create gRPC client
	grpcClient := lcmV1.NewLcmCertificateJobServiceClient(conn)

	// Build request
	req := &lcmV1.CancelJobRequest{
		JobId: jobIDCancel,
	}

	// Send request
	_, err = grpcClient.CancelJob(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to cancel job: %w", err)
	}

	fmt.Printf("\nJob '%s' cancelled successfully.\n", jobIDCancel)
	return nil
}
