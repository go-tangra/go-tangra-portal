package job

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/client"
)

var (
	jobIDResult       string
	includePrivateKey bool
	outputDir         string
	outputPrefix      string
)

var resultCmd = &cobra.Command{
	Use:   "result",
	Short: "Get the result of a completed certificate job",
	Long: `Get the certificate and related files from a completed job.

Example:
  lcm-client job result --job-id 550e8400-e29b-41d4-a716-446655440000
  lcm-client job result --job-id <id> --include-key --output-dir /etc/ssl
`,
	RunE: runResult,
}

func init() {
	resultCmd.Flags().StringVar(&jobIDResult, "job-id", "", "Job ID to get result (required)")
	resultCmd.Flags().BoolVar(&includePrivateKey, "include-key", false, "Include private key in response (if server-generated)")
	resultCmd.Flags().StringVar(&outputDir, "output-dir", ".", "Directory to save certificate files")
	resultCmd.Flags().StringVar(&outputPrefix, "output-prefix", "", "Prefix for output files (default: common name from certificate)")

	_ = resultCmd.MarkFlagRequired("job-id")
}

func runResult(c *cobra.Command, args []string) error {
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

	fmt.Printf("Getting job result from server '%s'...\n", serverAddr)

	// Connect with mTLS
	conn, err := client.CreateMTLSConnection(serverAddr, certFile, keyFile, caFile)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	// Create gRPC client
	grpcClient := lcmV1.NewLcmCertificateJobServiceClient(conn)

	// Build request
	req := &lcmV1.GetJobResultRequest{
		JobId:             jobIDResult,
		IncludePrivateKey: &includePrivateKey,
	}

	// Send request
	resp, err := grpcClient.GetJobResult(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to get job result: %w", err)
	}

	// Check status
	if resp.GetStatus() != lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_COMPLETED {
		fmt.Printf("Job is not completed yet. Status: %s\n", resp.GetStatus().String())
		if resp.ErrorMessage != nil && *resp.ErrorMessage != "" {
			fmt.Printf("Error: %s\n", *resp.ErrorMessage)
		}
		return nil
	}

	// Display result info
	fmt.Printf("\nJob Result:\n")
	fmt.Printf("  Job ID: %s\n", resp.GetJobId())
	fmt.Printf("  Status: %s\n", resp.GetStatus().String())
	if resp.SerialNumber != nil {
		fmt.Printf("  Serial Number: %s\n", *resp.SerialNumber)
	}
	if resp.GetIssuedAt() != nil {
		fmt.Printf("  Issued At: %s\n", resp.GetIssuedAt().AsTime().Format(time.RFC3339))
	}
	if resp.GetExpiresAt() != nil {
		fmt.Printf("  Expires At: %s\n", resp.GetExpiresAt().AsTime().Format(time.RFC3339))
	}
	if resp.KeyType != nil {
		fmt.Printf("  Key Type: %s\n", *resp.KeyType)
	}
	if resp.KeySize != nil {
		fmt.Printf("  Key Size: %d\n", *resp.KeySize)
	}

	// Determine output prefix
	prefix := outputPrefix
	if prefix == "" {
		prefix = jobIDResult
	}

	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Save certificate
	if resp.CertificatePem != nil && *resp.CertificatePem != "" {
		certPath := filepath.Join(outputDir, fmt.Sprintf("%s.crt", prefix))
		if err := os.WriteFile(certPath, []byte(*resp.CertificatePem), 0644); err != nil {
			return fmt.Errorf("failed to save certificate: %w", err)
		}
		fmt.Printf("\nCertificate saved to: %s\n", certPath)
	}

	// Save CA certificate
	if resp.CaCertificatePem != nil && *resp.CaCertificatePem != "" {
		caPath := filepath.Join(outputDir, fmt.Sprintf("%s-ca.crt", prefix))
		if err := os.WriteFile(caPath, []byte(*resp.CaCertificatePem), 0644); err != nil {
			return fmt.Errorf("failed to save CA certificate: %w", err)
		}
		fmt.Printf("CA certificate saved to: %s\n", caPath)
	}

	// Save private key (if included)
	if resp.PrivateKeyPem != nil && *resp.PrivateKeyPem != "" {
		keyPath := filepath.Join(outputDir, fmt.Sprintf("%s.key", prefix))
		if err := os.WriteFile(keyPath, []byte(*resp.PrivateKeyPem), 0600); err != nil {
			return fmt.Errorf("failed to save private key: %w", err)
		}
		fmt.Printf("Private key saved to: %s\n", keyPath)
	}

	// Save CSR (if included)
	if resp.CsrPem != nil && *resp.CsrPem != "" {
		csrPath := filepath.Join(outputDir, fmt.Sprintf("%s.csr", prefix))
		if err := os.WriteFile(csrPath, []byte(*resp.CsrPem), 0644); err != nil {
			return fmt.Errorf("failed to save CSR: %w", err)
		}
		fmt.Printf("CSR saved to: %s\n", csrPath)
	}

	return nil
}
