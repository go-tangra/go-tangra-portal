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
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/cmd/client/internal/machine"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/client"
)

var (
	issuerName        string
	commonName        string
	dnsNames          []string
	ipAddresses       []string
	keyType           string
	keySize           int32
	validityDays      int32
	csrPEM            string
	waitForCompletion bool
	waitTimeout       time.Duration
	reqOutputDir      string
	reqOutputPrefix   string
	reqIncludeKey     bool
)

var requestCmd = &cobra.Command{
	Use:   "request",
	Short: "Request a new certificate job",
	Long: `Request a new certificate from the LCM server asynchronously.

This command creates a certificate job that will be processed by the server.
You can check the status with 'job status' and get the result with 'job result'.

Use --wait to wait for the certificate to be issued and download it automatically.

Example:
  lcm-client job request --issuer my-issuer --cn example.com
  lcm-client job request --issuer acme-issuer --cn example.com --dns www.example.com --dns api.example.com
  lcm-client job request --issuer my-issuer --cn myhost --key-type ecdsa --key-size 256
  lcm-client job request --issuer my-issuer --cn example.com --wait --output-dir /etc/ssl
`,
	RunE: runRequest,
}

func init() {
	requestCmd.Flags().StringVar(&issuerName, "issuer", "", "Issuer name to use for certificate generation (required)")
	requestCmd.Flags().StringVar(&commonName, "cn", "", "Common name for the certificate (required)")
	requestCmd.Flags().StringSliceVar(&dnsNames, "dns", nil, "DNS names for Subject Alternative Names")
	requestCmd.Flags().StringSliceVar(&ipAddresses, "ip", nil, "IP addresses for Subject Alternative Names")
	requestCmd.Flags().StringVar(&keyType, "key-type", "rsa", "Key type: rsa or ecdsa")
	requestCmd.Flags().Int32Var(&keySize, "key-size", 2048, "Key size in bits (2048/4096 for RSA, 256/384 for ECDSA)")
	requestCmd.Flags().Int32Var(&validityDays, "validity", 365, "Certificate validity in days (1-825)")
	requestCmd.Flags().StringVar(&csrPEM, "csr", "", "Optional CSR file path (if not provided, key will be generated)")

	// Wait mode flags
	requestCmd.Flags().BoolVar(&waitForCompletion, "wait", false, "Wait for certificate to be issued and download automatically")
	requestCmd.Flags().DurationVar(&waitTimeout, "wait-timeout", 15*time.Minute, "Maximum time to wait for certificate (used with --wait)")
	requestCmd.Flags().StringVar(&reqOutputDir, "output-dir", ".", "Directory to save certificate files (used with --wait)")
	requestCmd.Flags().StringVar(&reqOutputPrefix, "output-prefix", "", "Prefix for output files (default: common name)")
	requestCmd.Flags().BoolVar(&reqIncludeKey, "include-key", true, "Include private key in downloaded files (used with --wait)")

	_ = requestCmd.MarkFlagRequired("issuer")
	_ = requestCmd.MarkFlagRequired("cn")
}

func runRequest(c *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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

	fmt.Printf("Requesting certificate job from server '%s'...\n", serverAddr)
	fmt.Printf("  Issuer: %s\n", issuerName)
	fmt.Printf("  Common Name: %s\n", commonName)

	// Connect with mTLS
	conn, err := client.CreateMTLSConnection(serverAddr, certFile, keyFile, caFile)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	// Create gRPC client for certificate job service
	grpcClient := lcmV1.NewLcmCertificateJobServiceClient(conn)

	// Read CSR file if provided
	var csrContent *string
	if csrPEM != "" {
		csrData, err := os.ReadFile(csrPEM)
		if err != nil {
			return fmt.Errorf("failed to read CSR file: %w", err)
		}
		csrStr := string(csrData)
		csrContent = &csrStr
	}

	// Build request
	req := &lcmV1.RequestCertificateRequest{
		IssuerName:   issuerName,
		CommonName:   commonName,
		DnsNames:     dnsNames,
		IpAddresses:  ipAddresses,
		KeyType:      &keyType,
		KeySize:      &keySize,
		ValidityDays: &validityDays,
		CsrPem:       csrContent,
	}

	// Send request
	resp, err := grpcClient.RequestCertificate(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to request certificate: %w", err)
	}

	// Display result
	fmt.Printf("\nCertificate job created successfully!\n")
	fmt.Printf("  Job ID: %s\n", resp.GetJobId())
	fmt.Printf("  Status: %s\n", resp.GetStatus().String())
	if resp.GetMessage() != "" {
		fmt.Printf("  Message: %s\n", resp.GetMessage())
	}

	// If --wait flag is set, poll for completion and download certificate
	if waitForCompletion {
		return waitAndDownloadCertificate(grpcClient, resp.GetJobId())
	}

	fmt.Println("\nUse the following commands to check status and get result:")
	fmt.Printf("  lcm-client job status --job-id %s\n", resp.GetJobId())
	fmt.Printf("  lcm-client job result --job-id %s\n", resp.GetJobId())

	return nil
}

// waitAndDownloadCertificate polls for job completion with exponential backoff
// and downloads the certificate when ready
func waitAndDownloadCertificate(grpcClient lcmV1.LcmCertificateJobServiceClient, jobID string) error {
	fmt.Printf("\nWaiting for certificate to be issued (timeout: %s)...\n", waitTimeout)

	// Exponential backoff parameters
	initialInterval := 1 * time.Second
	maxInterval := 30 * time.Second
	multiplier := 2.0
	currentInterval := initialInterval

	startTime := time.Now()
	deadline := startTime.Add(waitTimeout)

	for {
		// Check if we've exceeded the timeout
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for certificate (waited %s)", waitTimeout)
		}

		// Create context for this request
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

		// Check job status
		statusResp, err := grpcClient.GetJobStatus(ctx, &lcmV1.GetJobStatusRequest{
			JobId: jobID,
		})
		cancel()

		if err != nil {
			fmt.Printf("  Warning: failed to get status: %v (retrying...)\n", err)
		} else {
			elapsed := time.Since(startTime).Round(time.Second)
			fmt.Printf("  [%s] Status: %s\n", elapsed, statusResp.GetStatus().String())

			switch statusResp.GetStatus() {
			case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_COMPLETED:
				fmt.Printf("\nCertificate issued successfully!\n")
				return downloadCertificateResult(grpcClient, jobID)

			case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_FAILED:
				errMsg := "unknown error"
				if statusResp.ErrorMessage != nil {
					errMsg = *statusResp.ErrorMessage
				}
				return fmt.Errorf("certificate issuance failed: %s", errMsg)

			case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_CANCELLED:
				return fmt.Errorf("certificate job was cancelled")

			case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PENDING,
				lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PROCESSING:
				// Continue polling
			}
		}

		// Wait with exponential backoff
		time.Sleep(currentInterval)

		// Increase interval (with max cap)
		currentInterval = time.Duration(float64(currentInterval) * multiplier)
		if currentInterval > maxInterval {
			currentInterval = maxInterval
		}
	}
}

// downloadCertificateResult downloads the certificate files from a completed job
func downloadCertificateResult(grpcClient lcmV1.LcmCertificateJobServiceClient, jobID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get job result
	resp, err := grpcClient.GetJobResult(ctx, &lcmV1.GetJobResultRequest{
		JobId:             jobID,
		IncludePrivateKey: &reqIncludeKey,
	})
	if err != nil {
		return fmt.Errorf("failed to get certificate result: %w", err)
	}

	// Check status
	if resp.GetStatus() != lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_COMPLETED {
		return fmt.Errorf("job is not completed, status: %s", resp.GetStatus().String())
	}

	// Display result info
	fmt.Printf("\nCertificate Details:\n")
	if resp.SerialNumber != nil {
		fmt.Printf("  Serial Number: %s\n", *resp.SerialNumber)
	}
	if resp.GetIssuedAt() != nil {
		fmt.Printf("  Issued At: %s\n", resp.GetIssuedAt().AsTime().Format(time.RFC3339))
	}
	if resp.GetExpiresAt() != nil {
		fmt.Printf("  Expires At: %s\n", resp.GetExpiresAt().AsTime().Format(time.RFC3339))
	}

	// Determine output prefix
	prefix := reqOutputPrefix
	if prefix == "" {
		prefix = commonName
	}

	// Ensure output directory exists
	if err := os.MkdirAll(reqOutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	fmt.Printf("\nSaving certificate files:\n")

	// Save certificate
	if resp.CertificatePem != nil && *resp.CertificatePem != "" {
		certPath := filepath.Join(reqOutputDir, fmt.Sprintf("%s.crt", prefix))
		if err := os.WriteFile(certPath, []byte(*resp.CertificatePem), 0644); err != nil {
			return fmt.Errorf("failed to save certificate: %w", err)
		}
		fmt.Printf("  Certificate: %s\n", certPath)
	}

	// Save CA certificate
	if resp.CaCertificatePem != nil && *resp.CaCertificatePem != "" {
		caPath := filepath.Join(reqOutputDir, fmt.Sprintf("%s-ca.crt", prefix))
		if err := os.WriteFile(caPath, []byte(*resp.CaCertificatePem), 0644); err != nil {
			return fmt.Errorf("failed to save CA certificate: %w", err)
		}
		fmt.Printf("  CA Certificate: %s\n", caPath)
	}

	// Save private key (if included)
	if resp.PrivateKeyPem != nil && *resp.PrivateKeyPem != "" {
		keyPath := filepath.Join(reqOutputDir, fmt.Sprintf("%s.key", prefix))
		if err := os.WriteFile(keyPath, []byte(*resp.PrivateKeyPem), 0600); err != nil {
			return fmt.Errorf("failed to save private key: %w", err)
		}
		fmt.Printf("  Private Key: %s\n", keyPath)
	}

	fmt.Printf("\nCertificate successfully downloaded!\n")
	return nil
}

func getClientID() string {
	id := viper.GetString("client-id")
	if id == "" {
		id = machine.GetClientID()
	}
	return id
}

func expandPath(path string) string {
	if len(path) >= 2 && path[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	} else if path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return home
	}
	return path
}
