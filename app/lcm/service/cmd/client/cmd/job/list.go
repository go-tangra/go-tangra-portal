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

var (
	listIssuerName string
	listStatus     string
	listPage       uint32
	listPageSize   uint32
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List certificate jobs",
	Long: `List certificate jobs for the authenticated client.

Example:
  lcm-client job list
  lcm-client job list --status COMPLETED
  lcm-client job list --issuer my-issuer
`,
	RunE: runList,
}

func init() {
	listCmd.Flags().StringVar(&listIssuerName, "issuer", "", "Filter by issuer name")
	listCmd.Flags().StringVar(&listStatus, "status", "", "Filter by status (PENDING, PROCESSING, COMPLETED, FAILED, CANCELLED)")
	listCmd.Flags().Uint32Var(&listPage, "page", 1, "Page number")
	listCmd.Flags().Uint32Var(&listPageSize, "page-size", 20, "Page size")
}

func runList(c *cobra.Command, args []string) error {
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

	fmt.Printf("Listing jobs from server '%s'...\n", serverAddr)

	// Connect with mTLS
	conn, err := client.CreateMTLSConnection(serverAddr, certFile, keyFile, caFile)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	// Create gRPC client
	grpcClient := lcmV1.NewLcmCertificateJobServiceClient(conn)

	// Build request
	req := &lcmV1.ListJobsRequest{
		Page:     &listPage,
		PageSize: &listPageSize,
	}

	if listIssuerName != "" {
		req.IssuerName = &listIssuerName
	}

	if listStatus != "" {
		statusMap := map[string]lcmV1.CertificateJobStatus{
			"PENDING":    lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PENDING,
			"PROCESSING": lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PROCESSING,
			"COMPLETED":  lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_COMPLETED,
			"FAILED":     lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_FAILED,
			"CANCELLED":  lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_CANCELLED,
		}
		if status, ok := statusMap[listStatus]; ok {
			req.Status = &status
		} else {
			return fmt.Errorf("invalid status: %s (valid: PENDING, PROCESSING, COMPLETED, FAILED, CANCELLED)", listStatus)
		}
	}

	// Send request
	resp, err := grpcClient.ListJobs(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to list jobs: %w", err)
	}

	// Display results
	fmt.Printf("\nTotal jobs: %d\n\n", resp.GetTotal())

	if len(resp.GetJobs()) == 0 {
		fmt.Println("No jobs found.")
		return nil
	}

	// Print table header
	fmt.Printf("%-36s  %-12s  %-20s  %-20s  %s\n", "JOB ID", "STATUS", "ISSUER", "COMMON NAME", "CREATED AT")
	fmt.Printf("%-36s  %-12s  %-20s  %-20s  %s\n", "------", "------", "------", "-----------", "----------")

	for _, job := range resp.GetJobs() {
		createdAt := ""
		if job.GetCreatedAt() != nil {
			createdAt = job.GetCreatedAt().AsTime().Format(time.RFC3339)
		}

		statusStr := job.GetStatus().String()
		// Trim the prefix for display
		if len(statusStr) > 27 {
			statusStr = statusStr[27:] // Remove "CERTIFICATE_JOB_STATUS_" prefix
		}

		fmt.Printf("%-36s  %-12s  %-20s  %-20s  %s\n",
			truncate(job.GetJobId(), 36),
			truncate(statusStr, 12),
			truncate(job.GetIssuerName(), 20),
			truncate(job.GetCommonName(), 20),
			createdAt,
		)
	}

	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
