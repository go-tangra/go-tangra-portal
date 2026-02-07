package daemon

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/cmd/client/internal/hook"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/cmd/client/internal/machine"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/cmd/client/internal/storage"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/client"
)

var (
	deployHook       string
	deployScriptHook string
	hookTimeout      time.Duration
	syncInterval     time.Duration
	oneShot          bool
)

// Command is the daemon command
var Command = &cobra.Command{
	Use:   "daemon",
	Short: "Run in daemon mode, syncing and watching for certificate updates",
	Long: `Run the LCM client in daemon mode.

In this mode, the client:
1. Connects to the LCM server using mTLS
2. Syncs all available certificates for this client
3. Downloads new or renewed certificates to local storage
4. Executes deploy hooks for each new/updated certificate
5. Listens for real-time certificate updates via streaming

The certificates are stored in a certbot-like structure:
  ~/.lcm-client/live/<cert-name>/cert.pem      - Certificate
  ~/.lcm-client/live/<cert-name>/privkey.pem   - Private key
  ~/.lcm-client/live/<cert-name>/chain.pem     - CA chain
  ~/.lcm-client/live/<cert-name>/fullchain.pem - Cert + chain

Environment variables passed to hooks:
  LCM_CERT_NAME      - Certificate name
  LCM_CERT_PATH      - Path to certificate file
  LCM_KEY_PATH       - Path to private key file
  LCM_CHAIN_PATH     - Path to CA chain file
  LCM_FULLCHAIN_PATH - Path to fullchain file
  LCM_COMMON_NAME    - Certificate common name
  LCM_DNS_NAMES      - Comma-separated DNS names
  LCM_IP_ADDRESSES   - Comma-separated IP addresses
  LCM_SERIAL_NUMBER  - Certificate serial number
  LCM_EXPIRES_AT     - Certificate expiry (RFC3339)
  LCM_IS_RENEWAL     - "true" if this is a renewal

Example:
  lcm-client daemon --deploy-hook "/usr/local/bin/reload-nginx.sh"
  lcm-client daemon --deploy-hook "systemctl reload nginx"
  lcm-client daemon --one-shot  # Sync once and exit
`,
	RunE: runDaemon,
}

func init() {
	Command.Flags().StringVar(&deployHook, "deploy-hook", "", "Path to bash script to run after certificate deployment")
	Command.Flags().StringVar(&deployScriptHook, "deploy-script-hook", "", "Path to Lua (.lua) or JavaScript (.js) script to run after certificate deployment")
	Command.Flags().DurationVar(&hookTimeout, "hook-timeout", 5*time.Minute, "Timeout for hook execution")
	Command.Flags().DurationVar(&syncInterval, "sync-interval", 1*time.Hour, "Interval between certificate syncs (for fallback)")
	Command.Flags().BoolVar(&oneShot, "one-shot", false, "Sync certificates once and exit (don't stream)")
}

func runDaemon(c *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
	}()

	clientID := getClientID()
	serverAddr := viper.GetString("server")
	configDir := expandPath(viper.GetString("config-dir"))

	// Initialize certificate store
	store, err := storage.NewCertStore(configDir)
	if err != nil {
		return fmt.Errorf("failed to initialize certificate store: %w", err)
	}

	// Initialize hook runner
	hookRunner := hook.NewRunner()
	defer hookRunner.Close()

	hookConfig := &hook.HookConfig{
		BashScript: deployHook,
		ScriptFile: deployScriptHook,
		Timeout:    hookTimeout,
	}

	// Get mTLS credentials
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

	fmt.Printf("LCM Client Daemon\n")
	fmt.Printf("  Client ID:  %s\n", clientID)
	fmt.Printf("  Server:     %s\n", serverAddr)
	fmt.Printf("  Store:      %s\n", store.BaseDir())
	if deployHook != "" {
		fmt.Printf("  Deploy Hook (bash): %s\n", deployHook)
	}
	if deployScriptHook != "" {
		fmt.Printf("  Deploy Hook (script): %s\n", deployScriptHook)
	}
	fmt.Println()

	// Create mTLS connection
	fmt.Printf("Connecting to server '%s' with mTLS...\n", serverAddr)
	conn, err := client.CreateMTLSConnection(serverAddr, certFile, keyFile, caFile)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	grpcClient := lcmV1.NewLcmClientServiceClient(conn)

	// Initial sync
	fmt.Println("Syncing certificates...")
	updated, err := syncCertificates(ctx, grpcClient, store, hookRunner, hookConfig, clientID)
	if err != nil {
		return fmt.Errorf("initial sync failed: %w", err)
	}
	fmt.Printf("Sync complete: %d certificates updated\n", updated)

	if oneShot {
		fmt.Println("One-shot mode: exiting")
		return nil
	}

	// Start streaming updates
	fmt.Println("\nListening for certificate updates...")
	return streamUpdates(ctx, grpcClient, store, hookRunner, hookConfig, clientID, syncInterval)
}

// syncCertificates fetches and stores all certificates for the client
func syncCertificates(ctx context.Context, grpcClient lcmV1.LcmClientServiceClient, store *storage.CertStore, hookRunner *hook.Runner, hookConfig *hook.HookConfig, clientID string) (int, error) {
	// List all certificates
	resp, err := grpcClient.ListClientCertificates(ctx, &lcmV1.ListClientCertificatesRequest{
		ClientId:             &clientID,
		IncludeCertificatePem: boolPtr(true),
	})
	if err != nil {
		return 0, fmt.Errorf("failed to list certificates: %w", err)
	}

	caCertPEM := resp.GetCaCertificatePem()
	updatedCount := 0

	for _, certInfo := range resp.GetCertificates() {
		if certInfo.GetStatus() != lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_ISSUED {
			continue // Skip non-issued certificates
		}

		certName := getCertName(certInfo)
		certPEM := certInfo.GetCertificatePem()

		if certPEM == "" {
			fmt.Printf("  Skipping %s: no certificate PEM\n", certName)
			continue
		}

		// Check if certificate has changed
		existingMeta, _ := store.LoadMetadata(certName)
		if existingMeta != nil && existingMeta.SerialNumber == certInfo.GetSerialNumber() {
			fmt.Printf("  %s: up to date\n", certName)
			continue
		}

		isRenewal := existingMeta != nil
		previousSerial := ""
		renewalCount := 0
		if isRenewal {
			previousSerial = existingMeta.SerialNumber
			renewalCount = existingMeta.RenewalCount + 1
		}

		// Load existing private key (we don't get it from the server)
		keyPEM := ""
		if store.CertificateExists(certName) {
			keyPEM, _ = store.LoadPrivateKey(certName)
		}

		// Build metadata
		var expiresAt time.Time
		if certInfo.GetExpiresAt() != nil {
			expiresAt = certInfo.GetExpiresAt().AsTime()
		}
		var issuedAt time.Time
		if certInfo.GetIssuedAt() != nil {
			issuedAt = certInfo.GetIssuedAt().AsTime()
		}

		metadata := &storage.CertMetadata{
			Name:           certName,
			CommonName:     certInfo.GetCommonName(),
			SerialNumber:   certInfo.GetSerialNumber(),
			Fingerprint:    certInfo.GetFingerprintSha256(),
			IssuedAt:       issuedAt,
			ExpiresAt:      expiresAt,
			IssuerName:     certInfo.GetIssuerName(),
			DNSNames:       certInfo.GetDnsNames(),
			IPAddresses:    certInfo.GetIpAddresses(),
			PreviousSerial: previousSerial,
			RenewalCount:   renewalCount,
		}

		// Save certificate
		if err := store.SaveCertificate(certName, certPEM, keyPEM, caCertPEM, metadata); err != nil {
			fmt.Printf("  %s: failed to save: %v\n", certName, err)
			continue
		}

		action := "downloaded"
		if isRenewal {
			action = "renewed"
		}
		fmt.Printf("  %s: %s (serial: %s)\n", certName, action, certInfo.GetSerialNumber())
		updatedCount++

		// Run deploy hook
		if hookConfig.BashScript != "" || hookConfig.ScriptFile != "" {
			paths := store.GetPaths(certName)
			hookCtx := &hook.HookContext{
				CertName:      certName,
				CertPath:      paths.CertFile,
				KeyPath:       paths.PrivKeyFile,
				ChainPath:     paths.ChainFile,
				FullChainPath: paths.FullChainFile,
				CommonName:    certInfo.GetCommonName(),
				DNSNames:      certInfo.GetDnsNames(),
				IPAddresses:   certInfo.GetIpAddresses(),
				SerialNumber:  certInfo.GetSerialNumber(),
				ExpiresAt:     expiresAt.Format(time.RFC3339),
				IsRenewal:     isRenewal,
			}

			fmt.Printf("    Running deploy hook...\n")
			result := hookRunner.RunDeployHook(ctx, hookConfig, hookCtx)
			if result.Success {
				fmt.Printf("    Hook completed successfully (%.2fs)\n", result.Duration.Seconds())
				// Update metadata with hook execution time
				_ = store.UpdateMetadata(certName, func(m *storage.CertMetadata) {
					m.LastHookExecution = time.Now()
				})
			} else {
				fmt.Printf("    Hook failed (exit %d): %s\n", result.ExitCode, result.ErrorMsg)
			}
			if result.Output != "" {
				fmt.Printf("    Output: %s\n", result.Output)
			}
		}
	}

	return updatedCount, nil
}

// streamUpdates listens for certificate updates via streaming
func streamUpdates(ctx context.Context, grpcClient lcmV1.LcmClientServiceClient, store *storage.CertStore, hookRunner *hook.Runner, hookConfig *hook.HookConfig, clientID string, fallbackInterval time.Duration) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		err := runStreamLoop(ctx, grpcClient, store, hookRunner, hookConfig, clientID)
		if err != nil {
			if ctx.Err() != nil {
				return nil // Context cancelled, exit gracefully
			}
			fmt.Printf("Stream disconnected: %v\n", err)
		}

		// On disconnect, do a sync and wait before reconnecting
		fmt.Println("Performing fallback sync...")
		if _, err := syncCertificates(ctx, grpcClient, store, hookRunner, hookConfig, clientID); err != nil {
			fmt.Printf("Fallback sync failed: %v\n", err)
		}

		fmt.Printf("Reconnecting in %s...\n", fallbackInterval)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(fallbackInterval):
		}
	}
}

// runStreamLoop runs the streaming update loop
func runStreamLoop(ctx context.Context, grpcClient lcmV1.LcmClientServiceClient, store *storage.CertStore, hookRunner *hook.Runner, hookConfig *hook.HookConfig, clientID string) error {
	stream, err := grpcClient.StreamCertificateUpdates(ctx, &lcmV1.StreamCertificateUpdatesRequest{
		ClientId: &clientID,
	})
	if err != nil {
		return fmt.Errorf("failed to start stream: %w", err)
	}

	for {
		event, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		handleUpdateEvent(ctx, event, store, hookRunner, hookConfig)
	}
}

// handleUpdateEvent processes a certificate update event
func handleUpdateEvent(ctx context.Context, event *lcmV1.CertificateUpdateEvent, store *storage.CertStore, hookRunner *hook.Runner, hookConfig *hook.HookConfig) {
	certInfo := event.GetCertificate()
	if certInfo == nil {
		return
	}

	certName := getCertName(certInfo)
	eventType := event.GetEventType()

	switch eventType {
	case lcmV1.CertificateUpdateType_CERTIFICATE_ISSUED,
		lcmV1.CertificateUpdateType_CERTIFICATE_RENEWED:

		fmt.Printf("\n[%s] Certificate %s: %s\n",
			time.Now().Format("15:04:05"),
			eventType.String(),
			certName)

		certPEM := certInfo.GetCertificatePem()
		if certPEM == "" {
			fmt.Printf("  No certificate PEM in event, will sync on next interval\n")
			return
		}

		// Check existing certificate
		existingMeta, _ := store.LoadMetadata(certName)
		isRenewal := existingMeta != nil
		previousSerial := ""
		renewalCount := 0
		if isRenewal {
			previousSerial = existingMeta.SerialNumber
			renewalCount = existingMeta.RenewalCount + 1
		}

		// Load existing private key
		keyPEM := ""
		if store.CertificateExists(certName) {
			keyPEM, _ = store.LoadPrivateKey(certName)
		}

		// Build metadata
		var expiresAt time.Time
		if certInfo.GetExpiresAt() != nil {
			expiresAt = certInfo.GetExpiresAt().AsTime()
		}
		var issuedAt time.Time
		if certInfo.GetIssuedAt() != nil {
			issuedAt = certInfo.GetIssuedAt().AsTime()
		}

		metadata := &storage.CertMetadata{
			Name:           certName,
			CommonName:     certInfo.GetCommonName(),
			SerialNumber:   certInfo.GetSerialNumber(),
			Fingerprint:    certInfo.GetFingerprintSha256(),
			IssuedAt:       issuedAt,
			ExpiresAt:      expiresAt,
			IssuerName:     certInfo.GetIssuerName(),
			DNSNames:       certInfo.GetDnsNames(),
			IPAddresses:    certInfo.GetIpAddresses(),
			PreviousSerial: previousSerial,
			RenewalCount:   renewalCount,
		}

		caCertPEM := event.GetCaCertificatePem()

		// Save certificate
		if err := store.SaveCertificate(certName, certPEM, keyPEM, caCertPEM, metadata); err != nil {
			fmt.Printf("  Failed to save: %v\n", err)
			return
		}
		fmt.Printf("  Saved to %s/live/%s/\n", store.BaseDir(), certName)

		// Run deploy hook
		if hookConfig.BashScript != "" || hookConfig.ScriptFile != "" {
			paths := store.GetPaths(certName)
			hookCtx := &hook.HookContext{
				CertName:      certName,
				CertPath:      paths.CertFile,
				KeyPath:       paths.PrivKeyFile,
				ChainPath:     paths.ChainFile,
				FullChainPath: paths.FullChainFile,
				CommonName:    certInfo.GetCommonName(),
				DNSNames:      certInfo.GetDnsNames(),
				IPAddresses:   certInfo.GetIpAddresses(),
				SerialNumber:  certInfo.GetSerialNumber(),
				ExpiresAt:     expiresAt.Format(time.RFC3339),
				IsRenewal:     isRenewal,
			}

			fmt.Printf("  Running deploy hook...\n")
			result := hookRunner.RunDeployHook(ctx, hookConfig, hookCtx)
			if result.Success {
				fmt.Printf("  Hook completed successfully (%.2fs)\n", result.Duration.Seconds())
				_ = store.UpdateMetadata(certName, func(m *storage.CertMetadata) {
					m.LastHookExecution = time.Now()
				})
			} else {
				fmt.Printf("  Hook failed (exit %d): %s\n", result.ExitCode, result.ErrorMsg)
			}
			if result.Output != "" {
				fmt.Printf("  Output: %s\n", result.Output)
			}
		}

	case lcmV1.CertificateUpdateType_CERTIFICATE_REVOKED:
		fmt.Printf("\n[%s] Certificate REVOKED: %s\n",
			time.Now().Format("15:04:05"),
			certName)
		// Optionally delete the certificate
		// store.DeleteCertificate(certName)

	case lcmV1.CertificateUpdateType_CERTIFICATE_EXPIRING:
		fmt.Printf("\n[%s] Certificate EXPIRING SOON: %s\n",
			time.Now().Format("15:04:05"),
			certName)
	}
}

// getCertName returns a certificate name from CertificateInfo
func getCertName(certInfo *lcmV1.CertificateInfo) string {
	if certInfo.GetName() != "" {
		return certInfo.GetName()
	}
	if certInfo.GetCommonName() != "" {
		return certInfo.GetCommonName()
	}
	return "unknown"
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

func boolPtr(v bool) *bool {
	return &v
}
