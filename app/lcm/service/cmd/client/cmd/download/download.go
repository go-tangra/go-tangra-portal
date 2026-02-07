package download

import (
	"context"
	"crypto/x509"
	"encoding/pem"
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

var requestID string

// Command is the download command
var Command = &cobra.Command{
	Use:   "download",
	Short: "Download an issued certificate",
	Long: `Download an issued certificate from the LCM server.

Use this command after your certificate request has been approved.

Example:
  lcm-client download --request-id abc123-def456
`,
	RunE: runDownload,
}

func init() {
	Command.Flags().StringVar(&requestID, "request-id", "", "Request ID to download certificate for (required)")
	_ = Command.MarkFlagRequired("request-id")
}

func runDownload(c *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clientID := getClientID()
	serverAddr := viper.GetString("server")
	configDir := expandPath(viper.GetString("config-dir"))

	// Set certificate paths
	keyFile := viper.GetString("key")
	if keyFile == "" {
		keyFile = filepath.Join(configDir, fmt.Sprintf("%s.key", clientID))
	}
	certFile := viper.GetString("cert")
	if certFile == "" {
		certFile = filepath.Join(configDir, fmt.Sprintf("%s.crt", clientID))
	}
	caFile := viper.GetString("ca")
	if caFile == "" {
		caFile = filepath.Join(configDir, "ca.crt")
	}

	fmt.Printf("Downloading certificate for request '%s'...\n", requestID)

	// Load private key to extract public key
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read private key from %s: %w", keyFile, err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// Extract public key
	var pubKeyBytes []byte
	switch key := privateKey.(type) {
	case interface{ Public() interface{} }:
		pubKeyBytes, err = x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			return fmt.Errorf("failed to marshal public key: %w", err)
		}
	default:
		return fmt.Errorf("unsupported private key type")
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	// Connect to server (TLS without client cert)
	fmt.Printf("Connecting to server '%s'...\n", serverAddr)
	conn, err := client.CreateTLSConnectionWithoutClientCert(serverAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	// Create gRPC client
	grpcClient := lcmV1.NewLcmClientServiceClient(conn)

	// Send download request
	req := &lcmV1.DownloadClientCertificateRequest{
		RequestId: requestID,
		ClientId:  clientID,
		PublicKey: string(pubKeyPEM),
	}

	resp, err := grpcClient.DownloadClientCertificate(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to download certificate: %w", err)
	}

	// Check response status
	status := resp.GetStatus()
	switch status {
	case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_ISSUED:
		// Certificate ready - save it
		fmt.Println("Certificate is ready!")

		// Ensure config directory exists
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}

		// Save client certificate
		certPEM := resp.GetCertificatePem()
		if certPEM != "" {
			if err := os.WriteFile(certFile, []byte(certPEM), 0600); err != nil {
				return fmt.Errorf("failed to save certificate: %w", err)
			}
			fmt.Printf("Certificate saved to: %s\n", certFile)
		} else {
			return fmt.Errorf("no certificate in response")
		}

		// Save CA certificate
		caCertPEM := resp.GetCaCertificatePem()
		if caCertPEM != "" {
			if err := os.WriteFile(caFile, []byte(caCertPEM), 0644); err != nil {
				return fmt.Errorf("failed to save CA certificate: %w", err)
			}
			fmt.Printf("CA certificate saved to: %s\n", caFile)
		}

		fmt.Println("\nDownload complete! You can now use authenticated commands.")

	case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_PENDING:
		fmt.Println("Certificate is still pending approval. Check status with:")
		fmt.Printf("  lcm-client status --request-id %s\n", requestID)

	case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_REVOKED:
		fmt.Println("Certificate has been revoked. You may need to re-register.")

	default:
		fmt.Printf("Unexpected certificate status: %v\n", status)
	}

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
