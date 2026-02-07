package register

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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

var (
	sharedSecret string
	hostname     string
	dnsNames     []string
	ipAddresses  []string
	keySize      int
)

// Command is the register command
var Command = &cobra.Command{
	Use:   "register",
	Short: "Register this client with the LCM server",
	Long: `Register this client with the LCM server and request a certificate.

This command generates a key pair, sends a registration request to the server,
and saves the issued certificate (or request ID for pending requests).

Example:
  lcm-client register --secret my-shared-secret
  lcm-client register --secret my-secret --client-id my-client --hostname myhost.local
`,
	RunE: runRegister,
}

func init() {
	Command.Flags().StringVar(&sharedSecret, "secret", "", "Shared secret for authentication (required)")
	Command.Flags().StringVar(&hostname, "hostname", "", "Hostname for certificate (defaults to system hostname)")
	Command.Flags().StringSliceVar(&dnsNames, "dns", nil, "Additional DNS names for certificate")
	Command.Flags().StringSliceVar(&ipAddresses, "ip", nil, "Additional IP addresses for certificate")
	Command.Flags().IntVar(&keySize, "key-size", 2048, "RSA key size in bits (2048 or 4096)")

	_ = Command.MarkFlagRequired("secret")
}

func runRegister(c *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get configuration from viper (set by root command)
	configDir := expandPath(viper.GetString("config-dir"))
	clientID := getClientID()
	serverAddr := viper.GetString("server")

	// Ensure config directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

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

	fmt.Printf("Registering client '%s' with server '%s'...\n", clientID, serverAddr)

	// Get hostname
	if hostname == "" {
		hostname = machine.GetHostname()
	}

	// Generate RSA key pair
	fmt.Printf("Generating %d-bit RSA key pair...\n", keySize)
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Save private key
	if err := savePrivateKey(privateKey, keyFile); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}
	fmt.Printf("Private key saved to: %s\n", keyFile)

	// Encode public key to PEM
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	// Collect DNS names (hostname + additional)
	allDNSNames := []string{hostname}
	allDNSNames = append(allDNSNames, dnsNames...)

	// Collect IP addresses (auto-detect + additional)
	allIPAddresses := machine.GetLocalIPAddresses()
	allIPAddresses = append(allIPAddresses, ipAddresses...)

	// Get metadata
	metadata := machine.GetMetadata()

	// Connect to server (TLS without client cert for registration)
	fmt.Printf("Connecting to server...\n")
	conn, err := client.CreateTLSConnectionWithoutClientCert(serverAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	// Create gRPC client
	grpcClient := lcmV1.NewLcmClientServiceClient(conn)

	// Build registration request
	req := &lcmV1.CreateLcmClientRequest{
		ClientId:     clientID,
		Hostname:     hostname,
		SharedSecret: &sharedSecret,
		PublicKey:    string(pubKeyPEM),
		DnsNames:     allDNSNames,
		IpAddresses:  allIPAddresses,
		Metadata:     metadata,
	}

	// Send registration request
	fmt.Printf("Sending registration request...\n")
	resp, err := grpcClient.RegisterLcmClient(ctx, req)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	// Handle response
	if resp.Client != nil && resp.Client.TenantId != nil {
		fmt.Printf("Registered with tenant ID: %d\n", resp.Client.GetTenantId())
	}

	if resp.Certificate != nil {
		status := resp.Certificate.GetStatus()

		switch status {
		case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_ISSUED:
			// Certificate issued immediately - save it
			fmt.Println("Certificate issued successfully!")

			// Save client certificate
			certPEM := resp.Certificate.GetCertificatePem()
			if certPEM != "" {
				if err := os.WriteFile(certFile, []byte(certPEM), 0600); err != nil {
					return fmt.Errorf("failed to save certificate: %w", err)
				}
				fmt.Printf("Certificate saved to: %s\n", certFile)
			}

			// Save CA certificate
			caCertPEM := resp.GetCaCertificate()
			if caCertPEM != "" {
				if err := os.WriteFile(caFile, []byte(caCertPEM), 0644); err != nil {
					return fmt.Errorf("failed to save CA certificate: %w", err)
				}
				fmt.Printf("CA certificate saved to: %s\n", caFile)
			}

			fmt.Println("\nRegistration complete! You can now use authenticated commands.")

		case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_PENDING:
			// Certificate pending approval
			requestID := resp.Certificate.GetRequestId()
			fmt.Println("Certificate request is pending approval.")
			fmt.Printf("\nRequest ID: %s\n", requestID)
			fmt.Println("\nUse the following commands to check status and download:")
			fmt.Printf("  lcm-client status --request-id %s\n", requestID)
			fmt.Printf("  lcm-client download --request-id %s\n", requestID)

		default:
			fmt.Printf("Unexpected certificate status: %v\n", status)
		}
	} else if resp.Client != nil {
		// Client created but no certificate info
		fmt.Printf("Client registered successfully (ID: %s)\n", resp.Client.GetClientId())
		fmt.Println("No certificate information in response. Certificate may be pending.")
	} else {
		fmt.Println("Registration completed but no certificate or client info in response.")
	}

	return nil
}

func savePrivateKey(key *rsa.PrivateKey, path string) error {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	if err := os.WriteFile(path, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key file: %w", err)
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
