package issuer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/pkg/client"
)

var (
	// Common flags
	issuerName        string
	issuerType        string
	issuerDescription string
	issuerStatus      string
	keyType           string

	// Self-signed flags
	commonName             string
	dnsNames               []string
	ipAddresses            []string
	caCommonName           string
	caOrganization         string
	caOrganizationalUnit   string
	caCountry              string
	caProvince             string
	caLocality             string
	caValidityDays         int32

	// ACME flags
	acmeEmail          string
	acmeEndpoint       string
	acmeKeyType        string
	acmeKeySize        int32
	acmeMaxRetries     int32
	acmeBaseDelay      string
	acmeChallengeType  string
	acmeProviderName   string
	acmeProviderConfig []string
	// EAB (External Account Binding) flags
	acmeEabKid     string
	acmeEabHmacKey string
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new issuer",
	Long: `Create a new certificate issuer.

Issuer Types:
  self-signed - Creates certificates using a self-signed CA
  acme        - Uses ACME protocol (Let's Encrypt, etc.)

Examples:

  # Create a self-signed issuer
  lcm-client issuer create \
    --name my-issuer \
    --type self-signed \
    --common-name "*.example.com" \
    --dns "example.com,*.example.com" \
    --ca-common-name "My CA" \
    --ca-organization "My Org" \
    --ca-validity-days 365

  # Create an ACME issuer (Let's Encrypt staging)
  lcm-client issuer create \
    --name letsencrypt-staging \
    --type acme \
    --acme-email admin@example.com \
    --acme-endpoint https://acme-staging-v02.api.letsencrypt.org/directory \
    --acme-challenge-type HTTP

  # Create an ACME issuer with EAB (e.g., ZeroSSL, Google Trust Services)
  lcm-client issuer create \
    --name zerossl \
    --type acme \
    --acme-email admin@example.com \
    --acme-endpoint https://acme.zerossl.com/v2/DV90 \
    --acme-eab-kid "your-eab-kid" \
    --acme-eab-hmac-key "your-base64-hmac-key"
`,
	RunE: runCreate,
}

func init() {
	// Common flags
	createCmd.Flags().StringVar(&issuerName, "name", "", "Issuer name (required)")
	createCmd.Flags().StringVar(&issuerType, "type", "self-signed", "Issuer type: self-signed or acme")
	createCmd.Flags().StringVar(&issuerDescription, "description", "", "Issuer description")
	createCmd.Flags().StringVar(&issuerStatus, "status", "active", "Initial status: active or disabled")
	createCmd.Flags().StringVar(&keyType, "key-type", "ecdsa", "Key type: ecdsa or rsa")

	// Self-signed flags
	createCmd.Flags().StringVar(&commonName, "common-name", "", "Common name for certificates")
	createCmd.Flags().StringSliceVar(&dnsNames, "dns", nil, "DNS names (comma-separated)")
	createCmd.Flags().StringSliceVar(&ipAddresses, "ip", nil, "IP addresses (comma-separated)")
	createCmd.Flags().StringVar(&caCommonName, "ca-common-name", "", "CA certificate common name")
	createCmd.Flags().StringVar(&caOrganization, "ca-organization", "", "CA organization")
	createCmd.Flags().StringVar(&caOrganizationalUnit, "ca-ou", "", "CA organizational unit")
	createCmd.Flags().StringVar(&caCountry, "ca-country", "", "CA country code (2 letters)")
	createCmd.Flags().StringVar(&caProvince, "ca-province", "", "CA province/state")
	createCmd.Flags().StringVar(&caLocality, "ca-locality", "", "CA locality/city")
	createCmd.Flags().Int32Var(&caValidityDays, "ca-validity-days", 365, "CA validity in days")

	// ACME flags
	createCmd.Flags().StringVar(&acmeEmail, "acme-email", "", "ACME account email")
	createCmd.Flags().StringVar(&acmeEndpoint, "acme-endpoint", "", "ACME server endpoint URL")
	createCmd.Flags().StringVar(&acmeKeyType, "acme-key-type", "rsa", "ACME key type: rsa or ec")
	createCmd.Flags().Int32Var(&acmeKeySize, "acme-key-size", 2048, "ACME key size in bits")
	createCmd.Flags().Int32Var(&acmeMaxRetries, "acme-max-retries", 3, "ACME max retry attempts")
	createCmd.Flags().StringVar(&acmeBaseDelay, "acme-base-delay", "2s", "ACME base delay between retries")
	createCmd.Flags().StringVar(&acmeChallengeType, "acme-challenge-type", "HTTP", "ACME challenge type: HTTP or DNS")
	createCmd.Flags().StringVar(&acmeProviderName, "acme-provider", "", "DNS provider name for DNS challenges")
	createCmd.Flags().StringSliceVar(&acmeProviderConfig, "acme-provider-config", nil, "DNS provider config (key=value)")
	// EAB flags for providers like ZeroSSL, Google Trust Services
	createCmd.Flags().StringVar(&acmeEabKid, "acme-eab-kid", "", "EAB Key Identifier (for ZeroSSL, Google Trust Services, etc.)")
	createCmd.Flags().StringVar(&acmeEabHmacKey, "acme-eab-hmac-key", "", "EAB HMAC Key (base64 encoded)")

	_ = createCmd.MarkFlagRequired("name")
}

func runCreate(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverAddr := viper.GetString("server")
	certFile := viper.GetString("cert")
	keyFile := viper.GetString("key")
	caFile := viper.GetString("ca")

	// Validate flags based on type
	if err := validateCreateFlags(); err != nil {
		return err
	}

	fmt.Printf("Creating issuer '%s' (type: %s) on server '%s'...\n", issuerName, issuerType, serverAddr)

	// Create mTLS connection
	conn, err := client.CreateMTLSConnection(serverAddr, certFile, keyFile, caFile)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Create gRPC client
	grpcClient := lcmV1.NewLcmIssuerServiceClient(conn)

	// Build request
	req := buildCreateRequest()

	// Create issuer
	resp, err := grpcClient.CreateIssuer(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to create issuer: %w", err)
	}

	fmt.Printf("\nIssuer created successfully!\n")
	printIssuerDetails(resp.Issuer)

	return nil
}

func validateCreateFlags() error {
	switch issuerType {
	case "self-signed":
		if commonName == "" {
			return fmt.Errorf("--common-name is required for self-signed issuer")
		}
		if caCommonName == "" {
			return fmt.Errorf("--ca-common-name is required for self-signed issuer")
		}
		if len(dnsNames) == 0 {
			return fmt.Errorf("--dns is required for self-signed issuer (at least one DNS name)")
		}
	case "acme":
		if acmeEmail == "" {
			return fmt.Errorf("--acme-email is required for ACME issuer")
		}
		if acmeEndpoint == "" {
			return fmt.Errorf("--acme-endpoint is required for ACME issuer")
		}
	default:
		return fmt.Errorf("invalid issuer type: %s (must be 'self-signed' or 'acme')", issuerType)
	}
	return nil
}

func buildCreateRequest() *lcmV1.CreateIssuerRequest {
	req := &lcmV1.CreateIssuerRequest{
		Name:        issuerName,
		Type:        issuerType,
		KeyType:     keyType,
		Description: issuerDescription,
		Status:      mapStatusString(issuerStatus),
	}

	switch issuerType {
	case "self-signed":
		req.SelfIssuer = &lcmV1.SelfIssuer{
			CommonName:           commonName,
			DnsNames:             dnsNames,
			IpAddresses:          ipAddresses,
			CaCommonName:         caCommonName,
			CaOrganization:       caOrganization,
			CaOrganizationalUnit: caOrganizationalUnit,
			CaCountry:            caCountry,
			CaProvince:           caProvince,
			CaLocality:           caLocality,
			CaValidityDays:       caValidityDays,
		}
	case "acme":
		acmeIssuer := &lcmV1.AcmeIssuer{
			Email:          acmeEmail,
			Endpoint:       acmeEndpoint,
			KeyType:        acmeKeyType,
			KeySize:        acmeKeySize,
			MaxRetries:     acmeMaxRetries,
			BaseDelay:      acmeBaseDelay,
			ChallengeType:  mapChallengeType(acmeChallengeType),
			ProviderName:   acmeProviderName,
			ProviderConfig: parseProviderConfig(acmeProviderConfig),
		}
		// Add EAB credentials if provided
		if acmeEabKid != "" {
			acmeIssuer.EabKid = &acmeEabKid
		}
		if acmeEabHmacKey != "" {
			acmeIssuer.EabHmacKey = &acmeEabHmacKey
		}
		req.AcmeIssuer = acmeIssuer
	}

	return req
}

func mapStatusString(status string) lcmV1.IssuerStatus {
	switch strings.ToLower(status) {
	case "active":
		return lcmV1.IssuerStatus_ISSUER_STATUS_ACTIVE
	case "disabled":
		return lcmV1.IssuerStatus_ISSUER_STATUS_DISABLED
	default:
		return lcmV1.IssuerStatus_ISSUER_STATUS_ACTIVE
	}
}

func mapChallengeType(ct string) lcmV1.ChallengeType {
	switch strings.ToUpper(ct) {
	case "DNS":
		return lcmV1.ChallengeType_DNS
	default:
		return lcmV1.ChallengeType_HTTP
	}
}

func parseProviderConfig(configs []string) map[string]string {
	result := make(map[string]string)
	for _, config := range configs {
		parts := strings.SplitN(config, "=", 2)
		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}
	return result
}
