package functional

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/test/config"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/test/helpers"
)

// TestEnvironment holds test environment configuration
type TestEnvironment struct {
	ServerAddr   string
	CAFile       string
	SharedSecret string
	Config       *config.TestConfig
}

// getTestDataDir returns the absolute path to the testdata directory
func getTestDataDir() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "testdata"
	}
	// Go up from functional/ to test/, then into testdata/
	testDir := filepath.Dir(filepath.Dir(filename))
	return filepath.Join(testDir, "testdata")
}

// loadTestEnvironment loads test environment from config file
func loadTestEnvironment(t *testing.T) *TestEnvironment {
	t.Helper()

	// Load config file
	configPath := os.Getenv("LCM_TEST_CONFIG")
	if configPath == "" {
		configPath = filepath.Join(getTestDataDir(), "dns_config.yaml")
	}
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Resolve CA file path relative to config file location
	caFile := cfg.Server.CAFile
	if !filepath.IsAbs(caFile) {
		caFile = filepath.Join(filepath.Dir(configPath), caFile)
	}

	// Check if CA file exists
	if _, err := os.Stat(caFile); os.IsNotExist(err) {
		t.Fatalf("CA file not found: %s", caFile)
	}

	return &TestEnvironment{
		ServerAddr:   cfg.Server.Address,
		CAFile:       caFile,
		SharedSecret: cfg.Server.SharedSecret,
		Config:       cfg,
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// TestClientRegistration tests the mTLS client registration flow
func TestClientRegistration(t *testing.T) {
	env := loadTestEnvironment(t)

	// Create gRPC client without mTLS (for registration)
	clients, err := helpers.NewGRPCClients(&helpers.ClientConfig{
		ServerAddr: env.ServerAddr,
		CAFile:     env.CAFile,
		Timeout:    30 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create gRPC clients: %v", err)
	}
	defer clients.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Test health check first
	t.Run("HealthCheck", func(t *testing.T) {
		if err := clients.HealthCheck(ctx); err != nil {
			t.Fatalf("Health check failed: %v", err)
		}
		t.Log("Health check passed")
	})

	// Test client registration
	clientID := fmt.Sprintf("test-client-%d", time.Now().UnixNano())
	hostname := "test-client.local"
	var requestID string

	// Generate key pair for registration
	privateKey, publicKeyPEM, err := generateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	_ = privateKey // We'll need this later to download the certificate

	t.Run("RegisterClient", func(t *testing.T) {
		resp, err := clients.LcmClient.RegisterLcmClient(ctx, &lcmV1.CreateLcmClientRequest{
			ClientId:     clientID,
			Hostname:     hostname,
			SharedSecret: &env.SharedSecret,
			PublicKey:    publicKeyPEM,
			DnsNames:     []string{hostname},
		})
		if err != nil {
			t.Fatalf("Failed to register client: %v", err)
		}

		// Check response
		if resp.Client != nil {
			t.Logf("Client registered: id=%d, client_id=%s", resp.Client.GetId(), resp.Client.GetClientId())
		}
		if resp.Certificate != nil {
			requestID = resp.Certificate.GetRequestId()
			t.Logf("Certificate created: request_id=%s, status=%s", requestID, resp.Certificate.GetStatus())
		}
	})

	// Test get request status
	t.Run("GetRequestStatus", func(t *testing.T) {
		if requestID == "" {
			t.Skip("No request ID from registration")
		}

		// Poll for status until approved or timeout
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		timeout := time.After(2 * time.Minute)

		for {
			select {
			case <-timeout:
				t.Log("Timeout waiting for certificate approval (this is expected if auto-approval is disabled)")
				return
			case <-ticker.C:
				resp, err := clients.LcmClient.GetRequestStatus(ctx, &lcmV1.GetRequestStatusRequest{
					RequestId: requestID,
					ClientId:  clientID,
				})
				if err != nil {
					t.Fatalf("Failed to get request status: %v", err)
				}

				t.Logf("Request status: %s", resp.Status)

				// MtlsCertificateStatus: ISSUED = certificate ready
				if resp.Status == lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_ISSUED {
					t.Log("Certificate issued!")
					return
				}
				if resp.Status == lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_REVOKED {
					t.Fatal("Certificate was revoked")
				}
			}
		}
	})
}

// generateKeyPair generates an ECDSA P-256 key pair and returns private key and PEM-encoded public key
func generateKeyPair() (*ecdsa.PrivateKey, string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}))

	return privateKey, publicKeyPEM, nil
}

// TestIssuerCreation tests issuer creation flow
func TestIssuerCreation(t *testing.T) {
	env := loadTestEnvironment(t)

	// For issuer creation, we need mTLS authentication
	// This test assumes we have a registered client with certificate
	certFile := getEnvOrDefault("LCM_TEST_CLIENT_CERT", "")
	keyFile := getEnvOrDefault("LCM_TEST_CLIENT_KEY", "")

	if certFile == "" || keyFile == "" {
		t.Skip("Skipping test: LCM_TEST_CLIENT_CERT and LCM_TEST_CLIENT_KEY not set")
	}

	clients, err := helpers.NewGRPCClients(&helpers.ClientConfig{
		ServerAddr: env.ServerAddr,
		CertFile:   certFile,
		KeyFile:    keyFile,
		CAFile:     env.CAFile,
		Timeout:    30 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create gRPC clients: %v", err)
	}
	defer clients.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Test self-signed issuer creation
	t.Run("CreateSelfSignedIssuer", func(t *testing.T) {
		issuerName := fmt.Sprintf("test-self-signed-%d", time.Now().UnixNano())

		resp, err := clients.Issuer.CreateIssuer(ctx, &lcmV1.CreateIssuerRequest{
			Name:        issuerName,
			Type:        "self-signed",
			KeyType:     "ecdsa",
			Description: "Test self-signed issuer",
			Status:      lcmV1.IssuerStatus_ISSUER_STATUS_ACTIVE,
			SelfIssuer: &lcmV1.SelfIssuer{
				CommonName:     "*.test.local",
				DnsNames:       []string{"test.local", "*.test.local"},
				CaCommonName:   "Test CA",
				CaOrganization: "Test Org",
				CaValidityDays: 365,
			},
		})
		if err != nil {
			t.Fatalf("Failed to create self-signed issuer: %v", err)
		}

		t.Logf("Created self-signed issuer: %s, type=%s", resp.Issuer.Name, resp.Issuer.Type)

		// Cleanup
		defer func() {
			_, _ = clients.Issuer.DeleteIssuer(ctx, &lcmV1.DeleteIssuerRequest{Name: issuerName})
		}()
	})

	// Test ACME issuer creation
	t.Run("CreateACMEIssuer", func(t *testing.T) {
		cfg := env.Config
		issuerName := fmt.Sprintf("test-acme-%d", time.Now().UnixNano())

		req := &lcmV1.CreateIssuerRequest{
			Name:        issuerName,
			Type:        "acme",
			KeyType:     "ecdsa",
			Description: "Test ACME issuer with Let's Encrypt",
			Status:      lcmV1.IssuerStatus_ISSUER_STATUS_ACTIVE,
			AcmeIssuer: &lcmV1.AcmeIssuer{
				Email:          cfg.ACME.Email,
				Endpoint:       cfg.ACME.Endpoint,
				KeyType:        "ec",
				KeySize:        256,
				MaxRetries:     3,
				BaseDelay:      "5s",
				ChallengeType:  lcmV1.ChallengeType_DNS,
				ProviderName:   cfg.DNSProvider.Name,
				ProviderConfig: cfg.DNSProvider.Config,
			},
		}

		// Add EAB if configured
		if cfg.ACME.EabKid != "" {
			eabKid := cfg.ACME.EabKid
			req.AcmeIssuer.EabKid = &eabKid
		}
		if cfg.ACME.EabHmacKey != "" {
			eabHmacKey := cfg.ACME.EabHmacKey
			req.AcmeIssuer.EabHmacKey = &eabHmacKey
		}

		resp, err := clients.Issuer.CreateIssuer(ctx, req)
		if err != nil {
			t.Fatalf("Failed to create ACME issuer: %v", err)
		}

		t.Logf("Created ACME issuer: %s, type=%s, endpoint=%s",
			resp.Issuer.Name, resp.Issuer.Type, cfg.ACME.Endpoint)

		// Don't cleanup - we'll use this issuer for certificate tests
	})

	// Test listing issuers
	t.Run("ListIssuers", func(t *testing.T) {
		resp, err := clients.Issuer.ListIssuers(ctx, &emptypb.Empty{})
		if err != nil {
			t.Fatalf("Failed to list issuers: %v", err)
		}

		t.Logf("Found %d issuers:", len(resp.Issuers))
		for _, issuer := range resp.Issuers {
			t.Logf("  - %s (type=%s, status=%s)", issuer.Name, issuer.Type, issuer.Status)
		}
	})

	// Test listing DNS providers
	t.Run("ListDNSProviders", func(t *testing.T) {
		resp, err := clients.Issuer.ListDnsProviders(ctx, &emptypb.Empty{})
		if err != nil {
			t.Fatalf("Failed to list DNS providers: %v", err)
		}

		t.Logf("Available DNS providers (%d):", len(resp.Providers))
		for _, provider := range resp.Providers {
			t.Logf("  - %s: required=%v, optional=%v",
				provider.Name, provider.RequiredFields, provider.OptionalFields)
		}
	})
}

// TestCertificateRequestFlow tests the async certificate request flow
func TestCertificateRequestFlow(t *testing.T) {
	env := loadTestEnvironment(t)

	certFile := getEnvOrDefault("LCM_TEST_CLIENT_CERT", "")
	keyFile := getEnvOrDefault("LCM_TEST_CLIENT_KEY", "")

	if certFile == "" || keyFile == "" {
		t.Skip("Skipping test: LCM_TEST_CLIENT_CERT and LCM_TEST_CLIENT_KEY not set")
	}

	clients, err := helpers.NewGRPCClients(&helpers.ClientConfig{
		ServerAddr: env.ServerAddr,
		CertFile:   certFile,
		KeyFile:    keyFile,
		CAFile:     env.CAFile,
		Timeout:    30 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create gRPC clients: %v", err)
	}
	defer clients.Close()

	cfg := env.Config
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeouts.GetCertificateIssuanceTimeout())
	defer cancel()

	// First, ensure we have an ACME issuer
	issuerName := getEnvOrDefault("LCM_TEST_ISSUER_NAME", "")
	if issuerName == "" {
		// Create a new ACME issuer for testing
		issuerName = fmt.Sprintf("test-acme-cert-%d", time.Now().UnixNano())
		_, err := clients.Issuer.CreateIssuer(ctx, &lcmV1.CreateIssuerRequest{
			Name:        issuerName,
			Type:        "acme",
			KeyType:     "ecdsa",
			Description: "Test ACME issuer for certificate flow",
			Status:      lcmV1.IssuerStatus_ISSUER_STATUS_ACTIVE,
			AcmeIssuer: &lcmV1.AcmeIssuer{
				Email:          cfg.ACME.Email,
				Endpoint:       cfg.ACME.Endpoint,
				KeyType:        "ec",
				KeySize:        256,
				MaxRetries:     3,
				BaseDelay:      "5s",
				ChallengeType:  lcmV1.ChallengeType_DNS,
				ProviderName:   cfg.DNSProvider.Name,
				ProviderConfig: cfg.DNSProvider.Config,
			},
		})
		if err != nil {
			t.Fatalf("Failed to create ACME issuer: %v", err)
		}
		t.Logf("Created test ACME issuer: %s", issuerName)
	}

	var jobID string

	// Test requesting a certificate
	t.Run("RequestCertificate", func(t *testing.T) {
		keyType := "ecdsa"
		keySize := int32(256)
		validityDays := int32(90)

		resp, err := clients.CertificateJob.RequestCertificate(ctx, &lcmV1.RequestCertificateRequest{
			IssuerName:   issuerName,
			CommonName:   cfg.TestDomain.Domain,
			DnsNames:     cfg.TestDomain.DNSNames,
			KeyType:      &keyType,
			KeySize:      &keySize,
			ValidityDays: &validityDays,
		})
		if err != nil {
			t.Fatalf("Failed to request certificate: %v", err)
		}

		jobID = resp.JobId
		t.Logf("Certificate request submitted: job_id=%s, status=%s", jobID, resp.Status)

		if jobID == "" {
			t.Fatal("Expected job_id in response")
		}
	})

	// Test polling for job status
	t.Run("PollJobStatus", func(t *testing.T) {
		if jobID == "" {
			t.Skip("No job ID from certificate request")
		}

		ticker := time.NewTicker(cfg.Timeouts.GetPollInterval())
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				t.Fatalf("Timeout waiting for certificate issuance: %v", ctx.Err())
			case <-ticker.C:
				resp, err := clients.CertificateJob.GetJobStatus(ctx, &lcmV1.GetJobStatusRequest{
					JobId: jobID,
				})
				if err != nil {
					t.Fatalf("Failed to get job status: %v", err)
				}

				t.Logf("Job status: %s (issuer=%s, cn=%s)",
					resp.Status, resp.IssuerName, resp.CommonName)

				switch resp.Status {
				case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_COMPLETED:
					t.Log("Certificate issuance completed!")
					return
				case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_FAILED:
					t.Fatalf("Certificate issuance failed: %s", resp.GetErrorMessage())
				case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PROCESSING:
					t.Log("Certificate issuance in progress...")
				}
			}
		}
	})

	// Test getting the certificate result
	t.Run("GetJobResult", func(t *testing.T) {
		if jobID == "" {
			t.Skip("No job ID from certificate request")
		}

		includePrivateKey := true
		resp, err := clients.CertificateJob.GetJobResult(ctx, &lcmV1.GetJobResultRequest{
			JobId:             jobID,
			IncludePrivateKey: &includePrivateKey,
		})
		if err != nil {
			t.Fatalf("Failed to get job result: %v", err)
		}

		if resp.Status != lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_COMPLETED {
			t.Fatalf("Expected completed status, got %s", resp.Status)
		}

		// Validate certificate
		if resp.CertificatePem == nil || *resp.CertificatePem == "" {
			t.Fatal("Expected certificate PEM in response")
		}

		cert, err := parseCertificatePEM(*resp.CertificatePem)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}

		t.Logf("Certificate issued successfully:")
		t.Logf("  Serial: %s", resp.GetSerialNumber())
		t.Logf("  Subject: %s", cert.Subject.CommonName)
		t.Logf("  DNS Names: %v", cert.DNSNames)
		t.Logf("  Not Before: %s", cert.NotBefore)
		t.Logf("  Not After: %s", cert.NotAfter)
		t.Logf("  Issuer: %s", cert.Issuer.CommonName)

		// Save certificate to file for inspection
		if outputDir := os.Getenv("LCM_TEST_OUTPUT_DIR"); outputDir != "" {
			certPath := filepath.Join(outputDir, fmt.Sprintf("cert-%s.pem", jobID))
			if err := os.WriteFile(certPath, []byte(*resp.CertificatePem), 0644); err != nil {
				t.Logf("Warning: failed to save certificate: %v", err)
			} else {
				t.Logf("Certificate saved to: %s", certPath)
			}

			if resp.PrivateKeyPem != nil && *resp.PrivateKeyPem != "" {
				keyPath := filepath.Join(outputDir, fmt.Sprintf("key-%s.pem", jobID))
				if err := os.WriteFile(keyPath, []byte(*resp.PrivateKeyPem), 0600); err != nil {
					t.Logf("Warning: failed to save private key: %v", err)
				} else {
					t.Logf("Private key saved to: %s", keyPath)
				}
			}
		}
	})

	// Test listing jobs
	t.Run("ListJobs", func(t *testing.T) {
		resp, err := clients.CertificateJob.ListJobs(ctx, &lcmV1.ListJobsRequest{})
		if err != nil {
			t.Fatalf("Failed to list jobs: %v", err)
		}

		t.Logf("Found %d jobs:", resp.Total)
		for _, job := range resp.Jobs {
			t.Logf("  - %s: status=%s, issuer=%s, cn=%s",
				job.JobId, job.Status, job.IssuerName, job.CommonName)
		}
	})
}

// TestEndToEndFlow tests the complete end-to-end certificate lifecycle
func TestEndToEndFlow(t *testing.T) {
	env := loadTestEnvironment(t)

	// Create temp directory for certificates
	tempDir, err := os.MkdirTemp("", "lcm-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	var clientCertFile, clientKeyFile string
	var clientID string
	var createdIssuerName string

	// Step 1: Client Registration
	t.Run("1_ClientRegistration", func(t *testing.T) {
		clients, err := helpers.NewGRPCClients(&helpers.ClientConfig{
			ServerAddr: env.ServerAddr,
			CAFile:     env.CAFile,
			Timeout:    30 * time.Second,
		})
		if err != nil {
			t.Fatalf("Failed to create gRPC clients: %v", err)
		}
		defer clients.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		// Health check
		if err := clients.HealthCheck(ctx); err != nil {
			t.Fatalf("Health check failed: %v", err)
		}
		t.Log("Health check passed")

		// Generate key pair
		privateKey, publicKeyPEM, err := generateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Register client
		// Note: The certificate CN is set to hostname, and the server looks up clients by CN
		// So we use the same value for both client_id and hostname
		clientID = fmt.Sprintf("e2e-client-%d", time.Now().UnixNano())
		hostname := clientID // Must match client_id since server looks up by certificate CN

		resp, err := clients.LcmClient.RegisterLcmClient(ctx, &lcmV1.CreateLcmClientRequest{
			ClientId:     clientID,
			Hostname:     hostname,
			SharedSecret: &env.SharedSecret,
			PublicKey:    publicKeyPEM,
			DnsNames:     []string{hostname},
		})
		if err != nil {
			t.Fatalf("Failed to register client: %v", err)
		}

		requestID := resp.Certificate.GetRequestId()
		t.Logf("Client registered: client_id=%s, request_id=%s", clientID, requestID)

		// Wait for certificate to be issued
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		timeout := time.After(2 * time.Minute)

		for {
			select {
			case <-timeout:
				t.Fatal("Timeout waiting for certificate")
			case <-ticker.C:
				statusResp, err := clients.LcmClient.GetRequestStatus(ctx, &lcmV1.GetRequestStatusRequest{
					RequestId: requestID,
					ClientId:  clientID,
				})
				if err != nil {
					t.Fatalf("Failed to get request status: %v", err)
				}

				if statusResp.Status == lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_ISSUED {
					t.Log("Certificate issued!")

					// Download the certificate (must include public key for verification)
					downloadResp, err := clients.LcmClient.DownloadClientCertificate(ctx, &lcmV1.DownloadClientCertificateRequest{
						RequestId: requestID,
						ClientId:  clientID,
						PublicKey: publicKeyPEM,
					})
					if err != nil {
						t.Fatalf("Failed to download certificate: %v", err)
					}

					if downloadResp.CertificatePem == nil || *downloadResp.CertificatePem == "" {
						t.Fatal("Downloaded certificate is empty")
					}

					// Save certificate to temp file
					clientCertFile = filepath.Join(tempDir, "client.crt")
					if err := os.WriteFile(clientCertFile, []byte(*downloadResp.CertificatePem), 0644); err != nil {
						t.Fatalf("Failed to save certificate: %v", err)
					}

					// Save private key to temp file
					clientKeyFile = filepath.Join(tempDir, "client.key")
					privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
					if err != nil {
						t.Fatalf("Failed to marshal private key: %v", err)
					}
					privateKeyPEM := pem.EncodeToMemory(&pem.Block{
						Type:  "EC PRIVATE KEY",
						Bytes: privateKeyBytes,
					})
					if err := os.WriteFile(clientKeyFile, privateKeyPEM, 0600); err != nil {
						t.Fatalf("Failed to save private key: %v", err)
					}

					t.Logf("Certificate saved to: %s", clientCertFile)
					t.Logf("Private key saved to: %s", clientKeyFile)
					return
				}
			}
		}
	})

	// Step 2: Issuer Creation (using the mTLS certificate from step 1)
	t.Run("2_IssuerCreation", func(t *testing.T) {
		if clientCertFile == "" || clientKeyFile == "" {
			t.Skip("No client certificate from registration step")
		}

		clients, err := helpers.NewGRPCClients(&helpers.ClientConfig{
			ServerAddr: env.ServerAddr,
			CertFile:   clientCertFile,
			KeyFile:    clientKeyFile,
			CAFile:     env.CAFile,
			Timeout:    30 * time.Second,
		})
		if err != nil {
			t.Fatalf("Failed to create gRPC clients with mTLS: %v", err)
		}
		defer clients.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		// Create self-signed issuer
		createdIssuerName = fmt.Sprintf("e2e-issuer-%d", time.Now().UnixNano())

		resp, err := clients.Issuer.CreateIssuer(ctx, &lcmV1.CreateIssuerRequest{
			Name:        createdIssuerName,
			Type:        "self-signed",
			KeyType:     "ecdsa",
			Description: "E2E test self-signed issuer",
			Status:      lcmV1.IssuerStatus_ISSUER_STATUS_ACTIVE,
			SelfIssuer: &lcmV1.SelfIssuer{
				CommonName:           "E2E Test Issuer",
				CaCommonName:         "E2E Test CA",
				CaOrganization:       "E2E Test Org",
				CaOrganizationalUnit: "E2E Test Unit",
				CaCountry:            "US",
				CaValidityDays:       365,
			},
		})
		if err != nil {
			t.Fatalf("Failed to create issuer: %v", err)
		}

		t.Logf("Issuer created: name=%s, type=%s", resp.Issuer.GetName(), resp.Issuer.GetType())

		// List issuers
		listResp, err := clients.Issuer.ListIssuers(ctx, &emptypb.Empty{})
		if err != nil {
			t.Fatalf("Failed to list issuers: %v", err)
		}

		t.Logf("Found %d issuers", len(listResp.Issuers))
		for _, issuer := range listResp.Issuers {
			t.Logf("  - %s: type=%s", issuer.GetName(), issuer.GetType())
		}
	})

	// Step 3: Certificate Request Flow
	t.Run("3_CertificateRequestFlow", func(t *testing.T) {
		if clientCertFile == "" || clientKeyFile == "" {
			t.Skip("No client certificate from registration step")
		}
		if createdIssuerName == "" {
			t.Skip("No issuer from issuer creation step")
		}

		clients, err := helpers.NewGRPCClients(&helpers.ClientConfig{
			ServerAddr: env.ServerAddr,
			CertFile:   clientCertFile,
			KeyFile:    clientKeyFile,
			CAFile:     env.CAFile,
			Timeout:    30 * time.Second,
		})
		if err != nil {
			t.Fatalf("Failed to create gRPC clients with mTLS: %v", err)
		}
		defer clients.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		t.Logf("Using issuer: %s", createdIssuerName)

		// Request certificate
		certResp, err := clients.CertificateJob.RequestCertificate(ctx, &lcmV1.RequestCertificateRequest{
			IssuerName: createdIssuerName,
			CommonName: "e2e-test.example.com",
			DnsNames:   []string{"e2e-test.example.com", "www.e2e-test.example.com"},
		})
		if err != nil {
			t.Fatalf("Failed to request certificate: %v", err)
		}

		jobID := certResp.GetJobId()
		t.Logf("Certificate job created: job_id=%s, status=%s", jobID, certResp.GetStatus())

		// Poll for job completion
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		timeout := time.After(10 * time.Minute)

		for {
			select {
			case <-timeout:
				t.Fatal("Timeout waiting for certificate issuance")
			case <-ticker.C:
				statusResp, err := clients.CertificateJob.GetJobStatus(ctx, &lcmV1.GetJobStatusRequest{
					JobId: jobID,
				})
				if err != nil {
					t.Fatalf("Failed to get job status: %v", err)
				}

				t.Logf("Job status: %s", statusResp.GetStatus())

				switch statusResp.GetStatus() {
				case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_COMPLETED:
					t.Log("Certificate issuance completed!")

					// Get the result
					includeKey := true
					resultResp, err := clients.CertificateJob.GetJobResult(ctx, &lcmV1.GetJobResultRequest{
						JobId:             jobID,
						IncludePrivateKey: &includeKey,
					})
					if err != nil {
						t.Fatalf("Failed to get job result: %v", err)
					}

					t.Logf("Certificate issued: serial=%s", resultResp.GetSerialNumber())
					if resultResp.CertificatePem != nil {
						cert, err := parseCertificatePEM(*resultResp.CertificatePem)
						if err == nil {
							t.Logf("  Subject: %s", cert.Subject.CommonName)
							t.Logf("  DNS Names: %v", cert.DNSNames)
							t.Logf("  Issuer: %s", cert.Issuer.CommonName)
						}
					}
					return

				case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_FAILED:
					t.Fatalf("Certificate issuance failed: %s", statusResp.GetErrorMessage())
				}
			}
		}
	})

	// Step 4: ACME Certificate Request Flow (optional - only if DNS config is complete)
	t.Run("4_ACMECertificateFlow", func(t *testing.T) {
		if clientCertFile == "" || clientKeyFile == "" {
			t.Skip("No client certificate from registration step")
		}

		// Check if ACME config is available
		if env.Config.ACME.Endpoint == "" || env.Config.ACME.Email == "" {
			t.Skip("ACME configuration not set")
		}
		if env.Config.DNSProvider.Name == "" || len(env.Config.DNSProvider.Config) == 0 {
			t.Skip("DNS provider configuration not set")
		}
		if env.Config.TestDomain.Domain == "" || len(env.Config.TestDomain.DNSNames) == 0 {
			t.Skip("Test domain configuration not set")
		}

		clients, err := helpers.NewGRPCClients(&helpers.ClientConfig{
			ServerAddr: env.ServerAddr,
			CertFile:   clientCertFile,
			KeyFile:    clientKeyFile,
			CAFile:     env.CAFile,
			Timeout:    30 * time.Second,
		})
		if err != nil {
			t.Fatalf("Failed to create gRPC clients with mTLS: %v", err)
		}
		defer clients.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()

		// Create ACME issuer
		acmeIssuerName := fmt.Sprintf("e2e-acme-issuer-%d", time.Now().UnixNano())

		acmeReq := &lcmV1.CreateIssuerRequest{
			Name:        acmeIssuerName,
			Type:        "acme",
			KeyType:     "ecdsa",
			Description: "E2E test ACME issuer",
			Status:      lcmV1.IssuerStatus_ISSUER_STATUS_ACTIVE,
			AcmeIssuer: &lcmV1.AcmeIssuer{
				Email:          env.Config.ACME.Email,
				Endpoint:       env.Config.ACME.Endpoint,
				KeyType:        "ec",
				KeySize:        256,
				MaxRetries:     3,
				BaseDelay:      "5s",
				ChallengeType:  lcmV1.ChallengeType_DNS,
				ProviderName:   env.Config.DNSProvider.Name,
				ProviderConfig: env.Config.DNSProvider.Config,
			},
		}

		// Add EAB if configured
		if env.Config.ACME.EabKid != "" {
			eabKid := env.Config.ACME.EabKid
			acmeReq.AcmeIssuer.EabKid = &eabKid
		}
		if env.Config.ACME.EabHmacKey != "" {
			eabHmacKey := env.Config.ACME.EabHmacKey
			acmeReq.AcmeIssuer.EabHmacKey = &eabHmacKey
		}

		createResp, err := clients.Issuer.CreateIssuer(ctx, acmeReq)
		if err != nil {
			t.Fatalf("Failed to create ACME issuer: %v", err)
		}

		t.Logf("ACME issuer created: name=%s, type=%s, endpoint=%s",
			createResp.Issuer.GetName(), createResp.Issuer.GetType(), env.Config.ACME.Endpoint)

		// Request certificate using ACME
		t.Logf("Requesting ACME certificate for: %v", env.Config.TestDomain.DNSNames)

		certResp, err := clients.CertificateJob.RequestCertificate(ctx, &lcmV1.RequestCertificateRequest{
			IssuerName: acmeIssuerName,
			CommonName: env.Config.TestDomain.Domain,
			DnsNames:   env.Config.TestDomain.DNSNames,
		})
		if err != nil {
			t.Fatalf("Failed to request ACME certificate: %v", err)
		}

		jobID := certResp.GetJobId()
		t.Logf("ACME certificate job created: job_id=%s, status=%s", jobID, certResp.GetStatus())

		// Poll for job completion (ACME takes longer due to DNS propagation)
		ticker := time.NewTicker(env.Config.Timeouts.GetPollInterval())
		defer ticker.Stop()
		timeout := time.After(env.Config.Timeouts.GetCertificateIssuanceTimeout())

		for {
			select {
			case <-timeout:
				t.Fatal("Timeout waiting for ACME certificate issuance")
			case <-ticker.C:
				statusResp, err := clients.CertificateJob.GetJobStatus(ctx, &lcmV1.GetJobStatusRequest{
					JobId: jobID,
				})
				if err != nil {
					t.Fatalf("Failed to get job status: %v", err)
				}

				t.Logf("ACME job status: %s", statusResp.GetStatus())

				switch statusResp.GetStatus() {
				case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_COMPLETED:
					t.Log("ACME certificate issuance completed!")

					// Get the result
					includeKey := true
					resultResp, err := clients.CertificateJob.GetJobResult(ctx, &lcmV1.GetJobResultRequest{
						JobId:             jobID,
						IncludePrivateKey: &includeKey,
					})
					if err != nil {
						t.Fatalf("Failed to get job result: %v", err)
					}

					t.Logf("ACME Certificate issued: serial=%s", resultResp.GetSerialNumber())
					if resultResp.CertificatePem != nil {
						cert, err := parseCertificatePEM(*resultResp.CertificatePem)
						if err == nil {
							t.Logf("  Subject: %s", cert.Subject.CommonName)
							t.Logf("  DNS Names: %v", cert.DNSNames)
							t.Logf("  Issuer: %s", cert.Issuer.CommonName)
							t.Logf("  Valid until: %s", cert.NotAfter)
						}
					}
					return

				case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_FAILED:
					t.Fatalf("ACME certificate issuance failed: %s", statusResp.GetErrorMessage())
				}
			}
		}
	})
}

// Helper functions

func parseCertificatePEM(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}
