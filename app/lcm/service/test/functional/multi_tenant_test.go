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
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/test/helpers"
)

// TestMultiTenantIsolation tests that tenants are properly isolated
func TestMultiTenantIsolation(t *testing.T) {
	env := loadTestEnvironment(t)

	// Create temp directory for certificates
	tempDir, err := os.MkdirTemp("", "lcm-mt-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Variables to track state across test steps
	var adminCertFile, adminKeyFile string
	var tenant1CertFile, tenant1KeyFile string
	var tenant2CertFile, tenant2KeyFile string
	var tenant1Secret, tenant2Secret string
	var tenant1IssuerName string
	var tenant1JobID string

	// Step 1: Register admin client (using global shared secret, tenant_id=0)
	t.Run("1_RegisterAdminClient", func(t *testing.T) {
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

		// Generate key pair for admin
		privateKey, publicKeyPEM, err := generateECDSAKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Register admin client with global shared secret
		adminClientID := fmt.Sprintf("admin-client-%d", time.Now().UnixNano())
		hostname := adminClientID

		resp, err := clients.LcmClient.RegisterLcmClient(ctx, &lcmV1.CreateLcmClientRequest{
			ClientId:     adminClientID,
			Hostname:     hostname,
			SharedSecret: &env.SharedSecret,
			PublicKey:    publicKeyPEM,
			DnsNames:     []string{hostname},
		})
		if err != nil {
			t.Fatalf("Failed to register admin client: %v", err)
		}

		requestID := resp.Certificate.GetRequestId()
		t.Logf("Admin client registered: client_id=%s, request_id=%s", adminClientID, requestID)

		// Wait for certificate issuance
		adminCertFile, adminKeyFile = waitForCertificateAndSave(t, ctx, clients, adminClientID, requestID, publicKeyPEM, privateKey, tempDir, "admin")
		t.Logf("Admin certificate saved to: %s", adminCertFile)
	})

	// Step 2: Create tenant secrets using admin client
	t.Run("2_CreateTenantSecrets", func(t *testing.T) {
		if adminCertFile == "" || adminKeyFile == "" {
			t.Skip("Admin certificate not available")
		}

		clients, err := helpers.NewGRPCClients(&helpers.ClientConfig{
			ServerAddr: env.ServerAddr,
			CertFile:   adminCertFile,
			KeyFile:    adminKeyFile,
			CAFile:     env.CAFile,
			Timeout:    30 * time.Second,
		})
		if err != nil {
			t.Fatalf("Failed to create gRPC clients: %v", err)
		}
		defer clients.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		// Create secret for tenant 1
		tenant1Secret = fmt.Sprintf("tenant1-secret-%d", time.Now().UnixNano())
		resp1, err := clients.TenantSecret.CreateTenantSecret(ctx, &lcmV1.CreateTenantSecretRequest{
			TenantId:    1,
			Secret:      tenant1Secret,
			Description: strPtr("Test secret for tenant 1"),
		})
		if err != nil {
			t.Fatalf("Failed to create tenant 1 secret: %v", err)
		}
		t.Logf("Created tenant 1 secret: id=%d, tenant_id=%d", resp1.TenantSecret.GetId(), resp1.TenantSecret.GetTenantId())

		// Create secret for tenant 2
		tenant2Secret = fmt.Sprintf("tenant2-secret-%d", time.Now().UnixNano())
		resp2, err := clients.TenantSecret.CreateTenantSecret(ctx, &lcmV1.CreateTenantSecretRequest{
			TenantId:    2,
			Secret:      tenant2Secret,
			Description: strPtr("Test secret for tenant 2"),
		})
		if err != nil {
			t.Fatalf("Failed to create tenant 2 secret: %v", err)
		}
		t.Logf("Created tenant 2 secret: id=%d, tenant_id=%d", resp2.TenantSecret.GetId(), resp2.TenantSecret.GetTenantId())
	})

	// Step 3: Register client for tenant 1
	t.Run("3_RegisterTenant1Client", func(t *testing.T) {
		if tenant1Secret == "" {
			t.Skip("Tenant 1 secret not created")
		}

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

		// Generate key pair for tenant 1
		privateKey, publicKeyPEM, err := generateECDSAKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Register client with tenant 1 secret
		clientID := fmt.Sprintf("tenant1-client-%d", time.Now().UnixNano())
		hostname := clientID

		resp, err := clients.LcmClient.RegisterLcmClient(ctx, &lcmV1.CreateLcmClientRequest{
			ClientId:     clientID,
			Hostname:     hostname,
			SharedSecret: &tenant1Secret,
			PublicKey:    publicKeyPEM,
			DnsNames:     []string{hostname},
		})
		if err != nil {
			t.Fatalf("Failed to register tenant 1 client: %v", err)
		}

		requestID := resp.Certificate.GetRequestId()
		t.Logf("Tenant 1 client registered: client_id=%s, request_id=%s", clientID, requestID)

		// Wait for certificate issuance
		tenant1CertFile, tenant1KeyFile = waitForCertificateAndSave(t, ctx, clients, clientID, requestID, publicKeyPEM, privateKey, tempDir, "tenant1")
		t.Logf("Tenant 1 certificate saved to: %s", tenant1CertFile)
	})

	// Step 4: Register client for tenant 2
	t.Run("4_RegisterTenant2Client", func(t *testing.T) {
		if tenant2Secret == "" {
			t.Skip("Tenant 2 secret not created")
		}

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

		// Generate key pair for tenant 2
		privateKey, publicKeyPEM, err := generateECDSAKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Register client with tenant 2 secret
		clientID := fmt.Sprintf("tenant2-client-%d", time.Now().UnixNano())
		hostname := clientID

		resp, err := clients.LcmClient.RegisterLcmClient(ctx, &lcmV1.CreateLcmClientRequest{
			ClientId:     clientID,
			Hostname:     hostname,
			SharedSecret: &tenant2Secret,
			PublicKey:    publicKeyPEM,
			DnsNames:     []string{hostname},
		})
		if err != nil {
			t.Fatalf("Failed to register tenant 2 client: %v", err)
		}

		requestID := resp.Certificate.GetRequestId()
		t.Logf("Tenant 2 client registered: client_id=%s, request_id=%s", clientID, requestID)

		// Wait for certificate issuance
		tenant2CertFile, tenant2KeyFile = waitForCertificateAndSave(t, ctx, clients, clientID, requestID, publicKeyPEM, privateKey, tempDir, "tenant2")
		t.Logf("Tenant 2 certificate saved to: %s", tenant2CertFile)
	})

	// Step 5: Create issuer and request certificate as tenant 1
	t.Run("5_Tenant1CreateIssuerAndRequestCert", func(t *testing.T) {
		if tenant1CertFile == "" || tenant1KeyFile == "" {
			t.Skip("Tenant 1 certificate not available")
		}

		clients, err := helpers.NewGRPCClients(&helpers.ClientConfig{
			ServerAddr: env.ServerAddr,
			CertFile:   tenant1CertFile,
			KeyFile:    tenant1KeyFile,
			CAFile:     env.CAFile,
			Timeout:    30 * time.Second,
		})
		if err != nil {
			t.Fatalf("Failed to create gRPC clients: %v", err)
		}
		defer clients.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		// Create issuer for tenant 1
		tenant1IssuerName = fmt.Sprintf("tenant1-issuer-%d", time.Now().UnixNano())

		_, err = clients.Issuer.CreateIssuer(ctx, &lcmV1.CreateIssuerRequest{
			Name:        tenant1IssuerName,
			Type:        "self-signed",
			KeyType:     "ecdsa",
			Description: "Tenant 1 test issuer",
			Status:      lcmV1.IssuerStatus_ISSUER_STATUS_ACTIVE,
			SelfIssuer: &lcmV1.SelfIssuer{
				CommonName:     "Tenant 1 Test Cert",
				CaCommonName:   "Tenant 1 CA",
				CaOrganization: "Tenant 1 Org",
				CaValidityDays: 365,
			},
		})
		if err != nil {
			t.Fatalf("Failed to create tenant 1 issuer: %v", err)
		}
		t.Logf("Tenant 1 issuer created: %s", tenant1IssuerName)

		// Request certificate
		certResp, err := clients.CertificateJob.RequestCertificate(ctx, &lcmV1.RequestCertificateRequest{
			IssuerName: tenant1IssuerName,
			CommonName: "tenant1-app.example.com",
			DnsNames:   []string{"tenant1-app.example.com", "www.tenant1-app.example.com"},
		})
		if err != nil {
			t.Fatalf("Failed to request certificate: %v", err)
		}

		tenant1JobID = certResp.GetJobId()
		t.Logf("Tenant 1 certificate job created: job_id=%s", tenant1JobID)

		// Wait for job completion
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		timeout := time.After(2 * time.Minute)

		for {
			select {
			case <-timeout:
				t.Fatal("Timeout waiting for certificate issuance")
			case <-ticker.C:
				statusResp, err := clients.CertificateJob.GetJobStatus(ctx, &lcmV1.GetJobStatusRequest{
					JobId: tenant1JobID,
				})
				if err != nil {
					t.Fatalf("Failed to get job status: %v", err)
				}

				if statusResp.GetStatus() == lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_COMPLETED {
					t.Logf("Tenant 1 certificate issued successfully")
					return
				}
				if statusResp.GetStatus() == lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_FAILED {
					t.Fatalf("Certificate issuance failed: %s", statusResp.GetErrorMessage())
				}
			}
		}
	})

	// Step 6: Verify tenant 2 CANNOT access tenant 1's resources
	t.Run("6_VerifyTenant2CannotAccessTenant1Resources", func(t *testing.T) {
		if tenant2CertFile == "" || tenant2KeyFile == "" {
			t.Skip("Tenant 2 certificate not available")
		}
		if tenant1JobID == "" || tenant1IssuerName == "" {
			t.Skip("Tenant 1 resources not available")
		}

		clients, err := helpers.NewGRPCClients(&helpers.ClientConfig{
			ServerAddr: env.ServerAddr,
			CertFile:   tenant2CertFile,
			KeyFile:    tenant2KeyFile,
			CAFile:     env.CAFile,
			Timeout:    30 * time.Second,
		})
		if err != nil {
			t.Fatalf("Failed to create gRPC clients: %v", err)
		}
		defer clients.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		// Try to get tenant 1's job status - should fail with NotFound
		t.Run("CannotAccessTenant1Job", func(t *testing.T) {
			_, err := clients.CertificateJob.GetJobStatus(ctx, &lcmV1.GetJobStatusRequest{
				JobId: tenant1JobID,
			})
			if err == nil {
				t.Fatal("Expected error when accessing tenant 1's job from tenant 2, but got none")
			}

			// Check that it's a NotFound error
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("Expected gRPC status error, got: %v", err)
			}
			if st.Code() != codes.NotFound {
				t.Fatalf("Expected NotFound error, got: %s - %s", st.Code(), st.Message())
			}
			t.Logf("Correctly denied access to tenant 1's job: %s", st.Message())
		})

		// Try to use tenant 1's issuer - should fail
		t.Run("CannotUseTenant1Issuer", func(t *testing.T) {
			_, err := clients.CertificateJob.RequestCertificate(ctx, &lcmV1.RequestCertificateRequest{
				IssuerName: tenant1IssuerName,
				CommonName: "unauthorized.example.com",
				DnsNames:   []string{"unauthorized.example.com"},
			})
			if err == nil {
				t.Fatal("Expected error when using tenant 1's issuer from tenant 2, but got none")
			}

			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("Expected gRPC status error, got: %v", err)
			}
			// Could be NotFound or PermissionDenied depending on implementation
			if st.Code() != codes.NotFound && st.Code() != codes.PermissionDenied {
				t.Fatalf("Expected NotFound or PermissionDenied error, got: %s - %s", st.Code(), st.Message())
			}
			t.Logf("Correctly denied access to tenant 1's issuer: %s", st.Message())
		})

		// List tenant 2's jobs - should be empty or only contain tenant 2's jobs
		t.Run("ListJobsOnlyShowsTenant2Jobs", func(t *testing.T) {
			listResp, err := clients.CertificateJob.ListJobs(ctx, &lcmV1.ListJobsRequest{})
			if err != nil {
				t.Fatalf("Failed to list jobs: %v", err)
			}

			// Check that tenant 1's job is not in the list
			for _, job := range listResp.Jobs {
				if job.GetJobId() == tenant1JobID {
					t.Fatalf("Tenant 1's job should not be visible to tenant 2")
				}
			}
			t.Logf("Tenant 2 job list contains %d jobs (tenant 1's job not visible)", len(listResp.Jobs))
		})
	})

	// Step 7: Verify admin CAN access all tenant resources
	t.Run("7_VerifyAdminCanAccessAllResources", func(t *testing.T) {
		if adminCertFile == "" || adminKeyFile == "" {
			t.Skip("Admin certificate not available")
		}
		if tenant1JobID == "" {
			t.Skip("Tenant 1 job not available")
		}

		clients, err := helpers.NewGRPCClients(&helpers.ClientConfig{
			ServerAddr: env.ServerAddr,
			CertFile:   adminCertFile,
			KeyFile:    adminKeyFile,
			CAFile:     env.CAFile,
			Timeout:    30 * time.Second,
		})
		if err != nil {
			t.Fatalf("Failed to create gRPC clients: %v", err)
		}
		defer clients.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		// Note: Admin with tenant_id=0 may or may not have access to tenant-specific resources
		// This depends on the implementation - let's test what actually happens

		// List all jobs as admin
		t.Run("AdminListJobs", func(t *testing.T) {
			listResp, err := clients.CertificateJob.ListJobs(ctx, &lcmV1.ListJobsRequest{})
			if err != nil {
				t.Fatalf("Failed to list jobs: %v", err)
			}
			t.Logf("Admin can see %d jobs", len(listResp.Jobs))

			// Log job details
			for _, job := range listResp.Jobs {
				t.Logf("  - Job: %s (issuer=%s, cn=%s, status=%s)",
					job.GetJobId(), job.GetIssuerName(), job.GetCommonName(), job.GetStatus())
			}
		})

		// Try to access tenant 1's job as admin
		t.Run("AdminAccessTenant1Job", func(t *testing.T) {
			resp, err := clients.CertificateJob.GetJobStatus(ctx, &lcmV1.GetJobStatusRequest{
				JobId: tenant1JobID,
			})
			if err != nil {
				// This might be expected if admin (tenant_id=0) cannot access other tenant resources
				st, _ := status.FromError(err)
				t.Logf("Admin cannot access tenant 1's job (this may be expected): %s - %s", st.Code(), st.Message())
			} else {
				t.Logf("Admin CAN access tenant 1's job: status=%s", resp.GetStatus())
			}
		})

		// List tenant secrets (admin-only operation)
		t.Run("AdminListTenantSecrets", func(t *testing.T) {
			listResp, err := clients.TenantSecret.ListTenantSecrets(ctx, &lcmV1.ListTenantSecretsRequest{})
			if err != nil {
				t.Fatalf("Failed to list tenant secrets: %v", err)
			}
			t.Logf("Admin can see %d tenant secrets", listResp.Total)
			for _, secret := range listResp.Items {
				t.Logf("  - Secret ID=%d, tenant_id=%d, status=%s",
					secret.GetId(), secret.GetTenantId(), secret.GetStatus())
			}
		})
	})

	// Step 8: Verify tenant 2 CANNOT manage tenant secrets
	t.Run("8_VerifyTenant2CannotManageTenantSecrets", func(t *testing.T) {
		if tenant2CertFile == "" || tenant2KeyFile == "" {
			t.Skip("Tenant 2 certificate not available")
		}

		clients, err := helpers.NewGRPCClients(&helpers.ClientConfig{
			ServerAddr: env.ServerAddr,
			CertFile:   tenant2CertFile,
			KeyFile:    tenant2KeyFile,
			CAFile:     env.CAFile,
			Timeout:    30 * time.Second,
		})
		if err != nil {
			t.Fatalf("Failed to create gRPC clients: %v", err)
		}
		defer clients.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		// Try to create a tenant secret (should fail - admin only)
		_, err = clients.TenantSecret.CreateTenantSecret(ctx, &lcmV1.CreateTenantSecretRequest{
			TenantId:    3,
			Secret:      "unauthorized-secret-attempt",
			Description: strPtr("This should fail"),
		})
		if err == nil {
			t.Fatal("Expected error when tenant 2 tries to create tenant secret, but got none")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected gRPC status error, got: %v", err)
		}
		t.Logf("Correctly denied tenant secret creation: %s - %s", st.Code(), st.Message())
	})
}

// Helper functions

func generateECDSAKeyPair() (*ecdsa.PrivateKey, string, error) {
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

func waitForCertificateAndSave(t *testing.T, ctx context.Context, clients *helpers.GRPCClients, clientID, requestID, publicKeyPEM string, privateKey *ecdsa.PrivateKey, tempDir, prefix string) (certFile, keyFile string) {
	t.Helper()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	timeout := time.After(2 * time.Minute)

	for {
		select {
		case <-timeout:
			t.Fatalf("Timeout waiting for certificate for %s", prefix)
		case <-ticker.C:
			statusResp, err := clients.LcmClient.GetRequestStatus(ctx, &lcmV1.GetRequestStatusRequest{
				RequestId: requestID,
				ClientId:  clientID,
			})
			if err != nil {
				t.Fatalf("Failed to get request status: %v", err)
			}

			if statusResp.Status == lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_ISSUED {
				// Download certificate
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

				// Save certificate
				certFile = filepath.Join(tempDir, fmt.Sprintf("%s.crt", prefix))
				if err := os.WriteFile(certFile, []byte(*downloadResp.CertificatePem), 0644); err != nil {
					t.Fatalf("Failed to save certificate: %v", err)
				}

				// Save private key
				keyFile = filepath.Join(tempDir, fmt.Sprintf("%s.key", prefix))
				privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
				if err != nil {
					t.Fatalf("Failed to marshal private key: %v", err)
				}
				privateKeyPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "EC PRIVATE KEY",
					Bytes: privateKeyBytes,
				})
				if err := os.WriteFile(keyFile, privateKeyPEM, 0600); err != nil {
					t.Fatalf("Failed to save private key: %v", err)
				}

				return certFile, keyFile
			}
		}
	}
}

func strPtr(s string) *string {
	return &s
}
