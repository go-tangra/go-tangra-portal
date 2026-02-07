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
	"google.golang.org/protobuf/types/known/timestamppb"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/test/helpers"
)

// TestAuditLogBasicFunctionality tests basic audit log operations
func TestAuditLogBasicFunctionality(t *testing.T) {
	env := loadTestEnvironment(t)

	// Create temp directory for certificates
	tempDir, err := os.MkdirTemp("", "lcm-audit-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Variables to track state across test steps
	var adminCertFile, adminKeyFile string
	var tenant1CertFile, tenant1KeyFile string
	var tenant1Secret string

	// Step 1: Register admin client
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

		privateKey, publicKeyPEM, err := generateTestKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		adminClientID := fmt.Sprintf("audit-admin-%d", time.Now().UnixNano())
		resp, err := clients.LcmClient.RegisterLcmClient(ctx, &lcmV1.CreateLcmClientRequest{
			ClientId:     adminClientID,
			Hostname:     adminClientID,
			SharedSecret: &env.SharedSecret,
			PublicKey:    publicKeyPEM,
			DnsNames:     []string{adminClientID},
		})
		if err != nil {
			t.Fatalf("Failed to register admin client: %v", err)
		}

		requestID := resp.Certificate.GetRequestId()
		t.Logf("Admin client registered: client_id=%s, request_id=%s", adminClientID, requestID)

		adminCertFile, adminKeyFile = waitForCertAndSave(t, ctx, clients, adminClientID, requestID, publicKeyPEM, privateKey, tempDir, "audit-admin")
	})

	// Step 2: Create tenant secret and register tenant client
	t.Run("2_SetupTenant1", func(t *testing.T) {
		if adminCertFile == "" {
			t.Skip("Admin certificate not available")
		}

		// Create tenant secret using admin
		adminClients, err := helpers.NewGRPCClients(&helpers.ClientConfig{
			ServerAddr: env.ServerAddr,
			CertFile:   adminCertFile,
			KeyFile:    adminKeyFile,
			CAFile:     env.CAFile,
			Timeout:    30 * time.Second,
		})
		if err != nil {
			t.Fatalf("Failed to create admin gRPC clients: %v", err)
		}
		defer adminClients.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		tenant1Secret = fmt.Sprintf("audit-tenant1-secret-%d", time.Now().UnixNano())
		_, err = adminClients.TenantSecret.CreateTenantSecret(ctx, &lcmV1.CreateTenantSecretRequest{
			TenantId:    100, // Use a unique tenant ID
			Secret:      tenant1Secret,
			Description: strPtr("Audit test tenant 1"),
		})
		if err != nil {
			t.Fatalf("Failed to create tenant secret: %v", err)
		}
		t.Log("Tenant 1 secret created")

		// Register tenant 1 client
		publicClients, err := helpers.NewGRPCClients(&helpers.ClientConfig{
			ServerAddr: env.ServerAddr,
			CAFile:     env.CAFile,
			Timeout:    30 * time.Second,
		})
		if err != nil {
			t.Fatalf("Failed to create public gRPC clients: %v", err)
		}
		defer publicClients.Close()

		privateKey, publicKeyPEM, err := generateTestKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		tenant1ClientID := fmt.Sprintf("audit-tenant1-%d", time.Now().UnixNano())
		resp, err := publicClients.LcmClient.RegisterLcmClient(ctx, &lcmV1.CreateLcmClientRequest{
			ClientId:     tenant1ClientID,
			Hostname:     tenant1ClientID,
			SharedSecret: &tenant1Secret,
			PublicKey:    publicKeyPEM,
			DnsNames:     []string{tenant1ClientID},
		})
		if err != nil {
			t.Fatalf("Failed to register tenant 1 client: %v", err)
		}

		requestID := resp.Certificate.GetRequestId()
		tenant1CertFile, tenant1KeyFile = waitForCertAndSave(t, ctx, publicClients, tenant1ClientID, requestID, publicKeyPEM, privateKey, tempDir, "audit-tenant1")
		t.Logf("Tenant 1 client registered with cert: %s", tenant1CertFile)
	})

	// Step 3: Generate some audit logs by performing operations
	t.Run("3_GenerateAuditLogs", func(t *testing.T) {
		if tenant1CertFile == "" {
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

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		// Perform several operations to generate audit logs
		// 1. List issuers (should succeed even if empty)
		_, err = clients.Issuer.ListIssuers(ctx, nil)
		if err != nil {
			t.Logf("ListIssuers returned error (might be expected): %v", err)
		}

		// 2. Create an issuer
		issuerName := fmt.Sprintf("audit-test-issuer-%d", time.Now().UnixNano())
		_, err = clients.Issuer.CreateIssuer(ctx, &lcmV1.CreateIssuerRequest{
			Name:        issuerName,
			Type:        "self-signed",
			KeyType:     "ecdsa",
			Description: "Issuer for audit log testing",
			Status:      lcmV1.IssuerStatus_ISSUER_STATUS_ACTIVE,
			SelfIssuer: &lcmV1.SelfIssuer{
				CommonName:     "Audit Test Cert",
				CaCommonName:   "Audit Test CA",
				CaOrganization: "Test Org",
				CaValidityDays: 30,
			},
		})
		if err != nil {
			t.Fatalf("Failed to create issuer: %v", err)
		}
		t.Logf("Created issuer: %s", issuerName)

		// 3. Request a certificate
		certResp, err := clients.CertificateJob.RequestCertificate(ctx, &lcmV1.RequestCertificateRequest{
			IssuerName: issuerName,
			CommonName: "audit-test.example.com",
			DnsNames:   []string{"audit-test.example.com"},
		})
		if err != nil {
			t.Fatalf("Failed to request certificate: %v", err)
		}
		t.Logf("Certificate job created: %s", certResp.GetJobId())

		// 4. List jobs
		_, err = clients.CertificateJob.ListJobs(ctx, &lcmV1.ListJobsRequest{})
		if err != nil {
			t.Fatalf("Failed to list jobs: %v", err)
		}

		// Wait a moment for audit logs to be written
		time.Sleep(2 * time.Second)
		t.Log("Generated multiple operations for audit logging")
	})

	// Step 4: Test listing audit logs as tenant 1
	t.Run("4_ListAuditLogsAsTenant1", func(t *testing.T) {
		if tenant1CertFile == "" {
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

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		// List all audit logs
		listResp, err := clients.AuditLog.ListAuditLogs(ctx, &lcmV1.ListAuditLogsRequest{})
		if err != nil {
			t.Fatalf("Failed to list audit logs: %v", err)
		}

		t.Logf("Found %d audit logs (total: %d)", len(listResp.Items), listResp.Total)
		if listResp.Total == 0 {
			t.Fatal("Expected at least some audit logs")
		}

		// Verify audit log structure
		for i, log := range listResp.Items {
			if i >= 5 {
				break // Only show first 5
			}
			t.Logf("  Log %d: id=%d, audit_id=%s, operation=%s, success=%v, latency=%dms",
				i+1, log.GetId(), log.GetAuditId(), log.GetOperation(), log.GetSuccess(), log.GetLatencyMs())

			// Verify required fields are present
			if log.GetAuditId() == "" {
				t.Error("Audit log missing audit_id")
			}
			if log.GetOperation() == "" {
				t.Error("Audit log missing operation")
			}
		}
	})

	// Step 5: Test filtering audit logs by operation
	t.Run("5_FilterAuditLogsByOperation", func(t *testing.T) {
		if tenant1CertFile == "" {
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

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		// Filter by operation containing "Issuer"
		operation := "Issuer"
		listResp, err := clients.AuditLog.ListAuditLogs(ctx, &lcmV1.ListAuditLogsRequest{
			Operation: &operation,
		})
		if err != nil {
			t.Fatalf("Failed to filter audit logs: %v", err)
		}

		t.Logf("Found %d audit logs for operations containing 'Issuer'", len(listResp.Items))
		for _, log := range listResp.Items {
			if log.GetOperation() != "" {
				t.Logf("  - %s (success=%v)", log.GetOperation(), log.GetSuccess())
			}
		}
	})

	// Step 6: Test filtering by success status
	t.Run("6_FilterAuditLogsBySuccess", func(t *testing.T) {
		if tenant1CertFile == "" {
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

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		// Filter successful operations
		success := true
		listResp, err := clients.AuditLog.ListAuditLogs(ctx, &lcmV1.ListAuditLogsRequest{
			Success: &success,
		})
		if err != nil {
			t.Fatalf("Failed to filter successful audit logs: %v", err)
		}
		t.Logf("Found %d successful audit logs", listResp.Total)

		// Filter failed operations
		success = false
		failedResp, err := clients.AuditLog.ListAuditLogs(ctx, &lcmV1.ListAuditLogsRequest{
			Success: &success,
		})
		if err != nil {
			t.Fatalf("Failed to filter failed audit logs: %v", err)
		}
		t.Logf("Found %d failed audit logs", failedResp.Total)
	})

	// Step 7: Test pagination
	t.Run("7_TestPagination", func(t *testing.T) {
		if tenant1CertFile == "" {
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

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		// Get page 1 with small page size
		pageSize := uint32(2)
		page := uint32(1)
		page1Resp, err := clients.AuditLog.ListAuditLogs(ctx, &lcmV1.ListAuditLogsRequest{
			PageSize: &pageSize,
			Page:     &page,
		})
		if err != nil {
			t.Fatalf("Failed to get page 1: %v", err)
		}
		t.Logf("Page 1: %d items (total: %d)", len(page1Resp.Items), page1Resp.Total)

		if page1Resp.Total > 2 {
			// Get page 2
			page = 2
			page2Resp, err := clients.AuditLog.ListAuditLogs(ctx, &lcmV1.ListAuditLogsRequest{
				PageSize: &pageSize,
				Page:     &page,
			})
			if err != nil {
				t.Fatalf("Failed to get page 2: %v", err)
			}
			t.Logf("Page 2: %d items", len(page2Resp.Items))

			// Verify different items on different pages
			if len(page1Resp.Items) > 0 && len(page2Resp.Items) > 0 {
				if page1Resp.Items[0].GetAuditId() == page2Resp.Items[0].GetAuditId() {
					t.Error("Page 1 and Page 2 have same first item - pagination may not be working")
				}
			}
		}
	})

	// Step 8: Test getting single audit log by ID
	t.Run("8_GetAuditLogByID", func(t *testing.T) {
		if tenant1CertFile == "" {
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

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		// First get a list to find an ID
		listResp, err := clients.AuditLog.ListAuditLogs(ctx, &lcmV1.ListAuditLogsRequest{})
		if err != nil {
			t.Fatalf("Failed to list audit logs: %v", err)
		}
		if len(listResp.Items) == 0 {
			t.Skip("No audit logs to test GetByID")
		}

		// Get by database ID
		targetID := listResp.Items[0].GetId()
		getResp, err := clients.AuditLog.GetAuditLog(ctx, &lcmV1.GetAuditLogRequest{
			Id: targetID,
		})
		if err != nil {
			t.Fatalf("Failed to get audit log by ID %d: %v", targetID, err)
		}

		if getResp.AuditLog.GetId() != targetID {
			t.Errorf("Expected ID %d, got %d", targetID, getResp.AuditLog.GetId())
		}
		t.Logf("Successfully retrieved audit log by ID: %d", targetID)

		// Get by audit ID (UUID)
		targetAuditID := listResp.Items[0].GetAuditId()
		getByAuditIDResp, err := clients.AuditLog.GetAuditLogByAuditId(ctx, &lcmV1.GetAuditLogByAuditIdRequest{
			AuditId: targetAuditID,
		})
		if err != nil {
			t.Fatalf("Failed to get audit log by audit_id %s: %v", targetAuditID, err)
		}

		if getByAuditIDResp.AuditLog.GetAuditId() != targetAuditID {
			t.Errorf("Expected audit_id %s, got %s", targetAuditID, getByAuditIDResp.AuditLog.GetAuditId())
		}
		t.Logf("Successfully retrieved audit log by audit_id: %s", targetAuditID)
	})

	// Step 9: Test audit statistics
	t.Run("9_GetAuditStats", func(t *testing.T) {
		if tenant1CertFile == "" {
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

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		statsResp, err := clients.AuditLog.GetAuditStats(ctx, &lcmV1.GetAuditStatsRequest{})
		if err != nil {
			t.Fatalf("Failed to get audit stats: %v", err)
		}

		t.Logf("Audit Statistics:")
		t.Logf("  Total Operations: %d", statsResp.TotalOperations)
		t.Logf("  Successful: %d", statsResp.SuccessfulOperations)
		t.Logf("  Failed: %d", statsResp.FailedOperations)
		t.Logf("  Avg Latency: %.2f ms", statsResp.AvgLatencyMs)
		t.Logf("  Unique Clients: %d", statsResp.UniqueClients)
		t.Logf("  Operations by Type:")
		for op, count := range statsResp.OperationsByType {
			t.Logf("    - %s: %d", op, count)
		}

		// Verify stats make sense
		if statsResp.SuccessfulOperations+statsResp.FailedOperations != statsResp.TotalOperations {
			t.Errorf("Stats don't add up: %d + %d != %d",
				statsResp.SuccessfulOperations, statsResp.FailedOperations, statsResp.TotalOperations)
		}
	})

	// Step 10: Test time-based filtering
	t.Run("10_FilterByTimeRange", func(t *testing.T) {
		if tenant1CertFile == "" {
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

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		// Filter logs from the last hour
		startTime := timestamppb.New(time.Now().Add(-1 * time.Hour))
		endTime := timestamppb.New(time.Now().Add(1 * time.Minute))

		listResp, err := clients.AuditLog.ListAuditLogs(ctx, &lcmV1.ListAuditLogsRequest{
			StartTime: startTime,
			EndTime:   endTime,
		})
		if err != nil {
			t.Fatalf("Failed to filter by time range: %v", err)
		}

		t.Logf("Found %d audit logs in the last hour", listResp.Total)

		// Filter with a future time range (should return 0)
		futureStart := timestamppb.New(time.Now().Add(24 * time.Hour))
		futureEnd := timestamppb.New(time.Now().Add(25 * time.Hour))

		futureResp, err := clients.AuditLog.ListAuditLogs(ctx, &lcmV1.ListAuditLogsRequest{
			StartTime: futureStart,
			EndTime:   futureEnd,
		})
		if err != nil {
			t.Fatalf("Failed to filter by future time range: %v", err)
		}

		if futureResp.Total != 0 {
			t.Errorf("Expected 0 logs for future time range, got %d", futureResp.Total)
		}
		t.Log("Time-based filtering works correctly")
	})
}

// TestAuditLogTenantIsolation tests that tenants can only see their own audit logs
func TestAuditLogTenantIsolation(t *testing.T) {
	env := loadTestEnvironment(t)

	tempDir, err := os.MkdirTemp("", "lcm-audit-isolation-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	var adminCertFile, adminKeyFile string
	var tenant1CertFile, tenant1KeyFile string
	var tenant2CertFile, tenant2KeyFile string
	var tenant1AuditLogID uint32

	// Step 1: Setup admin and two tenants
	t.Run("1_SetupAdminAndTenants", func(t *testing.T) {
		clients, err := helpers.NewGRPCClients(&helpers.ClientConfig{
			ServerAddr: env.ServerAddr,
			CAFile:     env.CAFile,
			Timeout:    30 * time.Second,
		})
		if err != nil {
			t.Fatalf("Failed to create gRPC clients: %v", err)
		}
		defer clients.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		// Register admin
		privateKey, publicKeyPEM, _ := generateTestKeyPair()
		adminClientID := fmt.Sprintf("iso-admin-%d", time.Now().UnixNano())
		resp, err := clients.LcmClient.RegisterLcmClient(ctx, &lcmV1.CreateLcmClientRequest{
			ClientId:     adminClientID,
			Hostname:     adminClientID,
			SharedSecret: &env.SharedSecret,
			PublicKey:    publicKeyPEM,
			DnsNames:     []string{adminClientID},
		})
		if err != nil {
			t.Fatalf("Failed to register admin: %v", err)
		}
		adminCertFile, adminKeyFile = waitForCertAndSave(t, ctx, clients, adminClientID, resp.Certificate.GetRequestId(), publicKeyPEM, privateKey, tempDir, "iso-admin")

		// Create admin client with mTLS
		adminClients, err := helpers.NewGRPCClients(&helpers.ClientConfig{
			ServerAddr: env.ServerAddr,
			CertFile:   adminCertFile,
			KeyFile:    adminKeyFile,
			CAFile:     env.CAFile,
			Timeout:    30 * time.Second,
		})
		if err != nil {
			t.Fatalf("Failed to create admin clients: %v", err)
		}
		defer adminClients.Close()

		// Create tenant secrets
		tenant1Secret := fmt.Sprintf("iso-t1-secret-%d", time.Now().UnixNano())
		_, err = adminClients.TenantSecret.CreateTenantSecret(ctx, &lcmV1.CreateTenantSecretRequest{
			TenantId: 201,
			Secret:   tenant1Secret,
		})
		if err != nil {
			t.Fatalf("Failed to create tenant 1 secret: %v", err)
		}

		tenant2Secret := fmt.Sprintf("iso-t2-secret-%d", time.Now().UnixNano())
		_, err = adminClients.TenantSecret.CreateTenantSecret(ctx, &lcmV1.CreateTenantSecretRequest{
			TenantId: 202,
			Secret:   tenant2Secret,
		})
		if err != nil {
			t.Fatalf("Failed to create tenant 2 secret: %v", err)
		}

		// Register tenant 1 client
		privateKey1, publicKeyPEM1, _ := generateTestKeyPair()
		t1ClientID := fmt.Sprintf("iso-t1-client-%d", time.Now().UnixNano())
		resp1, err := clients.LcmClient.RegisterLcmClient(ctx, &lcmV1.CreateLcmClientRequest{
			ClientId:     t1ClientID,
			Hostname:     t1ClientID,
			SharedSecret: &tenant1Secret,
			PublicKey:    publicKeyPEM1,
			DnsNames:     []string{t1ClientID},
		})
		if err != nil {
			t.Fatalf("Failed to register tenant 1 client: %v", err)
		}
		tenant1CertFile, tenant1KeyFile = waitForCertAndSave(t, ctx, clients, t1ClientID, resp1.Certificate.GetRequestId(), publicKeyPEM1, privateKey1, tempDir, "iso-t1")

		// Register tenant 2 client
		privateKey2, publicKeyPEM2, _ := generateTestKeyPair()
		t2ClientID := fmt.Sprintf("iso-t2-client-%d", time.Now().UnixNano())
		resp2, err := clients.LcmClient.RegisterLcmClient(ctx, &lcmV1.CreateLcmClientRequest{
			ClientId:     t2ClientID,
			Hostname:     t2ClientID,
			SharedSecret: &tenant2Secret,
			PublicKey:    publicKeyPEM2,
			DnsNames:     []string{t2ClientID},
		})
		if err != nil {
			t.Fatalf("Failed to register tenant 2 client: %v", err)
		}
		tenant2CertFile, tenant2KeyFile = waitForCertAndSave(t, ctx, clients, t2ClientID, resp2.Certificate.GetRequestId(), publicKeyPEM2, privateKey2, tempDir, "iso-t2")

		t.Log("Admin and both tenants set up successfully")
	})

	// Step 2: Generate audit logs for tenant 1
	t.Run("2_GenerateTenant1AuditLogs", func(t *testing.T) {
		if tenant1CertFile == "" {
			t.Skip("Tenant 1 not set up")
		}

		clients, err := helpers.NewGRPCClients(&helpers.ClientConfig{
			ServerAddr: env.ServerAddr,
			CertFile:   tenant1CertFile,
			KeyFile:    tenant1KeyFile,
			CAFile:     env.CAFile,
			Timeout:    30 * time.Second,
		})
		if err != nil {
			t.Fatalf("Failed to create tenant 1 clients: %v", err)
		}
		defer clients.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		// Create an issuer to generate audit logs
		issuerName := fmt.Sprintf("iso-t1-issuer-%d", time.Now().UnixNano())
		_, err = clients.Issuer.CreateIssuer(ctx, &lcmV1.CreateIssuerRequest{
			Name:    issuerName,
			Type:    "self-signed",
			KeyType: "ecdsa",
			Status:  lcmV1.IssuerStatus_ISSUER_STATUS_ACTIVE,
			SelfIssuer: &lcmV1.SelfIssuer{
				CommonName:     "Tenant 1 Isolation Test",
				CaCommonName:   "Tenant 1 CA",
				CaOrganization: "Test",
				CaValidityDays: 30,
			},
		})
		if err != nil {
			t.Fatalf("Failed to create issuer: %v", err)
		}

		time.Sleep(2 * time.Second)

		// Get tenant 1's audit logs
		listResp, err := clients.AuditLog.ListAuditLogs(ctx, &lcmV1.ListAuditLogsRequest{})
		if err != nil {
			t.Fatalf("Failed to list audit logs: %v", err)
		}

		if len(listResp.Items) > 0 {
			tenant1AuditLogID = listResp.Items[0].GetId()
			t.Logf("Tenant 1 generated audit logs, sample ID: %d", tenant1AuditLogID)
		}
	})

	// Step 3: Verify tenant 2 cannot see tenant 1's audit logs
	t.Run("3_VerifyTenant2CannotSeeTenant1Logs", func(t *testing.T) {
		if tenant2CertFile == "" {
			t.Skip("Tenant 2 not set up")
		}
		if tenant1AuditLogID == 0 {
			t.Skip("No tenant 1 audit log to test")
		}

		clients, err := helpers.NewGRPCClients(&helpers.ClientConfig{
			ServerAddr: env.ServerAddr,
			CertFile:   tenant2CertFile,
			KeyFile:    tenant2KeyFile,
			CAFile:     env.CAFile,
			Timeout:    30 * time.Second,
		})
		if err != nil {
			t.Fatalf("Failed to create tenant 2 clients: %v", err)
		}
		defer clients.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		// Try to access tenant 1's audit log by ID
		_, err = clients.AuditLog.GetAuditLog(ctx, &lcmV1.GetAuditLogRequest{
			Id: tenant1AuditLogID,
		})

		if err == nil {
			t.Fatal("Tenant 2 should NOT be able to access tenant 1's audit log")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("Expected gRPC status error, got: %v", err)
		}
		if st.Code() != codes.NotFound {
			t.Fatalf("Expected NotFound error, got: %s - %s", st.Code(), st.Message())
		}

		t.Logf("Correctly denied tenant 2 access to tenant 1's audit log: %s", st.Message())

		// Also verify tenant 2's list doesn't include tenant 1's logs
		listResp, err := clients.AuditLog.ListAuditLogs(ctx, &lcmV1.ListAuditLogsRequest{})
		if err != nil {
			t.Fatalf("Failed to list tenant 2 audit logs: %v", err)
		}

		for _, log := range listResp.Items {
			if log.GetId() == tenant1AuditLogID {
				t.Fatal("Tenant 1's audit log found in tenant 2's list - isolation failure!")
			}
		}
		t.Log("Tenant isolation verified - tenant 2 cannot see tenant 1's logs")
	})
}

// Helper functions

func generateTestKeyPair() (*ecdsa.PrivateKey, string, error) {
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

func waitForCertAndSave(t *testing.T, ctx context.Context, clients *helpers.GRPCClients, clientID, requestID, publicKeyPEM string, privateKey *ecdsa.PrivateKey, tempDir, prefix string) (certFile, keyFile string) {
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
				downloadResp, err := clients.LcmClient.DownloadClientCertificate(ctx, &lcmV1.DownloadClientCertificateRequest{
					RequestId: requestID,
					ClientId:  clientID,
					PublicKey: publicKeyPEM,
				})
				if err != nil {
					t.Fatalf("Failed to download certificate: %v", err)
				}

				certFile = filepath.Join(tempDir, fmt.Sprintf("%s.crt", prefix))
				if err := os.WriteFile(certFile, []byte(*downloadResp.CertificatePem), 0644); err != nil {
					t.Fatalf("Failed to save certificate: %v", err)
				}

				keyFile = filepath.Join(tempDir, fmt.Sprintf("%s.key", prefix))
				privateKeyBytes, _ := x509.MarshalECPrivateKey(privateKey)
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
