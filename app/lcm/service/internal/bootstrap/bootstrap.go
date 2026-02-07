package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	lcmV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/conf"
	"github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/data"
	appViewer "github.com/go-tangra/go-tangra-portal/pkg/entgo/viewer"
)

const (
	// AdminClientID is the client_id for the auto-generated admin certificate
	AdminClientID = "lcm-admin"

	// DeployerClientID is the client_id for the auto-generated deployer certificate
	DeployerClientID = "lcm-deployer"

	// WardenClientID is the client_id for the auto-generated warden certificate
	WardenClientID = "lcm-warden"

	// IpamClientID is the client_id for the auto-generated ipam certificate
	IpamClientID = "lcm-ipam"

	// PaperlessClientID is the client_id for the auto-generated paperless certificate
	PaperlessClientID = "lcm-paperless"

	// ServerCertIssuer is the issuer name for the server certificate (used when signing admin certs)
	ServerCertIssuer = "lcm-server"

	// RootCAIssuer is the issuer name for the root CA
	RootCAIssuer = "lcm-root-ca"

	// Certificate directory names (relative to data_dir)
	ServerCertDir    = "server"
	AdminCertDir     = "admin"
	DeployerCertDir  = "deployer"
	WardenCertDir    = "warden"
	IpamCertDir      = "ipam"
	PaperlessCertDir = "paperless"

	// Server certificate directory names for module services
	// These contain server certificates that the services present to clients
	WardenServerCertDir    = "warden-server"
	IpamServerCertDir      = "ipam-server"
	PaperlessServerCertDir = "paperless-server"
	DeployerServerCertDir  = "deployer-server"
)

// BootstrapService handles initial certificate setup on server startup
type BootstrapService struct {
	config     *conf.LCM
	certRepo   *data.MtlsCertificateRepo
	clientRepo *data.LcmClientRepo
	log        *log.Helper
}

// NewBootstrapService creates a new bootstrap service
func NewBootstrapService(
	ctx *bootstrap.Context,
	certRepo *data.MtlsCertificateRepo,
	clientRepo *data.LcmClientRepo,
) (*BootstrapService, error) {
	cfg, ok := ctx.GetCustomConfig("lcm")
	if !ok {
		return nil, fmt.Errorf("lcm config not found")
	}
	lcmConfig, ok := cfg.(*conf.LCM)
	if !ok {
		return nil, fmt.Errorf("invalid lcm config type")
	}

	return &BootstrapService{
		config:     lcmConfig,
		certRepo:   certRepo,
		clientRepo: clientRepo,
		log:        ctx.NewLoggerHelper("lcm/bootstrap"),
	}, nil
}

// Bootstrap performs the initial certificate setup
func (bs *BootstrapService) Bootstrap(ctx context.Context) error {
	// Wrap context with system viewer to bypass ent privacy checks during bootstrap
	ctx = appViewer.NewSystemViewerContext(ctx)
	bs.log.Info("Starting mTLS certificate bootstrap...")

	// Step 1: Ensure server certificate exists
	_, _, err := bs.ensureServerCertificate(ctx)
	if err != nil {
		return fmt.Errorf("failed to ensure server certificate: %w", err)
	}

	// Step 2: Ensure admin client certificate exists (signed by CA, not server)
	caCert, caKey, err := bs.loadRootCA()
	if err != nil {
		return fmt.Errorf("failed to load root CA for admin cert signing: %w", err)
	}
	if err := bs.ensureAdminCertificate(ctx, caCert, caKey); err != nil {
		return fmt.Errorf("failed to ensure admin certificate: %w", err)
	}

	// Step 3: Ensure deployer client certificate exists (signed by CA)
	if err := bs.ensureDeployerCertificate(ctx, caCert, caKey); err != nil {
		return fmt.Errorf("failed to ensure deployer certificate: %w", err)
	}

	// Step 4: Ensure warden client certificate exists (signed by CA)
	if err := bs.ensureWardenCertificate(ctx, caCert, caKey); err != nil {
		return fmt.Errorf("failed to ensure warden certificate: %w", err)
	}

	// Step 5: Ensure ipam client certificate exists (signed by CA)
	if err := bs.ensureIpamCertificate(ctx, caCert, caKey); err != nil {
		return fmt.Errorf("failed to ensure ipam certificate: %w", err)
	}

	// Step 6: Ensure paperless client certificate exists (signed by CA)
	if err := bs.ensurePaperlessCertificate(ctx, caCert, caKey); err != nil {
		return fmt.Errorf("failed to ensure paperless certificate: %w", err)
	}

	// Step 7: Ensure module SERVER certificates exist (for services to present to clients)
	// These are different from client certificates - they have SANs matching Docker service names
	if err := bs.ensureWardenServerCertificate(ctx, caCert, caKey); err != nil {
		return fmt.Errorf("failed to ensure warden server certificate: %w", err)
	}
	if err := bs.ensureIpamServerCertificate(ctx, caCert, caKey); err != nil {
		return fmt.Errorf("failed to ensure ipam server certificate: %w", err)
	}
	if err := bs.ensurePaperlessServerCertificate(ctx, caCert, caKey); err != nil {
		return fmt.Errorf("failed to ensure paperless server certificate: %w", err)
	}
	if err := bs.ensureDeployerServerCertificate(ctx, caCert, caKey); err != nil {
		return fmt.Errorf("failed to ensure deployer server certificate: %w", err)
	}

	bs.log.Info("mTLS certificate bootstrap completed successfully")
	return nil
}

// ensureServerCertificate ensures the server certificate exists, generating it if necessary
func (bs *BootstrapService) ensureServerCertificate(ctx context.Context) (*x509.Certificate, *rsa.PrivateKey, error) {
	serverCertPath := filepath.Join(bs.config.GetDataDir(), ServerCertDir, "server.crt")
	serverKeyPath := filepath.Join(bs.config.GetDataDir(), ServerCertDir, "server.key")

	// Check if server certificate exists in files
	if bs.certificatesExist(serverCertPath, serverKeyPath) {
		bs.log.Info("Server certificate already exists in files, loading...")
		return bs.loadCertificateAndKey(serverCertPath, serverKeyPath)
	}

	bs.log.Info("Server certificate not found, generating new intermediate CA certificate...")

	// Load Root CA
	caCert, caKey, err := bs.loadRootCA()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load root CA: %w", err)
	}

	// Generate server private key (RSA-2048)
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate server key: %w", err)
	}

	// Generate unique serial number
	serialNumber, err := bs.generateSerialNumber(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template with CA capabilities (intermediate CA)
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"LCM"},
			OrganizationalUnit: []string{"LCM Server CA"},
			CommonName:         "lcm-server",
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0, // Can only sign end-entity certificates
		MaxPathLenZero:        true,
	}

	// Add SANs (Subject Alternative Names)
	template.DNSNames = []string{
		"localhost",
		"lcm-server",
		"*.local",
	}
	template.IPAddresses = []net.IP{
		net.IPv4(127, 0, 0, 1),
		net.IPv4(0, 0, 0, 0),
		net.IPv6loopback,
	}

	// Create certificate signed by Root CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Parse the created certificate
	serverCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse server certificate: %w", err)
	}

	// Save to files
	if err := bs.saveCertificateToFiles(certDER, serverKey, serverCertPath, serverKeyPath); err != nil {
		return nil, nil, fmt.Errorf("failed to save server certificate to files: %w", err)
	}

	// Save to database
	if err := bs.saveServerCertificateToDatabase(ctx, serverCert, serverKey, serialNumber); err != nil {
		bs.log.Warnf("Failed to save server certificate to database (non-fatal): %v", err)
		// Continue even if database save fails - file-based cert is sufficient for server operation
	}

	bs.log.Infof("Generated server certificate with serial number: %d", serialNumber)
	return serverCert, serverKey, nil
}

// ensureAdminCertificate ensures the admin client certificate exists, generating it if necessary
func (bs *BootstrapService) ensureAdminCertificate(ctx context.Context, caCert *x509.Certificate, caKey any) error {
	adminCertPath := filepath.Join(bs.config.GetDataDir(), AdminCertDir, "admin.crt")
	adminKeyPath := filepath.Join(bs.config.GetDataDir(), AdminCertDir, "admin.key")

	// Check if admin certificate exists in files
	if bs.certificatesExist(adminCertPath, adminKeyPath) {
		bs.log.Info("Admin certificate already exists in files")
		// Ensure client entry exists
		bs.ensureClientEntry(ctx)
		return nil
	}

	// Files don't exist - we need to generate new certificate
	// Even if one exists in DB, we need the files for the admin gateway to connect
	bs.log.Info("Admin certificate not found in files, generating new one signed by CA...")

	// Generate admin private key (RSA-2048)
	adminKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate admin key: %w", err)
	}

	// Generate unique serial number
	serialNumber, err := bs.generateSerialNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template (client certificate, NOT CA)
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"LCM"},
			OrganizationalUnit: []string{"LCM Admin"},
			CommonName:         AdminClientID,
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Create certificate signed by Root CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &adminKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create admin certificate: %w", err)
	}

	// Parse the created certificate
	adminCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse admin certificate: %w", err)
	}

	// Save to files
	if err := bs.saveCertificateToFiles(certDER, adminKey, adminCertPath, adminKeyPath); err != nil {
		return fmt.Errorf("failed to save admin certificate to files: %w", err)
	}

	// Save to database
	if err := bs.saveClientCertificateToDatabase(ctx, adminCert, adminKey, serialNumber); err != nil {
		bs.log.Warnf("Failed to save admin certificate to database (non-fatal): %v", err)
		// Continue even if database save fails
	}

	bs.log.Infof("Generated admin certificate with serial number: %d", serialNumber)
	return nil
}

// ensureDeployerCertificate ensures the deployer client certificate exists, generating it if necessary
func (bs *BootstrapService) ensureDeployerCertificate(ctx context.Context, caCert *x509.Certificate, caKey any) error {
	deployerCertPath := filepath.Join(bs.config.GetDataDir(), DeployerCertDir, "deployer.crt")
	deployerKeyPath := filepath.Join(bs.config.GetDataDir(), DeployerCertDir, "deployer.key")

	// Check if deployer certificate exists in files
	if bs.certificatesExist(deployerCertPath, deployerKeyPath) {
		bs.log.Info("Deployer certificate already exists in files")
		// Ensure client entry exists
		bs.ensureDeployerClientEntry(ctx)
		return nil
	}

	// Files don't exist - we need to generate new certificate
	bs.log.Info("Deployer certificate not found in files, generating new one signed by CA...")

	// Generate deployer private key (RSA-2048)
	deployerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate deployer key: %w", err)
	}

	// Generate unique serial number
	serialNumber, err := bs.generateSerialNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template (client certificate, NOT CA)
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"LCM"},
			OrganizationalUnit: []string{"LCM Deployer"},
			CommonName:         DeployerClientID,
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Create certificate signed by Root CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &deployerKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create deployer certificate: %w", err)
	}

	// Parse the created certificate
	deployerCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse deployer certificate: %w", err)
	}

	// Save to files
	if err := bs.saveCertificateToFiles(certDER, deployerKey, deployerCertPath, deployerKeyPath); err != nil {
		return fmt.Errorf("failed to save deployer certificate to files: %w", err)
	}

	// Save to database
	if err := bs.saveDeployerCertificateToDatabase(ctx, deployerCert, deployerKey, serialNumber); err != nil {
		bs.log.Warnf("Failed to save deployer certificate to database (non-fatal): %v", err)
		// Continue even if database save fails
	}

	bs.log.Infof("Generated deployer certificate with serial number: %d", serialNumber)
	return nil
}

// ensureWardenCertificate ensures the warden client certificate exists, generating it if necessary
func (bs *BootstrapService) ensureWardenCertificate(ctx context.Context, caCert *x509.Certificate, caKey any) error {
	wardenCertPath := filepath.Join(bs.config.GetDataDir(), WardenCertDir, "warden.crt")
	wardenKeyPath := filepath.Join(bs.config.GetDataDir(), WardenCertDir, "warden.key")

	// Check if warden certificate exists in files
	if bs.certificatesExist(wardenCertPath, wardenKeyPath) {
		bs.log.Info("Warden certificate already exists in files")
		bs.ensureWardenClientEntry(ctx)
		return nil
	}

	bs.log.Info("Warden certificate not found in files, generating new one signed by CA...")

	// Generate warden private key (RSA-2048)
	wardenKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate warden key: %w", err)
	}

	// Generate unique serial number
	serialNumber, err := bs.generateSerialNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template (client certificate, NOT CA)
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"LCM"},
			OrganizationalUnit: []string{"LCM Warden"},
			CommonName:         WardenClientID,
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Create certificate signed by Root CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &wardenKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create warden certificate: %w", err)
	}

	// Parse the created certificate
	wardenCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse warden certificate: %w", err)
	}

	// Save to files
	if err := bs.saveCertificateToFiles(certDER, wardenKey, wardenCertPath, wardenKeyPath); err != nil {
		return fmt.Errorf("failed to save warden certificate to files: %w", err)
	}

	// Save to database
	if err := bs.saveModuleCertificateToDatabase(ctx, wardenCert, wardenKey, serialNumber, WardenClientID, "LCM Warden"); err != nil {
		bs.log.Warnf("Failed to save warden certificate to database (non-fatal): %v", err)
	}

	bs.log.Infof("Generated warden certificate with serial number: %d", serialNumber)
	return nil
}

// ensureIpamCertificate ensures the ipam client certificate exists, generating it if necessary
func (bs *BootstrapService) ensureIpamCertificate(ctx context.Context, caCert *x509.Certificate, caKey any) error {
	ipamCertPath := filepath.Join(bs.config.GetDataDir(), IpamCertDir, "ipam.crt")
	ipamKeyPath := filepath.Join(bs.config.GetDataDir(), IpamCertDir, "ipam.key")

	// Check if ipam certificate exists in files
	if bs.certificatesExist(ipamCertPath, ipamKeyPath) {
		bs.log.Info("IPAM certificate already exists in files")
		bs.ensureIpamClientEntry(ctx)
		return nil
	}

	bs.log.Info("IPAM certificate not found in files, generating new one signed by CA...")

	// Generate ipam private key (RSA-2048)
	ipamKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate ipam key: %w", err)
	}

	// Generate unique serial number
	serialNumber, err := bs.generateSerialNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template (client certificate, NOT CA)
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"LCM"},
			OrganizationalUnit: []string{"LCM IPAM"},
			CommonName:         IpamClientID,
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Create certificate signed by Root CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &ipamKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create ipam certificate: %w", err)
	}

	// Parse the created certificate
	ipamCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse ipam certificate: %w", err)
	}

	// Save to files
	if err := bs.saveCertificateToFiles(certDER, ipamKey, ipamCertPath, ipamKeyPath); err != nil {
		return fmt.Errorf("failed to save ipam certificate to files: %w", err)
	}

	// Save to database
	if err := bs.saveModuleCertificateToDatabase(ctx, ipamCert, ipamKey, serialNumber, IpamClientID, "LCM IPAM"); err != nil {
		bs.log.Warnf("Failed to save ipam certificate to database (non-fatal): %v", err)
	}

	bs.log.Infof("Generated ipam certificate with serial number: %d", serialNumber)
	return nil
}

// ensurePaperlessCertificate ensures the paperless client certificate exists, generating it if necessary
func (bs *BootstrapService) ensurePaperlessCertificate(ctx context.Context, caCert *x509.Certificate, caKey any) error {
	paperlessCertPath := filepath.Join(bs.config.GetDataDir(), PaperlessCertDir, "paperless.crt")
	paperlessKeyPath := filepath.Join(bs.config.GetDataDir(), PaperlessCertDir, "paperless.key")

	// Check if paperless certificate exists in files
	if bs.certificatesExist(paperlessCertPath, paperlessKeyPath) {
		bs.log.Info("Paperless certificate already exists in files")
		bs.ensurePaperlessClientEntry(ctx)
		return nil
	}

	bs.log.Info("Paperless certificate not found in files, generating new one signed by CA...")

	// Generate paperless private key (RSA-2048)
	paperlessKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate paperless key: %w", err)
	}

	// Generate unique serial number
	serialNumber, err := bs.generateSerialNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template (client certificate, NOT CA)
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"LCM"},
			OrganizationalUnit: []string{"LCM Paperless"},
			CommonName:         PaperlessClientID,
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Create certificate signed by Root CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &paperlessKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create paperless certificate: %w", err)
	}

	// Parse the created certificate
	paperlessCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse paperless certificate: %w", err)
	}

	// Save to files
	if err := bs.saveCertificateToFiles(certDER, paperlessKey, paperlessCertPath, paperlessKeyPath); err != nil {
		return fmt.Errorf("failed to save paperless certificate to files: %w", err)
	}

	// Save to database
	if err := bs.saveModuleCertificateToDatabase(ctx, paperlessCert, paperlessKey, serialNumber, PaperlessClientID, "LCM Paperless"); err != nil {
		bs.log.Warnf("Failed to save paperless certificate to database (non-fatal): %v", err)
	}

	bs.log.Infof("Generated paperless certificate with serial number: %d", serialNumber)
	return nil
}

// ensureWardenServerCertificate generates a SERVER certificate for the Warden service
// This certificate has SANs matching Docker service names so TLS verification succeeds
func (bs *BootstrapService) ensureWardenServerCertificate(ctx context.Context, caCert *x509.Certificate, caKey any) error {
	serverCertPath := filepath.Join(bs.config.GetDataDir(), WardenServerCertDir, "server.crt")
	serverKeyPath := filepath.Join(bs.config.GetDataDir(), WardenServerCertDir, "server.key")

	if bs.certificatesExist(serverCertPath, serverKeyPath) {
		bs.log.Info("Warden server certificate already exists in files")
		return nil
	}

	bs.log.Info("Warden server certificate not found, generating new one...")

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate warden server key: %w", err)
	}

	serialNumber, err := bs.generateSerialNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"LCM"},
			OrganizationalUnit: []string{"Warden Service"},
			CommonName:         "warden-service",
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		// SANs must include Docker service name and common development hostnames
		DNSNames: []string{
			"warden-service",
			"warden",
			"localhost",
			"warden.local",
		},
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),
			net.IPv6loopback,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create warden server certificate: %w", err)
	}

	if err := bs.saveCertificateToFiles(certDER, serverKey, serverCertPath, serverKeyPath); err != nil {
		return fmt.Errorf("failed to save warden server certificate: %w", err)
	}

	bs.log.Infof("Generated warden server certificate with serial number: %d", serialNumber)
	return nil
}

// ensureIpamServerCertificate generates a SERVER certificate for the IPAM service
func (bs *BootstrapService) ensureIpamServerCertificate(ctx context.Context, caCert *x509.Certificate, caKey any) error {
	serverCertPath := filepath.Join(bs.config.GetDataDir(), IpamServerCertDir, "server.crt")
	serverKeyPath := filepath.Join(bs.config.GetDataDir(), IpamServerCertDir, "server.key")

	if bs.certificatesExist(serverCertPath, serverKeyPath) {
		bs.log.Info("IPAM server certificate already exists in files")
		return nil
	}

	bs.log.Info("IPAM server certificate not found, generating new one...")

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate ipam server key: %w", err)
	}

	serialNumber, err := bs.generateSerialNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"LCM"},
			OrganizationalUnit: []string{"IPAM Service"},
			CommonName:         "ipam-service",
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames: []string{
			"ipam-service",
			"ipam",
			"localhost",
			"ipam.local",
		},
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),
			net.IPv6loopback,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create ipam server certificate: %w", err)
	}

	if err := bs.saveCertificateToFiles(certDER, serverKey, serverCertPath, serverKeyPath); err != nil {
		return fmt.Errorf("failed to save ipam server certificate: %w", err)
	}

	bs.log.Infof("Generated ipam server certificate with serial number: %d", serialNumber)
	return nil
}

// ensurePaperlessServerCertificate generates a SERVER certificate for the Paperless service
func (bs *BootstrapService) ensurePaperlessServerCertificate(ctx context.Context, caCert *x509.Certificate, caKey any) error {
	serverCertPath := filepath.Join(bs.config.GetDataDir(), PaperlessServerCertDir, "server.crt")
	serverKeyPath := filepath.Join(bs.config.GetDataDir(), PaperlessServerCertDir, "server.key")

	if bs.certificatesExist(serverCertPath, serverKeyPath) {
		bs.log.Info("Paperless server certificate already exists in files")
		return nil
	}

	bs.log.Info("Paperless server certificate not found, generating new one...")

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate paperless server key: %w", err)
	}

	serialNumber, err := bs.generateSerialNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"LCM"},
			OrganizationalUnit: []string{"Paperless Service"},
			CommonName:         "paperless-service",
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames: []string{
			"paperless-service",
			"paperless",
			"localhost",
			"paperless.local",
		},
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),
			net.IPv6loopback,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create paperless server certificate: %w", err)
	}

	if err := bs.saveCertificateToFiles(certDER, serverKey, serverCertPath, serverKeyPath); err != nil {
		return fmt.Errorf("failed to save paperless server certificate: %w", err)
	}

	bs.log.Infof("Generated paperless server certificate with serial number: %d", serialNumber)
	return nil
}

// ensureDeployerServerCertificate generates a SERVER certificate for the Deployer service
func (bs *BootstrapService) ensureDeployerServerCertificate(ctx context.Context, caCert *x509.Certificate, caKey any) error {
	serverCertPath := filepath.Join(bs.config.GetDataDir(), DeployerServerCertDir, "server.crt")
	serverKeyPath := filepath.Join(bs.config.GetDataDir(), DeployerServerCertDir, "server.key")

	if bs.certificatesExist(serverCertPath, serverKeyPath) {
		bs.log.Info("Deployer server certificate already exists in files")
		return nil
	}

	bs.log.Info("Deployer server certificate not found, generating new one...")

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate deployer server key: %w", err)
	}

	serialNumber, err := bs.generateSerialNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"LCM"},
			OrganizationalUnit: []string{"Deployer Service"},
			CommonName:         "deployer-service",
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames: []string{
			"deployer-service",
			"deployer",
			"localhost",
			"deployer.local",
		},
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),
			net.IPv6loopback,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create deployer server certificate: %w", err)
	}

	if err := bs.saveCertificateToFiles(certDER, serverKey, serverCertPath, serverKeyPath); err != nil {
		return fmt.Errorf("failed to save deployer server certificate: %w", err)
	}

	bs.log.Infof("Generated deployer server certificate with serial number: %d", serialNumber)
	return nil
}

// certificatesExist checks if both certificate and key files exist
func (bs *BootstrapService) certificatesExist(certPath, keyPath string) bool {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return false
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return false
	}
	return true
}

// loadRootCA loads the root CA certificate and private key from files
func (bs *BootstrapService) loadRootCA() (*x509.Certificate, any, error) {
	caCertPath := bs.config.GetCaCertPath()
	caKeyPath := bs.config.GetCaKeyPath()

	// Check if CA files exist
	if !bs.certificatesExist(caCertPath, caKeyPath) {
		return nil, nil, fmt.Errorf("root CA certificates not found at %s and %s", caCertPath, caKeyPath)
	}

	// Load CA certificate
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Load CA private key
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA key: %w", err)
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA key PEM")
	}

	var caKey any
	switch caKeyBlock.Type {
	case "PRIVATE KEY":
		caKey, err = x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	case "RSA PRIVATE KEY":
		caKey, err = x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	default:
		return nil, nil, fmt.Errorf("unsupported CA key type: %s", caKeyBlock.Type)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA key: %w", err)
	}

	return caCert, caKey, nil
}

// loadCertificateAndKey loads a certificate and RSA private key from files
func (bs *BootstrapService) loadCertificateAndKey(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Load certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Load private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode key PEM")
	}

	var key any
	switch keyBlock.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %s", keyBlock.Type)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("key is not an RSA private key")
	}

	return cert, rsaKey, nil
}

// generateSerialNumber generates a unique serial number for certificates
func (bs *BootstrapService) generateSerialNumber(ctx context.Context) (int64, error) {
	// Use timestamp-based serial with collision checking
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// Try to find a unique serial number
	for i := 0; i < 100; i++ {
		serialNumber := timestamp + int64(i)
		exists, err := bs.certRepo.IsExistBySerialNumber(ctx, serialNumber)
		if err != nil {
			bs.log.Warnf("Error checking serial number existence: %v", err)
			// If database check fails, use the timestamp directly
			return timestamp, nil
		}
		if !exists {
			return serialNumber, nil
		}
	}

	return 0, fmt.Errorf("failed to generate unique serial number after 100 attempts")
}

// saveCertificateToFiles saves a certificate and private key to files
func (bs *BootstrapService) saveCertificateToFiles(certDER []byte, key *rsa.PrivateKey, certPath, keyPath string) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Save certificate
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Save private key
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Set appropriate permissions on key file
	if err := os.Chmod(keyPath, 0600); err != nil {
		return fmt.Errorf("failed to set key file permissions: %w", err)
	}

	bs.log.Infof("Saved certificate to: %s", certPath)
	bs.log.Infof("Saved private key to: %s", keyPath)

	return nil
}

// saveServerCertificateToDatabase saves the server certificate to the database
func (bs *BootstrapService) saveServerCertificateToDatabase(ctx context.Context, cert *x509.Certificate, key *rsa.PrivateKey, serialNumber int64) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	fingerprint := sha256.Sum256(cert.Raw)

	// Encode public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	keyUsages := bs.keyUsageToStrings(cert.KeyUsage)
	extKeyUsages := bs.extKeyUsageToStrings(cert.ExtKeyUsage)
	dnsNames := cert.DNSNames
	ipAddresses := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ipAddresses = append(ipAddresses, ip.String())
	}

	certData := &lcmV1.MtlsCertificate{
		SerialNumber:       ptr(serialNumber),
		ClientId:           ptr("lcm-server"),
		CommonName:         ptr(cert.Subject.CommonName),
		SubjectDn:          ptr(cert.Subject.String()),
		IssuerDn:           ptr(cert.Issuer.String()),
		IssuerName:         ptr(RootCAIssuer),
		FingerprintSha256:  ptr(hex.EncodeToString(fingerprint[:])),
		PublicKeyAlgorithm: ptr("RSA"),
		PublicKeySize:      ptr(int32(key.PublicKey.Size() * 8)),
		SignatureAlgorithm: ptr(cert.SignatureAlgorithm.String()),
		CertificatePem:     ptr(string(certPEM)),
		PublicKeyPem:       ptr(string(pubKeyPEM)),
		DnsNames:           dnsNames,
		IpAddresses:        ipAddresses,
		CertType:           ptr(lcmV1.MtlsCertificateType_MTLS_CERT_TYPE_INTERNAL),
		Status:             ptr(lcmV1.MtlsCertificateStatus_MTLS_CERTIFICATE_STATUS_ACTIVE),
		IsCa:               ptr(true),
		PathLenConstraint:  ptr(int32(0)),
		KeyUsage:           keyUsages,
		ExtKeyUsage:        extKeyUsages,
		NotBefore:          timestamppb.New(cert.NotBefore),
		NotAfter:           timestamppb.New(cert.NotAfter),
		IssuedAt:           timestamppb.Now(),
	}

	_, err = bs.certRepo.Create(ctx, certData)
	if err != nil {
		return fmt.Errorf("failed to create certificate in database: %w", err)
	}

	bs.log.Info("Saved server certificate to database")
	return nil
}

// ensureClientEntry ensures the LcmClient entry exists for the admin client
func (bs *BootstrapService) ensureClientEntry(ctx context.Context) {
	existingClient, _ := bs.clientRepo.GetByTenantAndClientID(ctx, 0, AdminClientID)
	if existingClient == nil {
		_, err := bs.clientRepo.Create(ctx, 0, AdminClientID, map[string]string{
			"type":        "admin",
			"description": "LCM Admin Client (auto-generated)",
		})
		if err != nil {
			bs.log.Warnf("Failed to create LcmClient entry (non-fatal): %v", err)
		} else {
			bs.log.Info("Created LcmClient entry for admin")
		}
	}
}

// ensureDeployerClientEntry ensures the LcmClient entry exists for the deployer client
func (bs *BootstrapService) ensureDeployerClientEntry(ctx context.Context) {
	existingClient, _ := bs.clientRepo.GetByTenantAndClientID(ctx, 0, DeployerClientID)
	if existingClient == nil {
		_, err := bs.clientRepo.Create(ctx, 0, DeployerClientID, map[string]string{
			"type":        "deployer",
			"description": "LCM Deployer Client (auto-generated)",
		})
		if err != nil {
			bs.log.Warnf("Failed to create LcmClient entry for deployer (non-fatal): %v", err)
		} else {
			bs.log.Info("Created LcmClient entry for deployer")
		}
	}
}

// ensureWardenClientEntry ensures the LcmClient entry exists for the warden client
func (bs *BootstrapService) ensureWardenClientEntry(ctx context.Context) {
	existingClient, _ := bs.clientRepo.GetByTenantAndClientID(ctx, 0, WardenClientID)
	if existingClient == nil {
		_, err := bs.clientRepo.Create(ctx, 0, WardenClientID, map[string]string{
			"type":        "warden",
			"description": "LCM Warden Client (auto-generated)",
		})
		if err != nil {
			bs.log.Warnf("Failed to create LcmClient entry for warden (non-fatal): %v", err)
		} else {
			bs.log.Info("Created LcmClient entry for warden")
		}
	}
}

// ensureIpamClientEntry ensures the LcmClient entry exists for the ipam client
func (bs *BootstrapService) ensureIpamClientEntry(ctx context.Context) {
	existingClient, _ := bs.clientRepo.GetByTenantAndClientID(ctx, 0, IpamClientID)
	if existingClient == nil {
		_, err := bs.clientRepo.Create(ctx, 0, IpamClientID, map[string]string{
			"type":        "ipam",
			"description": "LCM IPAM Client (auto-generated)",
		})
		if err != nil {
			bs.log.Warnf("Failed to create LcmClient entry for ipam (non-fatal): %v", err)
		} else {
			bs.log.Info("Created LcmClient entry for ipam")
		}
	}
}

// ensurePaperlessClientEntry ensures the LcmClient entry exists for the paperless client
func (bs *BootstrapService) ensurePaperlessClientEntry(ctx context.Context) {
	existingClient, _ := bs.clientRepo.GetByTenantAndClientID(ctx, 0, PaperlessClientID)
	if existingClient == nil {
		_, err := bs.clientRepo.Create(ctx, 0, PaperlessClientID, map[string]string{
			"type":        "paperless",
			"description": "LCM Paperless Client (auto-generated)",
		})
		if err != nil {
			bs.log.Warnf("Failed to create LcmClient entry for paperless (non-fatal): %v", err)
		} else {
			bs.log.Info("Created LcmClient entry for paperless")
		}
	}
}

// saveModuleCertificateToDatabase saves a module client certificate to the database
func (bs *BootstrapService) saveModuleCertificateToDatabase(ctx context.Context, cert *x509.Certificate, key *rsa.PrivateKey, serialNumber int64, clientID string, orgUnit string) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	fingerprint := sha256.Sum256(cert.Raw)

	// Encode public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	keyUsages := bs.keyUsageToStrings(cert.KeyUsage)
	extKeyUsages := bs.extKeyUsageToStrings(cert.ExtKeyUsage)

	certData := &lcmV1.MtlsCertificate{
		SerialNumber:       ptr(serialNumber),
		ClientId:           ptr(clientID),
		CommonName:         ptr(cert.Subject.CommonName),
		SubjectDn:          ptr(cert.Subject.String()),
		IssuerDn:           ptr(cert.Issuer.String()),
		IssuerName:         ptr(RootCAIssuer),
		FingerprintSha256:  ptr(hex.EncodeToString(fingerprint[:])),
		PublicKeyAlgorithm: ptr("RSA"),
		PublicKeySize:      ptr(int32(key.PublicKey.Size() * 8)),
		SignatureAlgorithm: ptr(cert.SignatureAlgorithm.String()),
		CertificatePem:     ptr(string(certPEM)),
		PublicKeyPem:       ptr(string(pubKeyPEM)),
		CertType:           ptr(lcmV1.MtlsCertificateType_MTLS_CERT_TYPE_CLIENT),
		Status:             ptr(lcmV1.MtlsCertificateStatus_MTLS_CERTIFICATE_STATUS_ACTIVE),
		IsCa:               ptr(false),
		KeyUsage:           keyUsages,
		ExtKeyUsage:        extKeyUsages,
		NotBefore:          timestamppb.New(cert.NotBefore),
		NotAfter:           timestamppb.New(cert.NotAfter),
		IssuedAt:           timestamppb.Now(),
	}

	_, err = bs.certRepo.Create(ctx, certData)
	if err != nil {
		return fmt.Errorf("failed to create certificate in database: %w", err)
	}

	// Also create the LcmClient entry if it doesn't exist based on clientID
	switch clientID {
	case WardenClientID:
		bs.ensureWardenClientEntry(ctx)
	case IpamClientID:
		bs.ensureIpamClientEntry(ctx)
	case PaperlessClientID:
		bs.ensurePaperlessClientEntry(ctx)
	}

	bs.log.Infof("Saved %s certificate to database", clientID)
	return nil
}

// saveDeployerCertificateToDatabase saves the deployer certificate to the database
func (bs *BootstrapService) saveDeployerCertificateToDatabase(ctx context.Context, cert *x509.Certificate, key *rsa.PrivateKey, serialNumber int64) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	fingerprint := sha256.Sum256(cert.Raw)

	// Encode public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	keyUsages := bs.keyUsageToStrings(cert.KeyUsage)
	extKeyUsages := bs.extKeyUsageToStrings(cert.ExtKeyUsage)

	certData := &lcmV1.MtlsCertificate{
		SerialNumber:       ptr(serialNumber),
		ClientId:           ptr(DeployerClientID),
		CommonName:         ptr(cert.Subject.CommonName),
		SubjectDn:          ptr(cert.Subject.String()),
		IssuerDn:           ptr(cert.Issuer.String()),
		IssuerName:         ptr(RootCAIssuer),
		FingerprintSha256:  ptr(hex.EncodeToString(fingerprint[:])),
		PublicKeyAlgorithm: ptr("RSA"),
		PublicKeySize:      ptr(int32(key.PublicKey.Size() * 8)),
		SignatureAlgorithm: ptr(cert.SignatureAlgorithm.String()),
		CertificatePem:     ptr(string(certPEM)),
		PublicKeyPem:       ptr(string(pubKeyPEM)),
		CertType:           ptr(lcmV1.MtlsCertificateType_MTLS_CERT_TYPE_CLIENT),
		Status:             ptr(lcmV1.MtlsCertificateStatus_MTLS_CERTIFICATE_STATUS_ACTIVE),
		IsCa:               ptr(false),
		KeyUsage:           keyUsages,
		ExtKeyUsage:        extKeyUsages,
		NotBefore:          timestamppb.New(cert.NotBefore),
		NotAfter:           timestamppb.New(cert.NotAfter),
		IssuedAt:           timestamppb.Now(),
	}

	_, err = bs.certRepo.Create(ctx, certData)
	if err != nil {
		return fmt.Errorf("failed to create certificate in database: %w", err)
	}

	// Also create the LcmClient entry if it doesn't exist
	bs.ensureDeployerClientEntry(ctx)

	bs.log.Info("Saved deployer certificate to database")
	return nil
}

// saveClientCertificateToDatabase saves a client certificate to the database
func (bs *BootstrapService) saveClientCertificateToDatabase(ctx context.Context, cert *x509.Certificate, key *rsa.PrivateKey, serialNumber int64) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	fingerprint := sha256.Sum256(cert.Raw)

	// Encode public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	keyUsages := bs.keyUsageToStrings(cert.KeyUsage)
	extKeyUsages := bs.extKeyUsageToStrings(cert.ExtKeyUsage)

	certData := &lcmV1.MtlsCertificate{
		SerialNumber:       ptr(serialNumber),
		ClientId:           ptr(AdminClientID),
		CommonName:         ptr(cert.Subject.CommonName),
		SubjectDn:          ptr(cert.Subject.String()),
		IssuerDn:           ptr(cert.Issuer.String()),
		IssuerName:         ptr(ServerCertIssuer),
		FingerprintSha256:  ptr(hex.EncodeToString(fingerprint[:])),
		PublicKeyAlgorithm: ptr("RSA"),
		PublicKeySize:      ptr(int32(key.PublicKey.Size() * 8)),
		SignatureAlgorithm: ptr(cert.SignatureAlgorithm.String()),
		CertificatePem:     ptr(string(certPEM)),
		PublicKeyPem:       ptr(string(pubKeyPEM)),
		CertType:           ptr(lcmV1.MtlsCertificateType_MTLS_CERT_TYPE_CLIENT),
		Status:             ptr(lcmV1.MtlsCertificateStatus_MTLS_CERTIFICATE_STATUS_ACTIVE),
		IsCa:               ptr(false),
		KeyUsage:           keyUsages,
		ExtKeyUsage:        extKeyUsages,
		NotBefore:          timestamppb.New(cert.NotBefore),
		NotAfter:           timestamppb.New(cert.NotAfter),
		IssuedAt:           timestamppb.Now(),
	}

	_, err = bs.certRepo.Create(ctx, certData)
	if err != nil {
		return fmt.Errorf("failed to create certificate in database: %w", err)
	}

	// Also create the LcmClient entry if it doesn't exist
	bs.ensureClientEntry(ctx)

	bs.log.Info("Saved admin certificate to database")
	return nil
}

// keyUsageToStrings converts x509.KeyUsage to a slice of strings
func (bs *BootstrapService) keyUsageToStrings(ku x509.KeyUsage) []string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "ContentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KeyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "EncipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "DecipherOnly")
	}
	return usages
}

// extKeyUsageToStrings converts []x509.ExtKeyUsage to a slice of strings
func (bs *BootstrapService) extKeyUsageToStrings(ekus []x509.ExtKeyUsage) []string {
	var usages []string
	for _, eku := range ekus {
		switch eku {
		case x509.ExtKeyUsageAny:
			usages = append(usages, "Any")
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "EmailProtection")
		case x509.ExtKeyUsageIPSECEndSystem:
			usages = append(usages, "IPSECEndSystem")
		case x509.ExtKeyUsageIPSECTunnel:
			usages = append(usages, "IPSECTunnel")
		case x509.ExtKeyUsageIPSECUser:
			usages = append(usages, "IPSECUser")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSPSigning")
		default:
			usages = append(usages, fmt.Sprintf("Unknown(%d)", eku))
		}
	}
	return usages
}

// ptr is a helper function to create a pointer to a value
func ptr[T any](v T) *T {
	return &v
}
