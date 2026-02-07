package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	conf "github.com/go-tangra/go-tangra-portal/app/lcm/service/internal/conf"
)

// CertManager manages certificate generation and loading for the gRPC server
type CertManager struct {
	config *conf.LCM
	log    *log.Helper
}

// NewCertManager creates a new certificate manager
// It will auto-generate CA certificates if they don't exist and auto_generate_ca is enabled
func NewCertManager(ctx *bootstrap.Context) (*CertManager, error) {
	cfg, ok := ctx.GetCustomConfig("lcm")
	if !ok {
		return nil, fmt.Errorf("lcm config not found")
	}
	lcmConfig, ok := cfg.(*conf.LCM)
	if !ok {
		return nil, fmt.Errorf("invalid lcm config type")
	}

	cm := &CertManager{
		config: lcmConfig,
		log:    ctx.NewLoggerHelper("lcm/cert-manager"),
	}

	// Ensure CA certificates exist (auto-generate if configured)
	if err := cm.ensureCA(); err != nil {
		return nil, fmt.Errorf("failed to ensure CA certificates: %w", err)
	}

	return cm, nil
}

// GetServerTLSConfig returns a TLS configuration for the gRPC server
// It will auto-generate server certificates if they don't exist
func (cm *CertManager) GetServerTLSConfig() (*tls.Config, error) {
	serverCertPath := filepath.Join(cm.config.GetDataDir(), "server", "server.crt")
	serverKeyPath := filepath.Join(cm.config.GetDataDir(), "server", "server.key")

	// Check if server certificates exist
	if !cm.certificatesExist(serverCertPath, serverKeyPath) {
		cm.log.Info("Server certificates not found, generating new ones...")
		if err := cm.generateServerCertificates(serverCertPath, serverKeyPath); err != nil {
			return nil, fmt.Errorf("failed to generate server certificates: %w", err)
		}
	}

	// Load the server certificate and key
	cert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificates: %w", err)
	}

	// Load CA certificate for client verification
	caCert, _, err := cm.loadCA()
	if err != nil {
		return nil, fmt.Errorf("failed to load CA for client verification: %w", err)
	}

	// Create CA certificate pool for client verification
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    caCertPool,
	}, nil
}

// ensureCA ensures CA certificates exist, generating them if auto_generate_ca is enabled
func (cm *CertManager) ensureCA() error {
	caCertPath := cm.config.GetCaCertPath()
	caKeyPath := cm.config.GetCaKeyPath()

	// Check if CA files already exist
	if cm.certificatesExist(caCertPath, caKeyPath) {
		cm.log.Info("CA certificates already exist")
		return nil
	}

	// If auto-generate is not enabled, we can't create CA
	if !cm.config.GetAutoGenerateCa() {
		cm.log.Warn("CA certificates not found and auto_generate_ca is disabled")
		return nil // Don't fail - let it fail later when CA is actually needed
	}

	cm.log.Info("CA certificates not found, generating new CA...")
	if err := cm.generateCA(caCertPath, caKeyPath); err != nil {
		return fmt.Errorf("failed to generate CA: %w", err)
	}

	cm.log.Info("CA certificates generated successfully")
	return nil
}

// certificatesExist checks if both certificate and key files exist
func (cm *CertManager) certificatesExist(certPath, keyPath string) bool {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return false
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return false
	}
	return true
}

// generateServerCertificates generates server certificate signed by the configured CA
func (cm *CertManager) generateServerCertificates(certPath, keyPath string) error {
	// Load CA certificate and key
	caCert, caKey, err := cm.loadCA()
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}

	// Generate server private key
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate server private key: %w", err)
	}

	// Create certificate template for server
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"LCM"},
			OrganizationalUnit: []string{"LCM Server"},
			CommonName:         "lcm-server",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year validity
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
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

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Ensure server directory exists
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return fmt.Errorf("failed to create server directory: %w", err)
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

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Set appropriate permissions
	if err := os.Chmod(keyPath, 0600); err != nil {
		return fmt.Errorf("failed to set key file permissions: %w", err)
	}

	cm.log.Infof("Generated server certificate: %s", certPath)
	cm.log.Infof("Generated server key: %s", keyPath)

	return nil
}

// loadCA loads the CA certificate and private key
func (cm *CertManager) loadCA() (*x509.Certificate, any, error) {
	caCertPath := cm.config.GetCaCertPath()
	caKeyPath := cm.config.GetCaKeyPath()

	// Check if CA files exist
	if !cm.certificatesExist(caCertPath, caKeyPath) {
		if cm.config.GetAutoGenerateCa() {
			cm.log.Info("CA certificates not found, generating new CA...")
			if err := cm.generateCA(caCertPath, caKeyPath); err != nil {
				return nil, nil, fmt.Errorf("failed to generate CA: %w", err)
			}
		} else {
			return nil, nil, fmt.Errorf("CA certificates not found at %s and %s", caCertPath, caKeyPath)
		}
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

// SignClientCertificate signs a client certificate using the CA
func (cm *CertManager) SignClientCertificate(publicKeyPEM string, commonName string, dnsNames []string, ipAddresses []string, validityDays int) (certPEM string, serialNumber int64, err error) {
	// Load CA certificate and key
	caCert, caKey, err := cm.loadCA()
	if err != nil {
		return "", 0, fmt.Errorf("failed to load CA: %w", err)
	}

	// Parse the public key
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", 0, fmt.Errorf("failed to decode public key PEM")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", 0, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Generate serial number
	serialBig, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return "", 0, fmt.Errorf("failed to generate serial number: %w", err)
	}
	serialNumber = serialBig.Int64()

	// Set validity
	if validityDays <= 0 {
		validityDays = int(cm.config.GetDefaultValidityDays())
		if validityDays <= 0 {
			validityDays = 365 // Default 1 year
		}
	}

	// Parse IP addresses
	var ips []net.IP
	for _, ipStr := range ipAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			ips = append(ips, ip)
		}
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"LCM"},
			OrganizationalUnit: []string{"LCM Client"},
			CommonName:         commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validityDays),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, publicKey, caKey)
	if err != nil {
		return "", 0, fmt.Errorf("failed to create client certificate: %w", err)
	}

	// Encode to PEM
	certPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	cm.log.Infof("Signed client certificate for %s (serial: %d)", commonName, serialNumber)

	return string(certPEMBytes), serialNumber, nil
}

// GetCACertificatePEM returns the CA certificate in PEM format
func (cm *CertManager) GetCACertificatePEM() (string, error) {
	caCertPath := cm.config.GetCaCertPath()
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return "", fmt.Errorf("failed to read CA certificate: %w", err)
	}
	return string(caCertPEM), nil
}

// GetConfig returns the LCM configuration
func (cm *CertManager) GetConfig() *conf.LCM {
	return cm.config
}

// generateCA generates a self-signed CA certificate and key
func (cm *CertManager) generateCA(caCertPath, caKeyPath string) error {
	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to generate CA private key: %w", err)
	}

	// Create CA certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"LCM"},
			OrganizationalUnit: []string{"LCM Certificate Authority"},
			CommonName:         "LCM Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create self-signed CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Ensure CA directory exists
	if err := os.MkdirAll(filepath.Dir(caCertPath), 0755); err != nil {
		return fmt.Errorf("failed to create CA directory: %w", err)
	}

	// Save CA certificate
	caCertOut, err := os.Create(caCertPath)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate file: %w", err)
	}
	defer caCertOut.Close()

	if err := pem.Encode(caCertOut, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}); err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	// Save CA private key
	caKeyOut, err := os.Create(caKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create CA key file: %w", err)
	}
	defer caKeyOut.Close()

	caPrivKeyBytes, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return fmt.Errorf("failed to marshal CA private key: %w", err)
	}

	if err := pem.Encode(caKeyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: caPrivKeyBytes}); err != nil {
		return fmt.Errorf("failed to write CA private key: %w", err)
	}

	// Set appropriate permissions
	if err := os.Chmod(caKeyPath, 0600); err != nil {
		return fmt.Errorf("failed to set CA key file permissions: %w", err)
	}

	cm.log.Infof("Generated CA certificate: %s", caCertPath)
	cm.log.Infof("Generated CA key: %s", caKeyPath)

	return nil
}
