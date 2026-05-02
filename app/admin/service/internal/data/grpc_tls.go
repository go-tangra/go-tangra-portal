package data

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-kratos/kratos/v2/log"
	"google.golang.org/grpc/credentials"
)

// loadAdminClientTLS loads mTLS credentials for the admin-service to connect
// to a target module's gRPC server. It uses the registration-rework layout
// produced by cert.Ensure() in go-tangra-common:
//   - CA:          {certsDir}/ca/ca.crt
//   - Client cert: {certsDir}/client/client.crt
//   - Client key:  {certsDir}/client/client.key
//
// certsDir defaults to /app/certs and can be overridden via the CERTS_DIR env var.
// serverName should match a SAN in the target module's server certificate
// (e.g. "lcm-service", "deployer-service").
func loadAdminClientTLS(serverName string, l *log.Helper) (credentials.TransportCredentials, error) {
	certsDir := os.Getenv("CERTS_DIR")
	if certsDir == "" {
		certsDir = "/app/certs"
	}

	caCertPath := filepath.Join(certsDir, "ca", "ca.crt")
	clientCertPath := filepath.Join(certsDir, "client", "client.crt")
	clientKeyPath := filepath.Join(certsDir, "client", "client.key")

	// Load CA certificate
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		l.Errorf("Failed to read CA cert from %s: %v", caCertPath, err)
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		l.Errorf("Failed to parse CA cert from %s", caCertPath)
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Load client certificate and key
	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		l.Errorf("Failed to load client cert/key from %s, %s: %v", clientCertPath, clientKeyPath, err)
		return nil, err
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}

	l.Infof("Loaded TLS credentials: CA=%s, Cert=%s, ServerName=%s", caCertPath, clientCertPath, serverName)

	return credentials.NewTLS(tlsConfig), nil
}
