package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// KeyAlgorithm represents the supported key algorithms
type KeyAlgorithm string

const (
	KeyAlgorithmRSA2048   KeyAlgorithm = "RSA2048"
	KeyAlgorithmRSA4096   KeyAlgorithm = "RSA4096"
	KeyAlgorithmECDSAP256 KeyAlgorithm = "ECDSAP256"
	KeyAlgorithmECDSAP384 KeyAlgorithm = "ECDSAP384"
)

// MtlsIssuer handles mTLS certificate generation and signing
type MtlsIssuer struct {
	caCert *x509.Certificate
	caKey  any // *rsa.PrivateKey or *ecdsa.PrivateKey
	caPEM  []byte
}

// CertificateRequest contains the parameters for issuing a new certificate
type CertificateRequest struct {
	ClientID       string
	CommonName     string
	Organization   []string
	OrgUnit        []string
	Country        []string
	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string
	URIs           []string
	ValidityDays   int
	IsCA           bool
	PathLenConstraint int
	KeyAlgorithm   KeyAlgorithm
	CSR            *x509.CertificateRequest // Optional CSR (if provided, use the public key from it)
	PublicKey      any                      // Optional public key (if CSR not provided and key generation not desired)
}

// IssuedCertificate contains the result of certificate issuance
type IssuedCertificate struct {
	SerialNumber       int64
	Certificate        *x509.Certificate
	CertificatePEM     string
	PrivateKeyPEM      string // Empty if CSR or public key was provided
	PublicKeyPEM       string
	FingerprintSHA256  string
	FingerprintSHA1    string
	PublicKeyAlgorithm string
	PublicKeySize      int
	SignatureAlgorithm string
	NotBefore          time.Time
	NotAfter           time.Time
	SubjectDN          string
	IssuerDN           string
	KeyUsage           []string
	ExtKeyUsage        []string
}

// NewMtlsIssuer creates a new MtlsIssuer from CA certificate and key paths
func NewMtlsIssuer(caCertPath, caKeyPath string) (*MtlsIssuer, error) {
	// Load CA certificate
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Load CA private key
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA key: %w", err)
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA key PEM")
	}

	var caKey any
	switch caKeyBlock.Type {
	case "PRIVATE KEY":
		caKey, err = x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	case "RSA PRIVATE KEY":
		caKey, err = x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	case "EC PRIVATE KEY":
		caKey, err = x509.ParseECPrivateKey(caKeyBlock.Bytes)
	default:
		return nil, fmt.Errorf("unsupported CA key type: %s", caKeyBlock.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse CA key: %w", err)
	}

	return &MtlsIssuer{
		caCert: caCert,
		caKey:  caKey,
		caPEM:  caCertPEM,
	}, nil
}

// NewMtlsIssuerFromPEM creates a new MtlsIssuer from PEM-encoded certificate and key
func NewMtlsIssuerFromPEM(caCertPEM, caKeyPEM []byte) (*MtlsIssuer, error) {
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA key PEM")
	}

	var caKey any
	switch caKeyBlock.Type {
	case "PRIVATE KEY":
		caKey, err = x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	case "RSA PRIVATE KEY":
		caKey, err = x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	case "EC PRIVATE KEY":
		caKey, err = x509.ParseECPrivateKey(caKeyBlock.Bytes)
	default:
		return nil, fmt.Errorf("unsupported CA key type: %s", caKeyBlock.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse CA key: %w", err)
	}

	return &MtlsIssuer{
		caCert: caCert,
		caKey:  caKey,
		caPEM:  caCertPEM,
	}, nil
}

// GetCACertificatePEM returns the CA certificate in PEM format
func (i *MtlsIssuer) GetCACertificatePEM() string {
	return string(i.caPEM)
}

// GetCACertificate returns the CA certificate
func (i *MtlsIssuer) GetCACertificate() *x509.Certificate {
	return i.caCert
}

// IssueCertificate issues a new certificate based on the request
func (i *MtlsIssuer) IssueCertificate(req *CertificateRequest, serialNumber int64) (*IssuedCertificate, error) {
	if req == nil {
		return nil, fmt.Errorf("certificate request is required")
	}

	// Default values
	if req.ValidityDays <= 0 {
		req.ValidityDays = 365
	}
	if req.KeyAlgorithm == "" {
		req.KeyAlgorithm = KeyAlgorithmRSA2048
	}

	var publicKey any
	var privateKey any
	var privateKeyPEM string

	// Determine public key source
	if req.CSR != nil {
		// Use public key from CSR
		publicKey = req.CSR.PublicKey
	} else if req.PublicKey != nil {
		// Use provided public key
		publicKey = req.PublicKey
	} else {
		// Generate new key pair
		var err error
		privateKey, publicKey, err = generateKeyPair(req.KeyAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key pair: %w", err)
		}
		privateKeyPEM, err = encodePrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encode private key: %w", err)
		}
	}

	// Build certificate template
	now := time.Now()
	notAfter := now.AddDate(0, 0, req.ValidityDays)

	subject := pkix.Name{
		CommonName: req.CommonName,
	}
	if len(req.Organization) > 0 {
		subject.Organization = req.Organization
	} else {
		subject.Organization = []string{"LCM"}
	}
	if len(req.OrgUnit) > 0 {
		subject.OrganizationalUnit = req.OrgUnit
	}
	if len(req.Country) > 0 {
		subject.Country = req.Country
	} else {
		subject.Country = []string{"US"}
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serialNumber),
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  req.IsCA,
	}

	if req.IsCA {
		template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		if req.PathLenConstraint >= 0 {
			template.MaxPathLen = req.PathLenConstraint
			template.MaxPathLenZero = req.PathLenConstraint == 0
		}
	} else {
		template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	// Add SANs
	template.DNSNames = req.DNSNames
	template.IPAddresses = req.IPAddresses
	template.EmailAddresses = req.EmailAddresses

	// Parse URI strings if provided
	// Note: URIs should be parsed from string to *url.URL if needed

	// Create certificate signed by CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, i.caCert, publicKey, i.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the created certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode public key to PEM
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	// Calculate fingerprints
	sha256Sum := sha256.Sum256(certDER)
	sha1Sum := sha1.Sum(certDER)

	// Get key algorithm and size
	pubKeyAlgo, pubKeySize := getPublicKeyInfo(publicKey)

	// Build key usage strings
	keyUsageStrings := keyUsageToStrings(cert.KeyUsage)
	extKeyUsageStrings := extKeyUsageToStrings(cert.ExtKeyUsage)

	return &IssuedCertificate{
		SerialNumber:       serialNumber,
		Certificate:        cert,
		CertificatePEM:     string(certPEM),
		PrivateKeyPEM:      privateKeyPEM,
		PublicKeyPEM:       string(pubKeyPEM),
		FingerprintSHA256:  hex.EncodeToString(sha256Sum[:]),
		FingerprintSHA1:    hex.EncodeToString(sha1Sum[:]),
		PublicKeyAlgorithm: pubKeyAlgo,
		PublicKeySize:      pubKeySize,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		SubjectDN:          cert.Subject.String(),
		IssuerDN:           cert.Issuer.String(),
		KeyUsage:           keyUsageStrings,
		ExtKeyUsage:        extKeyUsageStrings,
	}, nil
}

// ParseCSR parses a PEM-encoded CSR
func ParseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	return csr, nil
}

// ParsePublicKey parses a PEM-encoded public key
func ParsePublicKey(pubKeyPEM string) (any, error) {
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode public key PEM")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return pubKey, nil
}

// generateKeyPair generates a new key pair based on the algorithm
func generateKeyPair(algo KeyAlgorithm) (privateKey, publicKey any, err error) {
	switch algo {
	case KeyAlgorithmRSA2048:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		return key, &key.PublicKey, nil

	case KeyAlgorithmRSA4096:
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, err
		}
		return key, &key.PublicKey, nil

	case KeyAlgorithmECDSAP256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key, &key.PublicKey, nil

	case KeyAlgorithmECDSAP384:
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key, &key.PublicKey, nil

	default:
		return nil, nil, fmt.Errorf("unsupported key algorithm: %s", algo)
	}
}

// encodePrivateKey encodes a private key to PEM format
func encodePrivateKey(privateKey any) (string, error) {
	var keyBytes []byte
	var err error

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		keyBytes, err = x509.MarshalPKCS8PrivateKey(key)
	case *ecdsa.PrivateKey:
		keyBytes, err = x509.MarshalPKCS8PrivateKey(key)
	default:
		return "", fmt.Errorf("unsupported private key type")
	}

	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

// getPublicKeyInfo returns the algorithm and size of a public key
func getPublicKeyInfo(pubKey any) (algorithm string, size int) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return "RSA", key.Size() * 8
	case *ecdsa.PublicKey:
		return "ECDSA", key.Curve.Params().BitSize
	default:
		return "Unknown", 0
	}
}

// keyUsageToStrings converts x509.KeyUsage to a slice of strings
func keyUsageToStrings(ku x509.KeyUsage) []string {
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
func extKeyUsageToStrings(ekus []x509.ExtKeyUsage) []string {
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

// GenerateSerialNumber generates a unique serial number based on current time
// The caller should ensure uniqueness by checking against the database
func GenerateSerialNumber() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}
