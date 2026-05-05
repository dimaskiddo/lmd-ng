package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
)

const (
	caCertFile     = "ca.crt"
	caKeyFile      = "ca.key"
	serverCertFile = "server.crt"
	serverKeyFile  = "server.key"
	clientCertFile = "client.crt"
	clientKeyFile  = "client.key"

	// certValidityYears is how long auto-generated certificates are valid.
	certValidityYears = 10
)

// NewServerTLSConfig creates a TLS configuration for the DBS server with
// mutual TLS (mTLS). The server verifies client certificates against the CA.
func NewServerTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate from %s", caFile)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// NewClientTLSConfig creates a TLS configuration for DBS clients (RTP, scan,
// update) with mutual TLS. The client presents its certificate to the server
// and verifies the server certificate against the CA.
func NewClientTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate from %s", caFile)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		ServerName:   "lmd-ng-dbs",
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// EnsureCerts is an idempotent function that generates CA, server, and client
// certificates if they don't already exist. It is called from PersistentPreRunE
// so that TLS certificates are ready on any command invocation.
//
// If the user has provided custom certificate paths in the config, this function
// skips generation and only validates that the files exist.
func EnsureCerts(cfg *config.Config) error {
	tlsCfg := &cfg.Server.TLS

	// If auto_cert is disabled, validate that user-provided certs exist
	if !tlsCfg.AutoCert {
		return validateCustomCerts(tlsCfg)
	}

	certsDir := tlsCfg.CertsDir
	if certsDir == "" {
		certsDir = filepath.Join(cfg.App.BasePath, "certs")
		tlsCfg.CertsDir = certsDir
	}

	// Create certs directory if it doesn't exist
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		return fmt.Errorf("failed to create certs directory %s: %w", certsDir, err)
	}

	caC := filepath.Join(certsDir, caCertFile)
	caK := filepath.Join(certsDir, caKeyFile)
	srvC := filepath.Join(certsDir, serverCertFile)
	srvK := filepath.Join(certsDir, serverKeyFile)
	cliC := filepath.Join(certsDir, clientCertFile)
	cliK := filepath.Join(certsDir, clientKeyFile)

	// Check if all cert files already exist
	allExist := fileExists(caC) && fileExists(caK) &&
		fileExists(srvC) && fileExists(srvK) &&
		fileExists(cliC) && fileExists(cliK)

	if allExist {
		log.Debug("TLS certificates already exist, skipping generation", "certs_dir", certsDir)
		// Populate config paths if not set
		setDefaultCertPaths(tlsCfg, certsDir)
		return nil
	}

	log.Info("Auto-generating TLS certificates", "certs_dir", certsDir)

	// Generate CA
	caCertPEM, caKeyPEM, caPrivKey, err := generateCA()
	if err != nil {
		return fmt.Errorf("failed to generate CA: %w", err)
	}

	if err := writeCertFiles(caC, caCertPEM, caK, caKeyPEM); err != nil {
		return fmt.Errorf("failed to write CA files: %w", err)
	}

	// Parse CA cert for signing
	caBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse generated CA certificate: %w", err)
	}

	// Generate server certificate
	srvCertPEM, srvKeyPEM, err := generateSignedCert(caCert, caPrivKey, "lmd-ng-dbs", true)
	if err != nil {
		return fmt.Errorf("failed to generate server certificate: %w", err)
	}

	if err := writeCertFiles(srvC, srvCertPEM, srvK, srvKeyPEM); err != nil {
		return fmt.Errorf("failed to write server cert files: %w", err)
	}

	// Generate client certificate
	cliCertPEM, cliKeyPEM, err := generateSignedCert(caCert, caPrivKey, "lmd-ng-client", false)
	if err != nil {
		return fmt.Errorf("failed to generate client certificate: %w", err)
	}

	if err := writeCertFiles(cliC, cliCertPEM, cliK, cliKeyPEM); err != nil {
		return fmt.Errorf("failed to write client cert files: %w", err)
	}

	log.Info("TLS certificates generated successfully", "certs_dir", certsDir)

	// Populate config paths
	setDefaultCertPaths(tlsCfg, certsDir)

	return nil
}

// ServerCertPaths returns the resolved server cert, key, and CA file paths.
func ServerCertPaths(cfg *config.Config) (certFile, keyFile, caFile string) {
	tlsCfg := &cfg.Server.TLS
	certsDir := tlsCfg.CertsDir

	certFile = tlsCfg.CertFile
	if certFile == "" {
		certFile = filepath.Join(certsDir, serverCertFile)
	}

	keyFile = tlsCfg.KeyFile
	if keyFile == "" {
		keyFile = filepath.Join(certsDir, serverKeyFile)
	}

	caFile = tlsCfg.CAFile
	if caFile == "" {
		caFile = filepath.Join(certsDir, caCertFile)
	}

	return certFile, keyFile, caFile
}

// ClientCertPaths returns the resolved client cert, key, and CA file paths.
func ClientCertPaths(cfg *config.Config) (certFile, keyFile, caFile string) {
	tlsCfg := &cfg.Server.TLS
	certsDir := tlsCfg.CertsDir

	certFile = filepath.Join(certsDir, clientCertFile)
	keyFile = filepath.Join(certsDir, clientKeyFile)

	caFile = tlsCfg.CAFile
	if caFile == "" {
		caFile = filepath.Join(certsDir, caCertFile)
	}

	return certFile, keyFile, caFile
}

// generateCA creates a self-signed CA certificate and private key.
func generateCA() (certPEM, keyPEM []byte, privKey *ecdsa.PrivateKey, err error) {
	privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"LMD-NG By Dimas Restu H"},
			CommonName:   "LMD-NG Internal CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(certValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal CA private key: %w", err)
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, privKey, nil
}

// generateSignedCert creates a certificate signed by the given CA.
// If isServer is true, the certificate includes server-side extensions and SANs.
func generateSignedCert(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, commonName string, isServer bool) (certPEM, keyPEM []byte, err error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"LMD-NG"},
			CommonName:   commonName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(certValidityYears, 0, 0),
	}

	if isServer {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		// Add SANs for localhost connections (both Unix socket and TCP)
		template.DNSNames = []string{"localhost", commonName}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// writeCertFiles writes a certificate and key PEM to files with restricted permissions.
func writeCertFiles(certPath string, certPEM []byte, keyPath string, keyPEM []byte) error {
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write cert file %s: %w", certPath, err)
	}

	// Key files get restrictive permissions
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write key file %s: %w", keyPath, err)
	}

	return nil
}

// validateCustomCerts checks that user-provided certificate files exist.
func validateCustomCerts(tlsCfg *config.TLSConfig) error {
	if tlsCfg.CertFile == "" || tlsCfg.KeyFile == "" || tlsCfg.CAFile == "" {
		return fmt.Errorf("auto_cert is disabled but cert_file, key_file, or ca_file is empty; provide all three or enable auto_cert")
	}

	for _, path := range []string{tlsCfg.CertFile, tlsCfg.KeyFile, tlsCfg.CAFile} {
		if !fileExists(path) {
			return fmt.Errorf("TLS certificate file not found: %s", path)
		}
	}

	return nil
}

// setDefaultCertPaths populates empty TLS config paths with the auto-generated defaults.
func setDefaultCertPaths(tlsCfg *config.TLSConfig, certsDir string) {
	if tlsCfg.CertFile == "" {
		tlsCfg.CertFile = filepath.Join(certsDir, serverCertFile)
	}

	if tlsCfg.KeyFile == "" {
		tlsCfg.KeyFile = filepath.Join(certsDir, serverKeyFile)
	}

	if tlsCfg.CAFile == "" {
		tlsCfg.CAFile = filepath.Join(certsDir, caCertFile)
	}
}

// fileExists returns true if the given path exists and is a regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	return !info.IsDir()
}
