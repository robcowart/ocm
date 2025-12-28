package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"software.sslmate.com/src/go-pkcs12"
)

// ExportPEM exports a certificate and private key as PEM format
// Private keys are exported in PKCS#8 format for universal compatibility
func ExportPEM(certPEM string, privateKeyDER []byte, algorithm string, caCertPEMs ...string) (string, error) {
	// Start with the certificate
	result := certPEM

	// Add CA certificates in order (intermediate first, then root)
	for _, caPEM := range caCertPEMs {
		result += caPEM
	}

	// Parse the private key from DER format (PKCS#1 for RSA, SEC1 for ECDSA)
	privateKey, err := ParsePrivateKey(privateKeyDER, algorithm)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// Convert to PKCS#8 format (universal format compatible with modern applications)
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key to PKCS#8: %w", err)
	}

	// Encode as PEM with PKCS#8 format
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8DER,
	})

	result += string(keyPEM)

	return result, nil
}

// ExportPEMSeparate exports certificate and private key as separate PEM files
// certFile contains the certificate + CA chain, keyFile contains only the private key
// Private keys are exported in PKCS#8 format for universal compatibility
func ExportPEMSeparate(certPEM string, privateKeyDER []byte, algorithm string, caCertPEMs ...string) (certFile, keyFile string, err error) {
	// Build certificate file (certificate + CA chain)
	certFile = certPEM

	// Add CA certificates in order (intermediate first, then root)
	for _, caPEM := range caCertPEMs {
		certFile += caPEM
	}

	// Parse the private key from DER format (PKCS#1 for RSA, SEC1 for ECDSA)
	privateKey, err := ParsePrivateKey(privateKeyDER, algorithm)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// Convert to PKCS#8 format (universal format compatible with modern applications)
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key to PKCS#8: %w", err)
	}

	// Encode as PEM with PKCS#8 format
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8DER,
	})

	keyFile = string(keyPEM)

	return certFile, keyFile, nil
}

// ExportPKCS12 exports a certificate and private key as PKCS#12/PFX format
func ExportPKCS12(cert *x509.Certificate, privateKey interface{}, password string, caCerts ...*x509.Certificate) ([]byte, error) {
	// Use modern encryption (AES-256-SHA256) by default
	encoder := pkcs12.Modern2023

	// Encode to PKCS#12
	pfxData, err := encoder.Encode(privateKey, cert, caCerts, password)
	if err != nil {
		return nil, fmt.Errorf("failed to encode PKCS#12: %w", err)
	}

	return pfxData, nil
}

// ExportPKCS12Legacy exports using legacy encryption for compatibility with older systems
func ExportPKCS12Legacy(cert *x509.Certificate, privateKey interface{}, password string, caCerts ...*x509.Certificate) ([]byte, error) {
	// Use legacy encryption (3DES)
	encoder := pkcs12.LegacyDES

	pfxData, err := encoder.Encode(privateKey, cert, caCerts, password)
	if err != nil {
		return nil, fmt.Errorf("failed to encode PKCS#12 (legacy): %w", err)
	}

	return pfxData, nil
}

// ParseCertificatePEM parses a PEM-encoded certificate
func ParseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}
