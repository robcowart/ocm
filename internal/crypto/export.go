package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"software.sslmate.com/src/go-pkcs12"
)

// ExportPEM exports a certificate and private key as PEM format
func ExportPEM(certPEM string, privateKeyDER []byte, algorithm string, caCertPEMs ...string) (string, error) {
	// Start with the certificate
	result := certPEM

	// Add CA certificates in order (intermediate first, then root)
	for _, caPEM := range caCertPEMs {
		result += caPEM
	}

	// Add private key
	var pemType string
	switch algorithm {
	case "rsa":
		pemType = "RSA PRIVATE KEY"
	case "ecdsa":
		pemType = "EC PRIVATE KEY"
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  pemType,
		Bytes: privateKeyDER,
	})

	result += string(keyPEM)

	return result, nil
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
