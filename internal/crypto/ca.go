package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// CARequest represents a request to create a Certificate Authority
type CARequest struct {
	FriendlyName string
	Subject      pkix.Name
	Algorithm    string // "rsa" or "ecdsa"
	RSABits      int
	ECCurve      string // "P256" or "P384"
	ValidityDays int
}

// CAResult contains the generated CA certificate and private key
type CAResult struct {
	Certificate    *x509.Certificate
	CertificatePEM string
	PrivateKey     interface{} // *rsa.PrivateKey or *ecdsa.PrivateKey
	PrivateKeyDER  []byte
}

// GenerateSelfSignedCA generates a self-signed Root CA
func GenerateSelfSignedCA(req *CARequest) (*CAResult, error) {
	// Generate private key
	privateKey, err := generatePrivateKey(req.Algorithm, req.RSABits, req.ECCurve)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Calculate validity period
	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, req.ValidityDays)

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               req.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
		MaxPathLen:            2,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, getPublicKey(privateKey), privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Marshal private key
	privateKeyDER, err := marshalPrivateKey(privateKey, req.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	return &CAResult{
		Certificate:    cert,
		CertificatePEM: string(certPEM),
		PrivateKey:     privateKey,
		PrivateKeyDER:  privateKeyDER,
	}, nil
}

// ImportCA imports an existing CA certificate and private key from PEM
func ImportCA(certPEM, keyPEM []byte, password string) (*CAResult, error) {
	// Parse certificate
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Verify it's a CA certificate
	if !cert.IsCA {
		return nil, fmt.Errorf("certificate is not a CA certificate")
	}

	// Parse private key
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	var privateKey interface{}
	var privateKeyDER []byte

	// Try to decrypt if encrypted
	if x509.IsEncryptedPEMBlock(keyBlock) {
		if password == "" {
			return nil, fmt.Errorf("private key is encrypted but no password provided")
		}
		decrypted, err := x509.DecryptPEMBlock(keyBlock, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}
		privateKeyDER = decrypted
	} else {
		privateKeyDER = keyBlock.Bytes
	}

	// Try to parse as different key types
	if key, err := x509.ParsePKCS8PrivateKey(privateKeyDER); err == nil {
		privateKey = key
	} else if key, err := x509.ParsePKCS1PrivateKey(privateKeyDER); err == nil {
		privateKey = key
	} else if key, err := x509.ParseECPrivateKey(privateKeyDER); err == nil {
		privateKey = key
	} else {
		return nil, fmt.Errorf("failed to parse private key")
	}

	// Verify key matches certificate
	if !verifyKeyPair(cert, privateKey) {
		return nil, fmt.Errorf("private key does not match certificate")
	}

	// Re-marshal the private key in standard format
	var algorithm string
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		algorithm = "rsa"
	case *ecdsa.PrivateKey:
		algorithm = "ecdsa"
	default:
		return nil, fmt.Errorf("unsupported key type")
	}

	privateKeyDER, err = marshalPrivateKey(privateKey, algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	return &CAResult{
		Certificate:    cert,
		CertificatePEM: string(certPEM),
		PrivateKey:     privateKey,
		PrivateKeyDER:  privateKeyDER,
	}, nil
}

// Helper functions

func generatePrivateKey(algorithm string, rsaBits int, ecCurve string) (interface{}, error) {
	switch algorithm {
	case "rsa":
		return rsa.GenerateKey(rand.Reader, rsaBits)
	case "ecdsa":
		var curve elliptic.Curve
		switch ecCurve {
		case "P256":
			curve = elliptic.P256()
		case "P384":
			curve = elliptic.P384()
		default:
			return nil, fmt.Errorf("unsupported EC curve: %s", ecCurve)
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

func getPublicKey(privateKey interface{}) interface{} {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey
	case *ecdsa.PrivateKey:
		return &key.PublicKey
	default:
		return nil
	}
}

func marshalPrivateKey(privateKey interface{}, algorithm string) ([]byte, error) {
	switch algorithm {
	case "rsa":
		rsaKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid RSA private key")
		}
		return x509.MarshalPKCS1PrivateKey(rsaKey), nil
	case "ecdsa":
		ecKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid ECDSA private key")
		}
		return x509.MarshalECPrivateKey(ecKey)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

func verifyKeyPair(cert *x509.Certificate, privateKey interface{}) bool {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return false
		}
		return key.PublicKey.N.Cmp(pubKey.N) == 0
	case *ecdsa.PrivateKey:
		pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		return key.PublicKey.X.Cmp(pubKey.X) == 0 && key.PublicKey.Y.Cmp(pubKey.Y) == 0
	default:
		return false
	}
}
