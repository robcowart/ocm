package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"time"
)

// CertificateRequest represents a request to create a certificate
type CertificateRequest struct {
	CommonName       string
	Organization     []string
	OrganizationUnit []string
	Country          []string
	Province         []string
	Locality         []string
	SANs             []string // DNS names and IP addresses
	Algorithm        string   // "rsa" or "ecdsa"
	RSABits          int
	ECCurve          string // "P256" or "P384"
	ValidityDays     int
	IsServerAuth     bool
	IsClientAuth     bool
}

// CertificateResult contains the generated certificate and private key
type CertificateResult struct {
	Certificate    *x509.Certificate
	CertificatePEM string
	PrivateKey     interface{}
	PrivateKeyDER  []byte
	SerialNumber   string
}

// GenerateCertificate generates a new certificate signed by the given CA
func GenerateCertificate(req *CertificateRequest, caCert *x509.Certificate, caPrivateKey interface{}) (*CertificateResult, error) {
	// Generate private key for the certificate
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

	// Parse SANs
	var dnsNames []string
	var ipAddresses []net.IP
	for _, san := range req.SANs {
		if ip := net.ParseIP(san); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, san)
		}
	}

	// Determine key usage
	var extKeyUsage []x509.ExtKeyUsage
	if req.IsServerAuth {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if req.IsClientAuth {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if len(extKeyUsage) == 0 {
		// Default to server auth if none specified
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         req.CommonName,
			Organization:       req.Organization,
			OrganizationalUnit: req.OrganizationUnit,
			Country:            req.Country,
			Province:           req.Province,
			Locality:           req.Locality,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	// Sign the certificate with the CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, getPublicKey(privateKey), caPrivateKey)
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

	return &CertificateResult{
		Certificate:    cert,
		CertificatePEM: string(certPEM),
		PrivateKey:     privateKey,
		PrivateKeyDER:  privateKeyDER,
		SerialNumber:   fmt.Sprintf("%X", serialNumber),
	}, nil
}

// ParsePrivateKey parses a DER-encoded private key
func ParsePrivateKey(der []byte, algorithm string) (interface{}, error) {
	switch algorithm {
	case "rsa":
		return x509.ParsePKCS1PrivateKey(der)
	case "ecdsa":
		return x509.ParseECPrivateKey(der)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// GetAlgorithmFromCert determines the algorithm used by a certificate
func GetAlgorithmFromCert(cert *x509.Certificate) string {
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "rsa"
	case *ecdsa.PublicKey:
		return "ecdsa"
	default:
		return "unknown"
	}
}
