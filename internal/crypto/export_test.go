package crypto

import (
	"crypto/x509/pkix"
	"strings"
	"testing"
)

func TestExportPEM_PKCS8Format(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		rsaBits   int
		ecCurve   string
	}{
		{
			name:      "RSA 2048",
			algorithm: "rsa",
			rsaBits:   2048,
		},
		{
			name:      "RSA 4096",
			algorithm: "rsa",
			rsaBits:   4096,
		},
		{
			name:      "ECDSA P256",
			algorithm: "ecdsa",
			ecCurve:   "P256",
		},
		{
			name:      "ECDSA P384",
			algorithm: "ecdsa",
			ecCurve:   "P384",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate a test CA
			req := &CARequest{
				FriendlyName: "Test CA",
				Subject: pkix.Name{
					CommonName:   "Test CA",
					Organization: []string{"Test Org"},
					Country:      []string{"US"},
				},
				ValidityDays: 365,
				Algorithm:    tt.algorithm,
			}

			if tt.algorithm == "rsa" {
				req.RSABits = tt.rsaBits
			} else {
				req.ECCurve = tt.ecCurve
			}

			ca, err := GenerateSelfSignedCA(req)
			if err != nil {
				t.Fatalf("Failed to generate CA: %v", err)
			}

			// Export to PEM
			pemBundle, err := ExportPEM(ca.CertificatePEM, ca.PrivateKeyDER, tt.algorithm)
			if err != nil {
				t.Fatalf("Failed to export PEM: %v", err)
			}

			// Check that it uses PKCS#8 format
			if !strings.Contains(pemBundle, "-----BEGIN PRIVATE KEY-----") {
				t.Errorf("Expected PKCS#8 format (BEGIN PRIVATE KEY), got: %s", pemBundle)
			}

			// Check that it doesn't use old formats
			if strings.Contains(pemBundle, "-----BEGIN RSA PRIVATE KEY-----") {
				t.Errorf("Found PKCS#1 format (BEGIN RSA PRIVATE KEY), should be PKCS#8")
			}
			if strings.Contains(pemBundle, "-----BEGIN EC PRIVATE KEY-----") {
				t.Errorf("Found SEC1 format (BEGIN EC PRIVATE KEY), should be PKCS#8")
			}

			// Verify the certificate is also present
			if !strings.Contains(pemBundle, "-----BEGIN CERTIFICATE-----") {
				t.Errorf("Certificate not found in PEM bundle")
			}
		})
	}
}

func TestExportPEM_WithCAChain(t *testing.T) {
	// Generate a test CA
	ca, err := GenerateSelfSignedCA(&CARequest{
		FriendlyName: "Test Root CA",
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		ValidityDays: 365,
		Algorithm:    "rsa",
		RSABits:      2048,
	})
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Export with CA chain
	pemBundle, err := ExportPEM(ca.CertificatePEM, ca.PrivateKeyDER, "rsa", ca.CertificatePEM)
	if err != nil {
		t.Fatalf("Failed to export PEM with CA chain: %v", err)
	}

	// Count certificates (should have cert + CA chain)
	certCount := strings.Count(pemBundle, "-----BEGIN CERTIFICATE-----")
	if certCount < 2 {
		t.Errorf("Expected at least 2 certificates in bundle, got %d", certCount)
	}

	// Verify PKCS#8 format
	if !strings.Contains(pemBundle, "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("Expected PKCS#8 format in bundle with CA chain")
	}
}

