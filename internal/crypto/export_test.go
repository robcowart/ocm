package crypto

import (
	"crypto/x509/pkix"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"
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
			require.NoError(t, err)

			// Export to PEM
			pemBundle, err := ExportPEM(ca.CertificatePEM, ca.PrivateKeyDER, tt.algorithm)
			require.NoError(t, err)

			// Check that it uses PKCS#8 format
			assert.Contains(t, pemBundle, "-----BEGIN PRIVATE KEY-----", "Expected PKCS#8 format")

			// Check that it doesn't use old formats
			assert.NotContains(t, pemBundle, "-----BEGIN RSA PRIVATE KEY-----", "Should not use PKCS#1 format")
			assert.NotContains(t, pemBundle, "-----BEGIN EC PRIVATE KEY-----", "Should not use SEC1 format")

			// Verify the certificate is also present
			assert.Contains(t, pemBundle, "-----BEGIN CERTIFICATE-----", "Certificate should be in bundle")
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
	require.NoError(t, err)

	// Export with CA chain
	pemBundle, err := ExportPEM(ca.CertificatePEM, ca.PrivateKeyDER, "rsa", ca.CertificatePEM)
	require.NoError(t, err)

	// Count certificates (should have cert + CA chain)
	certCount := strings.Count(pemBundle, "-----BEGIN CERTIFICATE-----")
	assert.GreaterOrEqual(t, certCount, 2, "Expected at least 2 certificates in bundle")

	// Verify PKCS#8 format
	assert.Contains(t, pemBundle, "-----BEGIN PRIVATE KEY-----", "Expected PKCS#8 format")
}

func TestExportPEM_InvalidPrivateKey(t *testing.T) {
	t.Run("Export with invalid private key DER fails", func(t *testing.T) {
		ca, err := GenerateSelfSignedCA(&CARequest{
			FriendlyName: "Test CA",
			Subject: pkix.Name{
				CommonName: "Test CA",
			},
			Algorithm:    "rsa",
			RSABits:      2048,
			ValidityDays: 365,
		})
		require.NoError(t, err)

		_, err = ExportPEM(ca.CertificatePEM, []byte("invalid"), "rsa")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse private key")
	})

	t.Run("Export with unsupported algorithm fails", func(t *testing.T) {
		ca, err := GenerateSelfSignedCA(&CARequest{
			FriendlyName: "Test CA",
			Subject: pkix.Name{
				CommonName: "Test CA",
			},
			Algorithm:    "rsa",
			RSABits:      2048,
			ValidityDays: 365,
		})
		require.NoError(t, err)

		_, err = ExportPEM(ca.CertificatePEM, ca.PrivateKeyDER, "unsupported")
		assert.Error(t, err)
	})
}

func TestExportPEMSeparate(t *testing.T) {
	ca, err := GenerateSelfSignedCA(&CARequest{
		FriendlyName: "Test CA",
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		Algorithm:    "rsa",
		RSABits:      2048,
		ValidityDays: 365,
	})
	require.NoError(t, err)

	t.Run("Export PEM as separate files", func(t *testing.T) {
		certFile, keyFile, err := ExportPEMSeparate(ca.CertificatePEM, ca.PrivateKeyDER, "rsa")
		require.NoError(t, err)

		// Cert file should have certificate
		assert.Contains(t, certFile, "-----BEGIN CERTIFICATE-----")
		assert.NotContains(t, certFile, "-----BEGIN PRIVATE KEY-----")

		// Key file should have private key only
		assert.Contains(t, keyFile, "-----BEGIN PRIVATE KEY-----")
		assert.NotContains(t, keyFile, "-----BEGIN CERTIFICATE-----")
	})

	t.Run("Export with CA chain in cert file", func(t *testing.T) {
		certFile, keyFile, err := ExportPEMSeparate(ca.CertificatePEM, ca.PrivateKeyDER, "rsa", ca.CertificatePEM)
		require.NoError(t, err)

		// Cert file should have multiple certificates
		certCount := strings.Count(certFile, "-----BEGIN CERTIFICATE-----")
		assert.GreaterOrEqual(t, certCount, 2)

		// Key file should still only have the key
		assert.Contains(t, keyFile, "-----BEGIN PRIVATE KEY-----")
		assert.NotContains(t, keyFile, "-----BEGIN CERTIFICATE-----")
	})

	t.Run("Export with invalid private key fails", func(t *testing.T) {
		_, _, err := ExportPEMSeparate(ca.CertificatePEM, []byte("invalid"), "rsa")
		assert.Error(t, err)
	})
}

func TestExportPKCS12(t *testing.T) {
	ca, err := GenerateSelfSignedCA(&CARequest{
		FriendlyName: "Test CA",
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		Algorithm:    "rsa",
		RSABits:      2048,
		ValidityDays: 365,
	})
	require.NoError(t, err)

	t.Run("Export PKCS12 successfully", func(t *testing.T) {
		password := "test-password"
		pfxData, err := ExportPKCS12(ca.Certificate, ca.PrivateKey, password)
		require.NoError(t, err)
		assert.NotEmpty(t, pfxData)

		// Verify we can decode it back
		privateKey, cert, caCerts, err := pkcs12.DecodeChain(pfxData, password)
		require.NoError(t, err)
		assert.NotNil(t, privateKey)
		assert.NotNil(t, cert)
		assert.Empty(t, caCerts) // No CA chain in this test
	})

	t.Run("Export PKCS12 with CA chain", func(t *testing.T) {
		// Generate a certificate
		certReq := &CertificateRequest{
			CommonName:   "example.com",
			Algorithm:    "rsa",
			RSABits:      2048,
			ValidityDays: 365,
		}

		cert, err := GenerateCertificate(certReq, ca.Certificate, ca.PrivateKey)
		require.NoError(t, err)

		password := "test-password"
		pfxData, err := ExportPKCS12(cert.Certificate, cert.PrivateKey, password, ca.Certificate)
		require.NoError(t, err)
		assert.NotEmpty(t, pfxData)

		// Verify we can decode it back with CA chain
		privateKey, decodedCert, caCerts, err := pkcs12.DecodeChain(pfxData, password)
		require.NoError(t, err)
		assert.NotNil(t, privateKey)
		assert.NotNil(t, decodedCert)
		assert.Len(t, caCerts, 1)
	})

	t.Run("Export PKCS12 with empty password", func(t *testing.T) {
		pfxData, err := ExportPKCS12(ca.Certificate, ca.PrivateKey, "")
		require.NoError(t, err)
		assert.NotEmpty(t, pfxData)

		// Verify we can decode with empty password
		_, cert, _, err := pkcs12.DecodeChain(pfxData, "")
		require.NoError(t, err)
		assert.NotNil(t, cert)
	})

	t.Run("Export PKCS12 for ECDSA", func(t *testing.T) {
		ecCA, err := GenerateSelfSignedCA(&CARequest{
			FriendlyName: "Test EC CA",
			Subject: pkix.Name{
				CommonName: "Test EC CA",
			},
			Algorithm:    "ecdsa",
			ECCurve:      "P256",
			ValidityDays: 365,
		})
		require.NoError(t, err)

		password := "test-password"
		pfxData, err := ExportPKCS12(ecCA.Certificate, ecCA.PrivateKey, password)
		require.NoError(t, err)
		assert.NotEmpty(t, pfxData)

		// Verify we can decode it back
		_, cert, _, err := pkcs12.DecodeChain(pfxData, password)
		require.NoError(t, err)
		assert.NotNil(t, cert)
	})
}

func TestExportPKCS12Legacy(t *testing.T) {
	ca, err := GenerateSelfSignedCA(&CARequest{
		FriendlyName: "Test CA",
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		Algorithm:    "rsa",
		RSABits:      2048,
		ValidityDays: 365,
	})
	require.NoError(t, err)

	t.Run("Export legacy PKCS12 successfully", func(t *testing.T) {
		password := "test-password"
		pfxData, err := ExportPKCS12Legacy(ca.Certificate, ca.PrivateKey, password)
		require.NoError(t, err)
		assert.NotEmpty(t, pfxData)

		// Verify we can decode it back
		privateKey, cert, caCerts, err := pkcs12.DecodeChain(pfxData, password)
		require.NoError(t, err)
		assert.NotNil(t, privateKey)
		assert.NotNil(t, cert)
		assert.Empty(t, caCerts)
	})

	t.Run("Export legacy PKCS12 with CA chain", func(t *testing.T) {
		// Generate a certificate
		certReq := &CertificateRequest{
			CommonName:   "example.com",
			Algorithm:    "rsa",
			RSABits:      2048,
			ValidityDays: 365,
		}

		cert, err := GenerateCertificate(certReq, ca.Certificate, ca.PrivateKey)
		require.NoError(t, err)

		password := "test-password"
		pfxData, err := ExportPKCS12Legacy(cert.Certificate, cert.PrivateKey, password, ca.Certificate)
		require.NoError(t, err)
		assert.NotEmpty(t, pfxData)

		// Verify we can decode it back
		_, decodedCert, caCerts, err := pkcs12.DecodeChain(pfxData, password)
		require.NoError(t, err)
		assert.NotNil(t, decodedCert)
		assert.Len(t, caCerts, 1)
	})
}

func TestParseCertificatePEM(t *testing.T) {
	ca, err := GenerateSelfSignedCA(&CARequest{
		FriendlyName: "Test CA",
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		Algorithm:    "rsa",
		RSABits:      2048,
		ValidityDays: 365,
	})
	require.NoError(t, err)

	t.Run("Parse valid certificate PEM", func(t *testing.T) {
		cert, err := ParseCertificatePEM([]byte(ca.CertificatePEM))
		require.NoError(t, err)
		assert.NotNil(t, cert)
		assert.Equal(t, ca.Certificate.SerialNumber, cert.SerialNumber)
		assert.Equal(t, ca.Certificate.Subject.CommonName, cert.Subject.CommonName)
	})

	t.Run("Parse invalid PEM fails", func(t *testing.T) {
		_, err := ParseCertificatePEM([]byte("invalid pem"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode certificate PEM")
	})

	t.Run("Parse wrong PEM type fails", func(t *testing.T) {
		wrongPEM := "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----"
		_, err := ParseCertificatePEM([]byte(wrongPEM))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode certificate PEM")
	})
}

