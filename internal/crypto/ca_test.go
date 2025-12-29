package crypto

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSelfSignedCA(t *testing.T) {
	t.Run("Generate RSA 2048 CA successfully", func(t *testing.T) {
		req := &CARequest{
			FriendlyName: "Test RSA CA",
			Subject: pkix.Name{
				CommonName:   "Test RSA Root CA",
				Organization: []string{"Test Org"},
				Country:      []string{"US"},
			},
			Algorithm:    "rsa",
			RSABits:      2048,
			ValidityDays: 365,
		}

		result, err := GenerateSelfSignedCA(req)
		require.NoError(t, err)
		assert.NotNil(t, result.Certificate)
		assert.NotNil(t, result.PrivateKey)
		assert.NotEmpty(t, result.CertificatePEM)
		assert.NotEmpty(t, result.PrivateKeyDER)

		// Verify it's an RSA key
		_, ok := result.PrivateKey.(*rsa.PrivateKey)
		assert.True(t, ok, "Private key should be RSA")

		// Verify certificate properties
		assert.True(t, result.Certificate.IsCA)
		assert.Equal(t, "Test RSA Root CA", result.Certificate.Subject.CommonName)
		assert.Contains(t, result.Certificate.Subject.Organization, "Test Org")
	})

	t.Run("Generate RSA 4096 CA successfully", func(t *testing.T) {
		req := &CARequest{
			FriendlyName: "Test RSA 4096 CA",
			Subject: pkix.Name{
				CommonName: "Test RSA 4096 Root CA",
			},
			Algorithm:    "rsa",
			RSABits:      4096,
			ValidityDays: 3650,
		}

		result, err := GenerateSelfSignedCA(req)
		require.NoError(t, err)

		rsaKey, ok := result.PrivateKey.(*rsa.PrivateKey)
		assert.True(t, ok)
		assert.Equal(t, 4096, rsaKey.N.BitLen())
	})

	t.Run("Generate ECDSA P256 CA successfully", func(t *testing.T) {
		req := &CARequest{
			FriendlyName: "Test ECDSA CA",
			Subject: pkix.Name{
				CommonName:   "Test ECDSA Root CA",
				Organization: []string{"Test Org"},
				Country:      []string{"US"},
			},
			Algorithm:    "ecdsa",
			ECCurve:      "P256",
			ValidityDays: 365,
		}

		result, err := GenerateSelfSignedCA(req)
		require.NoError(t, err)
		assert.NotNil(t, result.Certificate)
		assert.NotNil(t, result.PrivateKey)

		// Verify it's an ECDSA key
		_, ok := result.PrivateKey.(*ecdsa.PrivateKey)
		assert.True(t, ok, "Private key should be ECDSA")
	})

	t.Run("Generate ECDSA P384 CA successfully", func(t *testing.T) {
		req := &CARequest{
			FriendlyName: "Test ECDSA P384 CA",
			Subject: pkix.Name{
				CommonName: "Test ECDSA P384 Root CA",
			},
			Algorithm:    "ecdsa",
			ECCurve:      "P384",
			ValidityDays: 365,
		}

		result, err := GenerateSelfSignedCA(req)
		require.NoError(t, err)

		ecKey, ok := result.PrivateKey.(*ecdsa.PrivateKey)
		assert.True(t, ok)
		assert.Equal(t, 384, ecKey.Params().BitSize)
	})

	t.Run("Generate CA with unsupported algorithm fails", func(t *testing.T) {
		req := &CARequest{
			FriendlyName: "Test CA",
			Subject: pkix.Name{
				CommonName: "Test CA",
			},
			Algorithm:    "unsupported",
			ValidityDays: 365,
		}

		_, err := GenerateSelfSignedCA(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported algorithm")
	})

	t.Run("Generate CA with unsupported EC curve fails", func(t *testing.T) {
		req := &CARequest{
			FriendlyName: "Test CA",
			Subject: pkix.Name{
				CommonName: "Test CA",
			},
			Algorithm:    "ecdsa",
			ECCurve:      "P521", // Not supported
			ValidityDays: 365,
		}

		_, err := GenerateSelfSignedCA(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported EC curve")
	})

	t.Run("Verify CA certificate PEM format", func(t *testing.T) {
		req := &CARequest{
			FriendlyName: "Test CA",
			Subject: pkix.Name{
				CommonName: "Test CA",
			},
			Algorithm:    "rsa",
			RSABits:      2048,
			ValidityDays: 365,
		}

		result, err := GenerateSelfSignedCA(req)
		require.NoError(t, err)

		// Parse PEM
		block, _ := pem.Decode([]byte(result.CertificatePEM))
		assert.NotNil(t, block)
		assert.Equal(t, "CERTIFICATE", block.Type)

		// Parse certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		assert.Equal(t, result.Certificate.SerialNumber, cert.SerialNumber)
	})

	t.Run("Verify CA has proper key usage", func(t *testing.T) {
		req := &CARequest{
			FriendlyName: "Test CA",
			Subject: pkix.Name{
				CommonName: "Test CA",
			},
			Algorithm:    "rsa",
			RSABits:      2048,
			ValidityDays: 365,
		}

		result, err := GenerateSelfSignedCA(req)
		require.NoError(t, err)

		// Check key usage
		assert.True(t, result.Certificate.KeyUsage&x509.KeyUsageCertSign != 0)
		assert.True(t, result.Certificate.KeyUsage&x509.KeyUsageCRLSign != 0)
		assert.True(t, result.Certificate.KeyUsage&x509.KeyUsageDigitalSignature != 0)
	})

	t.Run("CA is self-signed", func(t *testing.T) {
		req := &CARequest{
			FriendlyName: "Test CA",
			Subject: pkix.Name{
				CommonName: "Test CA",
			},
			Algorithm:    "rsa",
			RSABits:      2048,
			ValidityDays: 365,
		}

		result, err := GenerateSelfSignedCA(req)
		require.NoError(t, err)

		// Issuer should equal subject for self-signed
		assert.Equal(t, result.Certificate.Subject.CommonName, result.Certificate.Issuer.CommonName)
	})
}

func TestImportCA(t *testing.T) {
	// Generate a CA to import
	req := &CARequest{
		FriendlyName: "Test CA",
		Subject: pkix.Name{
			CommonName:   "Test Import CA",
			Organization: []string{"Test Org"},
		},
		Algorithm:    "rsa",
		RSABits:      2048,
		ValidityDays: 365,
	}

	generated, err := GenerateSelfSignedCA(req)
	require.NoError(t, err)

	// Export private key as PEM
	keyDER, err := x509.MarshalPKCS8PrivateKey(generated.PrivateKey)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	t.Run("Import CA successfully", func(t *testing.T) {
		result, err := ImportCA([]byte(generated.CertificatePEM), keyPEM, "")
		require.NoError(t, err)
		assert.NotNil(t, result.Certificate)
		assert.NotNil(t, result.PrivateKey)
		assert.Equal(t, generated.Certificate.SerialNumber, result.Certificate.SerialNumber)
	})

	t.Run("Import CA with invalid certificate PEM fails", func(t *testing.T) {
		_, err := ImportCA([]byte("invalid pem"), keyPEM, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode certificate PEM")
	})

	t.Run("Import CA with invalid key PEM fails", func(t *testing.T) {
		_, err := ImportCA([]byte(generated.CertificatePEM), []byte("invalid pem"), "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode private key PEM")
	})

	t.Run("Import non-CA certificate fails", func(t *testing.T) {
		// Generate a regular certificate (not CA)
		certReq := &CertificateRequest{
			CommonName:   "example.com",
			Algorithm:    "rsa",
			RSABits:      2048,
			ValidityDays: 365,
		}

		cert, err := GenerateCertificate(certReq, generated.Certificate, generated.PrivateKey)
		require.NoError(t, err)

		certKeyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
		require.NoError(t, err)
		certKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: certKeyDER,
		})

		_, err = ImportCA([]byte(cert.CertificatePEM), certKeyPEM, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not a CA certificate")
	})

	t.Run("Import CA with mismatched key fails", func(t *testing.T) {
		// Generate a different key
		otherCA, err := GenerateSelfSignedCA(req)
		require.NoError(t, err)

		otherKeyDER, err := x509.MarshalPKCS8PrivateKey(otherCA.PrivateKey)
		require.NoError(t, err)
		otherKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: otherKeyDER,
		})

		_, err = ImportCA([]byte(generated.CertificatePEM), otherKeyPEM, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "private key does not match certificate")
	})

	t.Run("Import CA with PKCS1 RSA key", func(t *testing.T) {
		// Export as PKCS1
		rsaKey := generated.PrivateKey.(*rsa.PrivateKey)
		pkcs1DER := x509.MarshalPKCS1PrivateKey(rsaKey)
		pkcs1PEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: pkcs1DER,
		})

		result, err := ImportCA([]byte(generated.CertificatePEM), pkcs1PEM, "")
		require.NoError(t, err)
		assert.NotNil(t, result.PrivateKey)
	})

	t.Run("Import ECDSA CA successfully", func(t *testing.T) {
		ecReq := &CARequest{
			FriendlyName: "Test EC CA",
			Subject: pkix.Name{
				CommonName: "Test EC CA",
			},
			Algorithm:    "ecdsa",
			ECCurve:      "P256",
			ValidityDays: 365,
		}

		ecCA, err := GenerateSelfSignedCA(ecReq)
		require.NoError(t, err)

		ecKeyDER, err := x509.MarshalECPrivateKey(ecCA.PrivateKey.(*ecdsa.PrivateKey))
		require.NoError(t, err)
		ecKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: ecKeyDER,
		})

		result, err := ImportCA([]byte(ecCA.CertificatePEM), ecKeyPEM, "")
		require.NoError(t, err)
		assert.NotNil(t, result.PrivateKey)
		_, ok := result.PrivateKey.(*ecdsa.PrivateKey)
		assert.True(t, ok)
	})
}

func TestGetAlgorithmFromCert(t *testing.T) {
	t.Run("Detect RSA algorithm", func(t *testing.T) {
		req := &CARequest{
			FriendlyName: "Test CA",
			Subject: pkix.Name{
				CommonName: "Test CA",
			},
			Algorithm:    "rsa",
			RSABits:      2048,
			ValidityDays: 365,
		}

		result, err := GenerateSelfSignedCA(req)
		require.NoError(t, err)

		algo := GetAlgorithmFromCert(result.Certificate)
		assert.Equal(t, "rsa", algo)
	})

	t.Run("Detect ECDSA algorithm", func(t *testing.T) {
		req := &CARequest{
			FriendlyName: "Test CA",
			Subject: pkix.Name{
				CommonName: "Test CA",
			},
			Algorithm:    "ecdsa",
			ECCurve:      "P256",
			ValidityDays: 365,
		}

		result, err := GenerateSelfSignedCA(req)
		require.NoError(t, err)

		algo := GetAlgorithmFromCert(result.Certificate)
		assert.Equal(t, "ecdsa", algo)
	})
}

