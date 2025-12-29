package crypto

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCertificate(t *testing.T) {
	// Generate a CA first for signing
	caReq := &CARequest{
		FriendlyName: "Test CA",
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		Algorithm:    "rsa",
		RSABits:      2048,
		ValidityDays: 3650,
	}

	ca, err := GenerateSelfSignedCA(caReq)
	require.NoError(t, err)

	t.Run("Generate RSA certificate successfully", func(t *testing.T) {
		req := &CertificateRequest{
			CommonName:   "example.com",
			Organization: []string{"Example Org"},
			Country:      []string{"US"},
			SANs:         []string{"www.example.com", "*.example.com"},
			Algorithm:    "rsa",
			RSABits:      2048,
			ValidityDays: 365,
			IsServerAuth: true,
		}

		result, err := GenerateCertificate(req, ca.Certificate, ca.PrivateKey)
		require.NoError(t, err)
		assert.NotNil(t, result.Certificate)
		assert.NotNil(t, result.PrivateKey)
		assert.NotEmpty(t, result.CertificatePEM)
		assert.NotEmpty(t, result.PrivateKeyDER)
		assert.NotEmpty(t, result.SerialNumber)

		// Verify it's an RSA key
		_, ok := result.PrivateKey.(*rsa.PrivateKey)
		assert.True(t, ok, "Private key should be RSA")

		// Verify certificate properties
		assert.False(t, result.Certificate.IsCA)
		assert.Equal(t, "example.com", result.Certificate.Subject.CommonName)
		assert.Contains(t, result.Certificate.DNSNames, "www.example.com")
		assert.Contains(t, result.Certificate.DNSNames, "*.example.com")
	})

	t.Run("Generate ECDSA certificate successfully", func(t *testing.T) {
		req := &CertificateRequest{
			CommonName:   "example.com",
			Algorithm:    "ecdsa",
			ECCurve:      "P256",
			ValidityDays: 365,
			IsServerAuth: true,
		}

		result, err := GenerateCertificate(req, ca.Certificate, ca.PrivateKey)
		require.NoError(t, err)

		// Verify it's an ECDSA key
		_, ok := result.PrivateKey.(*ecdsa.PrivateKey)
		assert.True(t, ok, "Private key should be ECDSA")
	})

	t.Run("Generate certificate with IP SANs", func(t *testing.T) {
		req := &CertificateRequest{
			CommonName:   "example.com",
			SANs:         []string{"192.168.1.1", "10.0.0.1", "example.com"},
			Algorithm:    "rsa",
			RSABits:      2048,
			ValidityDays: 365,
			IsServerAuth: true,
		}

		result, err := GenerateCertificate(req, ca.Certificate, ca.PrivateKey)
		require.NoError(t, err)

		// Verify IP addresses are parsed correctly
		assert.Len(t, result.Certificate.IPAddresses, 2)
		assert.Equal(t, "192.168.1.1", result.Certificate.IPAddresses[0].String())
		assert.Equal(t, "10.0.0.1", result.Certificate.IPAddresses[1].String())

		// Verify DNS name
		assert.Contains(t, result.Certificate.DNSNames, "example.com")
	})

	t.Run("Generate certificate with server auth", func(t *testing.T) {
		req := &CertificateRequest{
			CommonName:   "server.example.com",
			Algorithm:    "rsa",
			RSABits:      2048,
			ValidityDays: 365,
			IsServerAuth: true,
			IsClientAuth: false,
		}

		result, err := GenerateCertificate(req, ca.Certificate, ca.PrivateKey)
		require.NoError(t, err)

		assert.Contains(t, result.Certificate.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		assert.NotContains(t, result.Certificate.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	})

	t.Run("Generate certificate with client auth", func(t *testing.T) {
		req := &CertificateRequest{
			CommonName:   "client.example.com",
			Algorithm:    "rsa",
			RSABits:      2048,
			ValidityDays: 365,
			IsServerAuth: false,
			IsClientAuth: true,
		}

		result, err := GenerateCertificate(req, ca.Certificate, ca.PrivateKey)
		require.NoError(t, err)

		assert.Contains(t, result.Certificate.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		assert.NotContains(t, result.Certificate.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	})

	t.Run("Generate certificate with both server and client auth", func(t *testing.T) {
		req := &CertificateRequest{
			CommonName:   "dual.example.com",
			Algorithm:    "rsa",
			RSABits:      2048,
			ValidityDays: 365,
			IsServerAuth: true,
			IsClientAuth: true,
		}

		result, err := GenerateCertificate(req, ca.Certificate, ca.PrivateKey)
		require.NoError(t, err)

		assert.Contains(t, result.Certificate.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		assert.Contains(t, result.Certificate.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	})

	t.Run("Generate certificate defaults to server auth", func(t *testing.T) {
		req := &CertificateRequest{
			CommonName:   "default.example.com",
			Algorithm:    "rsa",
			RSABits:      2048,
			ValidityDays: 365,
			IsServerAuth: false,
			IsClientAuth: false,
		}

		result, err := GenerateCertificate(req, ca.Certificate, ca.PrivateKey)
		require.NoError(t, err)

		// Should default to server auth
		assert.Contains(t, result.Certificate.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	})

	t.Run("Generate certificate with full subject details", func(t *testing.T) {
		req := &CertificateRequest{
			CommonName:       "example.com",
			Organization:     []string{"Example Org", "Example Subsidiary"},
			OrganizationUnit: []string{"Engineering", "Security"},
			Country:          []string{"US"},
			Province:         []string{"California"},
			Locality:         []string{"San Francisco"},
			Algorithm:        "rsa",
			RSABits:          2048,
			ValidityDays:     365,
			IsServerAuth:     true,
		}

		result, err := GenerateCertificate(req, ca.Certificate, ca.PrivateKey)
		require.NoError(t, err)

		assert.Equal(t, "example.com", result.Certificate.Subject.CommonName)
		assert.Equal(t, req.Organization, result.Certificate.Subject.Organization)
		// OrganizationalUnit order may vary, just check that both are present
		assert.ElementsMatch(t, req.OrganizationUnit, result.Certificate.Subject.OrganizationalUnit)
		assert.Equal(t, req.Country, result.Certificate.Subject.Country)
		assert.Equal(t, req.Province, result.Certificate.Subject.Province)
		assert.Equal(t, req.Locality, result.Certificate.Subject.Locality)
	})

	t.Run("Generate certificate with unsupported algorithm fails", func(t *testing.T) {
		req := &CertificateRequest{
			CommonName:   "example.com",
			Algorithm:    "unsupported",
			ValidityDays: 365,
		}

		_, err := GenerateCertificate(req, ca.Certificate, ca.PrivateKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported algorithm")
	})

	t.Run("Certificate is signed by CA", func(t *testing.T) {
		req := &CertificateRequest{
			CommonName:   "example.com",
			Algorithm:    "rsa",
			RSABits:      2048,
			ValidityDays: 365,
			IsServerAuth: true,
		}

		result, err := GenerateCertificate(req, ca.Certificate, ca.PrivateKey)
		require.NoError(t, err)

		// Issuer should be the CA
		assert.Equal(t, ca.Certificate.Subject.CommonName, result.Certificate.Issuer.CommonName)
	})

	t.Run("Certificate has proper key usage", func(t *testing.T) {
		req := &CertificateRequest{
			CommonName:   "example.com",
			Algorithm:    "rsa",
			RSABits:      2048,
			ValidityDays: 365,
			IsServerAuth: true,
		}

		result, err := GenerateCertificate(req, ca.Certificate, ca.PrivateKey)
		require.NoError(t, err)

		// Check key usage
		assert.True(t, result.Certificate.KeyUsage&x509.KeyUsageDigitalSignature != 0)
		assert.True(t, result.Certificate.KeyUsage&x509.KeyUsageKeyEncipherment != 0)
	})
}

func TestGenerateCertificate_ECDSA_CA(t *testing.T) {
	// Generate an ECDSA CA
	caReq := &CARequest{
		FriendlyName: "Test ECDSA CA",
		Subject: pkix.Name{
			CommonName: "Test ECDSA Root CA",
		},
		Algorithm:    "ecdsa",
		ECCurve:      "P256",
		ValidityDays: 3650,
	}

	ca, err := GenerateSelfSignedCA(caReq)
	require.NoError(t, err)

	t.Run("Generate certificate signed by ECDSA CA", func(t *testing.T) {
		req := &CertificateRequest{
			CommonName:   "example.com",
			Algorithm:    "ecdsa",
			ECCurve:      "P256",
			ValidityDays: 365,
			IsServerAuth: true,
		}

		result, err := GenerateCertificate(req, ca.Certificate, ca.PrivateKey)
		require.NoError(t, err)
		assert.NotNil(t, result.Certificate)

		_, ok := result.PrivateKey.(*ecdsa.PrivateKey)
		assert.True(t, ok)
	})

	t.Run("Generate RSA certificate signed by ECDSA CA", func(t *testing.T) {
		req := &CertificateRequest{
			CommonName:   "example.com",
			Algorithm:    "rsa",
			RSABits:      2048,
			ValidityDays: 365,
			IsServerAuth: true,
		}

		result, err := GenerateCertificate(req, ca.Certificate, ca.PrivateKey)
		require.NoError(t, err)
		assert.NotNil(t, result.Certificate)

		_, ok := result.PrivateKey.(*rsa.PrivateKey)
		assert.True(t, ok)
	})
}

func TestParsePrivateKey(t *testing.T) {
	t.Run("Parse RSA private key", func(t *testing.T) {
		caReq := &CARequest{
			FriendlyName: "Test CA",
			Subject: pkix.Name{
				CommonName: "Test CA",
			},
			Algorithm:    "rsa",
			RSABits:      2048,
			ValidityDays: 365,
		}

		ca, err := GenerateSelfSignedCA(caReq)
		require.NoError(t, err)

		key, err := ParsePrivateKey(ca.PrivateKeyDER, "rsa")
		require.NoError(t, err)

		_, ok := key.(*rsa.PrivateKey)
		assert.True(t, ok)
	})

	t.Run("Parse ECDSA private key", func(t *testing.T) {
		caReq := &CARequest{
			FriendlyName: "Test CA",
			Subject: pkix.Name{
				CommonName: "Test CA",
			},
			Algorithm:    "ecdsa",
			ECCurve:      "P256",
			ValidityDays: 365,
		}

		ca, err := GenerateSelfSignedCA(caReq)
		require.NoError(t, err)

		key, err := ParsePrivateKey(ca.PrivateKeyDER, "ecdsa")
		require.NoError(t, err)

		_, ok := key.(*ecdsa.PrivateKey)
		assert.True(t, ok)
	})

	t.Run("Parse with unsupported algorithm fails", func(t *testing.T) {
		_, err := ParsePrivateKey([]byte{}, "unsupported")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported algorithm")
	})

	t.Run("Parse with invalid DER fails", func(t *testing.T) {
		_, err := ParsePrivateKey([]byte("invalid"), "rsa")
		assert.Error(t, err)
	})
}
