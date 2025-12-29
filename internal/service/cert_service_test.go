package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateService_CreateCertificate(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	caService := NewCAService(db, cfg, userService)
	certService := NewCertificateService(db, caService, cfg, userService)
	
	// Perform setup
	setupReq := &SetupRequest{
		Username: "admin",
		Password: "password123",
	}
	_, err := userService.PerformInitialSetup(setupReq)
	require.NoError(t, err)
	
	// Create a CA first
	caReq := &CreateRootCARequest{
		FriendlyName: "Test CA",
		CommonName:   "Test CA",
	}
	ca, err := caService.CreateRootCA(caReq)
	require.NoError(t, err)
	
	t.Run("Create certificate successfully", func(t *testing.T) {
		req := &CreateCertificateRequest{
			AuthorityID:  ca.ID,
			CommonName:   "example.com",
			Organization: "Example Inc",
			Country:      "US",
			SANs:         []string{"www.example.com", "*.example.com"},
			IsServerAuth: true,
		}
		
		cert, err := certService.CreateCertificate(req)
		require.NoError(t, err)
		assert.NotEmpty(t, cert.ID)
		assert.Equal(t, "example.com", cert.CommonName)
		assert.Equal(t, ca.ID, cert.AuthorityID)
		assert.NotEmpty(t, cert.SerialNumber)
		assert.NotEmpty(t, cert.CertificatePEM)
		assert.NotEmpty(t, cert.PrivateKeyEnc)
		assert.False(t, cert.Revoked)
		assert.True(t, cert.IsServerAuth)
	})
	
	t.Run("Create certificate with defaults", func(t *testing.T) {
		req := &CreateCertificateRequest{
			AuthorityID: ca.ID,
			CommonName:  "default.com",
		}
		
		cert, err := certService.CreateCertificate(req)
		require.NoError(t, err)
		assert.NotEmpty(t, cert.ID)
		assert.Equal(t, "default.com", cert.CommonName)
	})
	
	t.Run("Create certificate with invalid CA fails", func(t *testing.T) {
		req := &CreateCertificateRequest{
			AuthorityID: "invalid-ca-id",
			CommonName:  "example.com",
		}
		
		_, err := certService.CreateCertificate(req)
		assert.Error(t, err)
	})
	
	t.Run("Create client auth certificate", func(t *testing.T) {
		req := &CreateCertificateRequest{
			AuthorityID:  ca.ID,
			CommonName:   "client.example.com",
			IsClientAuth: true,
		}
		
		cert, err := certService.CreateCertificate(req)
		require.NoError(t, err)
		assert.True(t, cert.IsClientAuth)
	})
}

func TestCertificateService_ListCertificates(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	caService := NewCAService(db, cfg, userService)
	certService := NewCertificateService(db, caService, cfg, userService)
	
	// Perform setup
	setupReq := &SetupRequest{
		Username: "admin",
		Password: "password123",
	}
	_, err := userService.PerformInitialSetup(setupReq)
	require.NoError(t, err)
	
	// Create a CA
	caReq := &CreateRootCARequest{
		FriendlyName: "Test CA",
		CommonName:   "Test CA",
	}
	ca, err := caService.CreateRootCA(caReq)
	require.NoError(t, err)
	
	t.Run("List certificates when empty", func(t *testing.T) {
		certs, err := certService.ListCertificates()
		require.NoError(t, err)
		assert.Empty(t, certs)
	})
	
	t.Run("List certificates after creating some", func(t *testing.T) {
		// Create two certificates
		for i := 1; i <= 2; i++ {
			req := &CreateCertificateRequest{
				AuthorityID: ca.ID,
				CommonName:  "cert" + string(rune('0'+i)) + ".com",
			}
			_, err := certService.CreateCertificate(req)
			require.NoError(t, err)
		}
		
		certs, err := certService.ListCertificates()
		require.NoError(t, err)
		assert.Len(t, certs, 2)
	})
}

func TestCertificateService_GetCertificate(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	caService := NewCAService(db, cfg, userService)
	certService := NewCertificateService(db, caService, cfg, userService)
	
	// Perform setup
	setupReq := &SetupRequest{
		Username: "admin",
		Password: "password123",
	}
	_, err := userService.PerformInitialSetup(setupReq)
	require.NoError(t, err)
	
	// Create a CA
	caReq := &CreateRootCARequest{
		FriendlyName: "Test CA",
		CommonName:   "Test CA",
	}
	ca, err := caService.CreateRootCA(caReq)
	require.NoError(t, err)
	
	// Create a certificate
	certReq := &CreateCertificateRequest{
		AuthorityID: ca.ID,
		CommonName:  "get-test.com",
	}
	cert, err := certService.CreateCertificate(certReq)
	require.NoError(t, err)
	
	t.Run("Get existing certificate", func(t *testing.T) {
		retrieved, err := certService.GetCertificate(cert.ID)
		require.NoError(t, err)
		assert.Equal(t, cert.ID, retrieved.ID)
		assert.Equal(t, cert.CommonName, retrieved.CommonName)
	})
	
	t.Run("Get non-existent certificate fails", func(t *testing.T) {
		_, err := certService.GetCertificate("non-existent-id")
		assert.Error(t, err)
	})
}

func TestCertificateService_RevokeCertificate(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	caService := NewCAService(db, cfg, userService)
	certService := NewCertificateService(db, caService, cfg, userService)
	
	// Perform setup
	setupReq := &SetupRequest{
		Username: "admin",
		Password: "password123",
	}
	_, err := userService.PerformInitialSetup(setupReq)
	require.NoError(t, err)
	
	// Create a CA
	caReq := &CreateRootCARequest{
		FriendlyName: "Test CA",
		CommonName:   "Test CA",
	}
	ca, err := caService.CreateRootCA(caReq)
	require.NoError(t, err)
	
	// Create a certificate
	certReq := &CreateCertificateRequest{
		AuthorityID: ca.ID,
		CommonName:  "revoke-test.com",
	}
	cert, err := certService.CreateCertificate(certReq)
	require.NoError(t, err)
	
	t.Run("Revoke certificate successfully", func(t *testing.T) {
		err := certService.RevokeCertificate(cert.ID)
		require.NoError(t, err)
		
		// Verify it's revoked
		retrieved, err := certService.GetCertificate(cert.ID)
		require.NoError(t, err)
		assert.True(t, retrieved.Revoked)
	})
}

func TestCertificateService_DeleteCertificate(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	caService := NewCAService(db, cfg, userService)
	certService := NewCertificateService(db, caService, cfg, userService)
	
	// Perform setup
	setupReq := &SetupRequest{
		Username: "admin",
		Password: "password123",
	}
	_, err := userService.PerformInitialSetup(setupReq)
	require.NoError(t, err)
	
	// Create a CA
	caReq := &CreateRootCARequest{
		FriendlyName: "Test CA",
		CommonName:   "Test CA",
	}
	ca, err := caService.CreateRootCA(caReq)
	require.NoError(t, err)
	
	// Create a certificate
	certReq := &CreateCertificateRequest{
		AuthorityID: ca.ID,
		CommonName:  "delete-test.com",
	}
	cert, err := certService.CreateCertificate(certReq)
	require.NoError(t, err)
	
	t.Run("Delete certificate successfully", func(t *testing.T) {
		err := certService.DeleteCertificate(cert.ID)
		require.NoError(t, err)
		
		// Verify it's deleted
		_, err = certService.GetCertificate(cert.ID)
		assert.Error(t, err)
	})
}

func TestCertificateService_ExportCertificate(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	caService := NewCAService(db, cfg, userService)
	certService := NewCertificateService(db, caService, cfg, userService)
	
	// Perform setup
	setupReq := &SetupRequest{
		Username: "admin",
		Password: "password123",
	}
	_, err := userService.PerformInitialSetup(setupReq)
	require.NoError(t, err)
	
	// Create a CA
	caReq := &CreateRootCARequest{
		FriendlyName: "Test CA",
		CommonName:   "Test CA",
	}
	ca, err := caService.CreateRootCA(caReq)
	require.NoError(t, err)
	
	// Create a certificate
	certReq := &CreateCertificateRequest{
		AuthorityID: ca.ID,
		CommonName:  "export-test.com",
	}
	cert, err := certService.CreateCertificate(certReq)
	require.NoError(t, err)
	
	t.Run("Export certificate as PEM", func(t *testing.T) {
		exportReq := &ExportRequest{
			CertificateID: cert.ID,
			Format:        "pem",
			SplitFiles:    false,
		}
		
		data, err := certService.ExportCertificate(exportReq)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
		assert.Contains(t, string(data), "BEGIN CERTIFICATE")
		assert.Contains(t, string(data), "BEGIN PRIVATE KEY")
	})
	
	t.Run("Export certificate as split PEM files", func(t *testing.T) {
		exportReq := &ExportRequest{
			CertificateID: cert.ID,
			Format:        "pem",
			SplitFiles:    true,
		}
		
		data, err := certService.ExportCertificate(exportReq)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
		// ZIP file starts with PK
		assert.Equal(t, byte('P'), data[0])
		assert.Equal(t, byte('K'), data[1])
	})
	
	t.Run("Export certificate as PKCS12", func(t *testing.T) {
		exportReq := &ExportRequest{
			CertificateID: cert.ID,
			Format:        "pkcs12",
			Password:      "test123",
			Legacy:        false,
		}
		
		data, err := certService.ExportCertificate(exportReq)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
	})
	
	t.Run("Export certificate as legacy PKCS12", func(t *testing.T) {
		exportReq := &ExportRequest{
			CertificateID: cert.ID,
			Format:        "pkcs12",
			Password:      "test123",
			Legacy:        true,
		}
		
		data, err := certService.ExportCertificate(exportReq)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
	})
	
	t.Run("Export with invalid format fails", func(t *testing.T) {
		exportReq := &ExportRequest{
			CertificateID: cert.ID,
			Format:        "invalid",
		}
		
		_, err := certService.ExportCertificate(exportReq)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported export format")
	})
}

func TestCertificateService_GetCertificateStatus(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	caService := NewCAService(db, cfg, userService)
	certService := NewCertificateService(db, caService, cfg, userService)
	
	// Perform setup
	setupReq := &SetupRequest{
		Username: "admin",
		Password: "password123",
	}
	_, err := userService.PerformInitialSetup(setupReq)
	require.NoError(t, err)
	
	// Create a CA
	caReq := &CreateRootCARequest{
		FriendlyName: "Test CA",
		CommonName:   "Test CA",
	}
	ca, err := caService.CreateRootCA(caReq)
	require.NoError(t, err)
	
	// Create a certificate
	certReq := &CreateCertificateRequest{
		AuthorityID: ca.ID,
		CommonName:  "status-test.com",
		SANs:        []string{"www.status-test.com"},
	}
	cert, err := certService.CreateCertificate(certReq)
	require.NoError(t, err)
	
	t.Run("Get certificate status", func(t *testing.T) {
		status, err := certService.GetCertificateStatus(cert.ID)
		require.NoError(t, err)
		assert.NotNil(t, status)
		assert.Equal(t, cert.ID, status.ID)
		assert.NotEmpty(t, status.Status)
		assert.Greater(t, status.DaysUntilExp, 0)
		assert.NotEmpty(t, status.SANs)
		assert.NotEmpty(t, status.IssuerName)
	})
	
	t.Run("Get status of revoked certificate", func(t *testing.T) {
		// Revoke the certificate
		err := certService.RevokeCertificate(cert.ID)
		require.NoError(t, err)
		
		status, err := certService.GetCertificateStatus(cert.ID)
		require.NoError(t, err)
		assert.Equal(t, "revoked", status.Status)
	})
}

func TestCertificateService_ListCertificatesWithStatus(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	caService := NewCAService(db, cfg, userService)
	certService := NewCertificateService(db, caService, cfg, userService)
	
	// Perform setup
	setupReq := &SetupRequest{
		Username: "admin",
		Password: "password123",
	}
	_, err := userService.PerformInitialSetup(setupReq)
	require.NoError(t, err)
	
	// Create a CA
	caReq := &CreateRootCARequest{
		FriendlyName: "Test CA",
		CommonName:   "Test CA",
	}
	ca, err := caService.CreateRootCA(caReq)
	require.NoError(t, err)
	
	// Create certificates
	for i := 1; i <= 2; i++ {
		certReq := &CreateCertificateRequest{
			AuthorityID: ca.ID,
			CommonName:  "cert" + string(rune('0'+i)) + ".com",
		}
		_, err := certService.CreateCertificate(certReq)
		require.NoError(t, err)
	}
	
	t.Run("List certificates with status", func(t *testing.T) {
		statuses, err := certService.ListCertificatesWithStatus()
		require.NoError(t, err)
		assert.Len(t, statuses, 2)
		for _, status := range statuses {
			assert.NotEmpty(t, status.Status)
			assert.NotEmpty(t, status.IssuerName)
		}
	})
}

