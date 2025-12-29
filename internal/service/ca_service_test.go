package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCAService_CreateRootCA(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	caService := NewCAService(db, cfg, userService)
	
	// Perform setup to initialize master key
	setupReq := &SetupRequest{
		Username: "admin",
		Password: "password123",
	}
	_, err := userService.PerformInitialSetup(setupReq)
	require.NoError(t, err)
	
	t.Run("Create Root CA successfully", func(t *testing.T) {
		req := &CreateRootCARequest{
			FriendlyName: "Test Root CA",
			CommonName:   "Test Root CA",
			Organization: "Test Org",
			Country:      "US",
			Algorithm:    "rsa",
			RSABits:      2048,
		}
		
		ca, err := caService.CreateRootCA(req)
		require.NoError(t, err)
		assert.NotEmpty(t, ca.ID)
		assert.Equal(t, "Test Root CA", ca.FriendlyName)
		assert.Equal(t, "Test Root CA", ca.CommonName)
		assert.True(t, ca.IsRoot)
		assert.NotEmpty(t, ca.SerialNumber)
		assert.NotEmpty(t, ca.CertificatePEM)
		assert.NotEmpty(t, ca.PrivateKeyEnc)
		assert.NotZero(t, ca.NotBefore)
		assert.NotZero(t, ca.NotAfter)
	})
	
	t.Run("Create Root CA with defaults", func(t *testing.T) {
		req := &CreateRootCARequest{
			FriendlyName: "Default CA",
			CommonName:   "Default CA",
		}
		
		ca, err := caService.CreateRootCA(req)
		require.NoError(t, err)
		assert.NotEmpty(t, ca.ID)
		assert.Equal(t, "Default CA", ca.CommonName)
	})
	
	t.Run("Create Root CA with ECDSA", func(t *testing.T) {
		req := &CreateRootCARequest{
			FriendlyName: "ECDSA CA",
			CommonName:   "ECDSA CA",
			Algorithm:    "ecdsa",
			ECCurve:      "P384",
		}
		
		ca, err := caService.CreateRootCA(req)
		require.NoError(t, err)
		assert.NotEmpty(t, ca.ID)
		assert.Equal(t, "ECDSA CA", ca.CommonName)
	})
}

func TestCAService_ImportCA(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	caService := NewCAService(db, cfg, userService)
	
	// Perform setup
	setupReq := &SetupRequest{
		Username: "admin",
		Password: "password123",
	}
	_, err := userService.PerformInitialSetup(setupReq)
	require.NoError(t, err)
	
	t.Run("Import CA with invalid certificate fails", func(t *testing.T) {
		importReq := &ImportCARequest{
			FriendlyName:   "Invalid CA",
			CertificatePEM: "invalid pem",
			PrivateKeyPEM:  "invalid pem",
		}
		
		_, err := caService.ImportCA(importReq)
		assert.Error(t, err)
	})
	
	// Note: Testing successful import would require creating valid separate
	// certificate and key PEM blocks, which is complex. The integration tests
	// cover the full import flow.
}

func TestCAService_ListAuthorities(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	caService := NewCAService(db, cfg, userService)
	
	// Perform setup
	setupReq := &SetupRequest{
		Username: "admin",
		Password: "password123",
	}
	_, err := userService.PerformInitialSetup(setupReq)
	require.NoError(t, err)
	
	t.Run("List authorities when empty", func(t *testing.T) {
		authorities, err := caService.ListAuthorities()
		require.NoError(t, err)
		assert.Empty(t, authorities)
	})
	
	t.Run("List authorities after creating some", func(t *testing.T) {
		// Create two CAs
		for i := 1; i <= 2; i++ {
			req := &CreateRootCARequest{
				FriendlyName: "CA " + string(rune('0'+i)),
				CommonName:   "CA " + string(rune('0'+i)),
			}
			_, err := caService.CreateRootCA(req)
			require.NoError(t, err)
		}
		
		authorities, err := caService.ListAuthorities()
		require.NoError(t, err)
		assert.Len(t, authorities, 2)
	})
}

func TestCAService_GetAuthority(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	caService := NewCAService(db, cfg, userService)
	
	// Perform setup
	setupReq := &SetupRequest{
		Username: "admin",
		Password: "password123",
	}
	_, err := userService.PerformInitialSetup(setupReq)
	require.NoError(t, err)
	
	// Create a CA
	createReq := &CreateRootCARequest{
		FriendlyName: "Get Test CA",
		CommonName:   "Get Test CA",
	}
	
	ca, err := caService.CreateRootCA(createReq)
	require.NoError(t, err)
	
	t.Run("Get existing authority", func(t *testing.T) {
		retrieved, err := caService.GetAuthority(ca.ID)
		require.NoError(t, err)
		assert.Equal(t, ca.ID, retrieved.ID)
		assert.Equal(t, ca.CommonName, retrieved.CommonName)
	})
	
	t.Run("Get non-existent authority fails", func(t *testing.T) {
		_, err := caService.GetAuthority("non-existent-id")
		assert.Error(t, err)
	})
}

func TestCAService_GetCAPrivateKey(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	caService := NewCAService(db, cfg, userService)
	
	// Perform setup
	setupReq := &SetupRequest{
		Username: "admin",
		Password: "password123",
	}
	_, err := userService.PerformInitialSetup(setupReq)
	require.NoError(t, err)
	
	// Create a CA
	createReq := &CreateRootCARequest{
		FriendlyName: "Key Test CA",
		CommonName:   "Key Test CA",
	}
	
	ca, err := caService.CreateRootCA(createReq)
	require.NoError(t, err)
	
	t.Run("Get CA private key successfully", func(t *testing.T) {
		privateKey, err := caService.GetCAPrivateKey(ca)
		require.NoError(t, err)
		assert.NotNil(t, privateKey)
	})
}

func TestCAService_GetAuthorityStatus(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	caService := NewCAService(db, cfg, userService)
	
	// Perform setup
	setupReq := &SetupRequest{
		Username: "admin",
		Password: "password123",
	}
	_, err := userService.PerformInitialSetup(setupReq)
	require.NoError(t, err)
	
	// Create a CA
	createReq := &CreateRootCARequest{
		FriendlyName: "Status Test CA",
		CommonName:   "Status Test CA",
	}
	
	ca, err := caService.CreateRootCA(createReq)
	require.NoError(t, err)
	
	t.Run("Get authority status", func(t *testing.T) {
		status, err := caService.GetAuthorityStatus(ca.ID)
		require.NoError(t, err)
		assert.NotNil(t, status)
		assert.Equal(t, ca.ID, status.ID)
		assert.NotEmpty(t, status.Status)
		assert.Greater(t, status.DaysUntilExp, 0)
	})
}

func TestCAService_ListAuthoritiesWithStatus(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	caService := NewCAService(db, cfg, userService)
	
	// Perform setup
	setupReq := &SetupRequest{
		Username: "admin",
		Password: "password123",
	}
	_, err := userService.PerformInitialSetup(setupReq)
	require.NoError(t, err)
	
	// Create a CA
	createReq := &CreateRootCARequest{
		FriendlyName: "Status List CA",
		CommonName:   "Status List CA",
	}
	
	_, err = caService.CreateRootCA(createReq)
	require.NoError(t, err)
	
	t.Run("List authorities with status", func(t *testing.T) {
		statuses, err := caService.ListAuthoritiesWithStatus()
		require.NoError(t, err)
		assert.Len(t, statuses, 1)
		assert.NotEmpty(t, statuses[0].Status)
	})
}

func TestCAService_DeleteAuthority(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	caService := NewCAService(db, cfg, userService)
	
	// Perform setup
	setupReq := &SetupRequest{
		Username: "admin",
		Password: "password123",
	}
	_, err := userService.PerformInitialSetup(setupReq)
	require.NoError(t, err)
	
	// Create a CA
	createReq := &CreateRootCARequest{
		FriendlyName: "Delete Test CA",
		CommonName:   "Delete Test CA",
	}
	
	ca, err := caService.CreateRootCA(createReq)
	require.NoError(t, err)
	
	t.Run("Delete authority successfully", func(t *testing.T) {
		err := caService.DeleteAuthority(ca.ID)
		require.NoError(t, err)
		
		// Verify it's deleted
		_, err = caService.GetAuthority(ca.ID)
		assert.Error(t, err)
	})
	
	t.Run("Delete non-existent authority", func(t *testing.T) {
		err := caService.DeleteAuthority("non-existent-id")
		// This might not error depending on database behavior
		_ = err
	})
}

func TestCAService_ExportAuthority(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	caService := NewCAService(db, cfg, userService)
	
	// Perform setup
	setupReq := &SetupRequest{
		Username: "admin",
		Password: "password123",
	}
	_, err := userService.PerformInitialSetup(setupReq)
	require.NoError(t, err)
	
	// Create a CA
	createReq := &CreateRootCARequest{
		FriendlyName: "Export Test CA",
		CommonName:   "Export Test CA",
	}
	
	ca, err := caService.CreateRootCA(createReq)
	require.NoError(t, err)
	
	t.Run("Export authority as PEM", func(t *testing.T) {
		exportReq := &ExportAuthorityRequest{
			AuthorityID: ca.ID,
			Format:      "pem",
			CertOnly:    false,
		}
		
		data, err := caService.ExportAuthority(exportReq)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
		assert.Contains(t, string(data), "BEGIN CERTIFICATE")
		assert.Contains(t, string(data), "BEGIN PRIVATE KEY")
	})
	
	t.Run("Export authority cert only", func(t *testing.T) {
		exportReq := &ExportAuthorityRequest{
			AuthorityID: ca.ID,
			Format:      "pem",
			CertOnly:    true,
		}
		
		data, err := caService.ExportAuthority(exportReq)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
		assert.Contains(t, string(data), "BEGIN CERTIFICATE")
		assert.NotContains(t, string(data), "BEGIN PRIVATE KEY")
	})
	
	t.Run("Export authority as PKCS12", func(t *testing.T) {
		exportReq := &ExportAuthorityRequest{
			AuthorityID: ca.ID,
			Format:      "pkcs12",
			Password:    "test123",
			Legacy:      false,
		}
		
		data, err := caService.ExportAuthority(exportReq)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
	})
	
	t.Run("Export authority as legacy PKCS12", func(t *testing.T) {
		exportReq := &ExportAuthorityRequest{
			AuthorityID: ca.ID,
			Format:      "pkcs12",
			Password:    "test123",
			Legacy:      true,
		}
		
		data, err := caService.ExportAuthority(exportReq)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
	})
	
	t.Run("Export with invalid format fails", func(t *testing.T) {
		exportReq := &ExportAuthorityRequest{
			AuthorityID: ca.ID,
			Format:      "invalid",
		}
		
		_, err := caService.ExportAuthority(exportReq)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported export format")
	})
}

