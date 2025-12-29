package database

import (
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/robcowart/ocm/internal/config"
	"github.com/robcowart/ocm/internal/database/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestDB creates a test database with migrations
func setupTestDB(t *testing.T) *Database {
	dbPath := t.TempDir() + "/test.db"
	
	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Type: "sqlite",
			SQLite: config.SQLiteConfig{
				Path: dbPath,
			},
		},
	}
	
	db, err := New(cfg)
	require.NoError(t, err, "Failed to create test database")
	
	err = db.Migrate()
	require.NoError(t, err, "Failed to run migrations")
	
	return db
}

func TestNew(t *testing.T) {
	t.Run("Create SQLite database successfully", func(t *testing.T) {
		dbPath := t.TempDir() + "/test.db"
		cfg := &config.Config{
			Database: config.DatabaseConfig{
				Type: "sqlite",
				SQLite: config.SQLiteConfig{
					Path: dbPath,
				},
			},
		}
		
		db, err := New(cfg)
		require.NoError(t, err)
		assert.NotNil(t, db)
		defer db.Close()
	})
	
	t.Run("Create with unsupported database type fails", func(t *testing.T) {
		cfg := &config.Config{
			Database: config.DatabaseConfig{
				Type: "unsupported",
			},
		}
		
		_, err := New(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported database type")
	})
}

func TestMigrate(t *testing.T) {
	t.Run("Run migrations successfully", func(t *testing.T) {
		dbPath := t.TempDir() + "/test.db"
		cfg := &config.Config{
			Database: config.DatabaseConfig{
				Type: "sqlite",
				SQLite: config.SQLiteConfig{
					Path: dbPath,
				},
			},
		}
		
		db, err := New(cfg)
		require.NoError(t, err)
		defer db.Close()
		
		err = db.Migrate()
		assert.NoError(t, err)
		
		// Verify tables were created
		var count int
		err = db.DB().QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").Scan(&count)
		require.NoError(t, err)
		assert.Greater(t, count, 0)
	})
	
	t.Run("Run migrations multiple times (idempotent)", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()
		
		// Run migrations again
		err := db.Migrate()
		assert.NoError(t, err)
	})
}

func TestDB(t *testing.T) {
	t.Run("Get underlying database connection", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()
		
		sqlDB := db.DB()
		assert.NotNil(t, sqlDB)
		
		// Verify it works
		err := sqlDB.Ping()
		assert.NoError(t, err)
	})
}

func TestCreateUser(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	t.Run("Create user successfully", func(t *testing.T) {
		user := &models.User{
			ID:           uuid.New().String(),
			Username:     "testuser",
			PasswordHash: "hash123",
			Role:         "admin",
			CreatedAt:    time.Now(),
		}
		
		err := db.CreateUser(user)
		assert.NoError(t, err)
	})
	
	t.Run("Create duplicate username fails", func(t *testing.T) {
		user := &models.User{
			ID:           uuid.New().String(),
			Username:     "duplicate",
			PasswordHash: "hash123",
			Role:         "admin",
			CreatedAt:    time.Now(),
		}
		
		err := db.CreateUser(user)
		require.NoError(t, err)
		
		// Try to create again with different ID but same username
		user2 := &models.User{
			ID:           uuid.New().String(),
			Username:     "duplicate",
			PasswordHash: "hash456",
			Role:         "user",
			CreatedAt:    time.Now(),
		}
		
		err = db.CreateUser(user2)
		assert.Error(t, err)
	})
}

func TestGetUserByUsername(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	// Create a user first
	user := &models.User{
		ID:           uuid.New().String(),
		Username:     "gettest",
		PasswordHash: "hash123",
		Role:         "admin",
		CreatedAt:    time.Now(),
	}
	err := db.CreateUser(user)
	require.NoError(t, err)
	
	t.Run("Get existing user", func(t *testing.T) {
		retrieved, err := db.GetUserByUsername("gettest")
		require.NoError(t, err)
		assert.Equal(t, user.ID, retrieved.ID)
		assert.Equal(t, user.Username, retrieved.Username)
		assert.Equal(t, user.PasswordHash, retrieved.PasswordHash)
		assert.Equal(t, user.Role, retrieved.Role)
	})
	
	t.Run("Get non-existent user fails", func(t *testing.T) {
		_, err := db.GetUserByUsername("nonexistent")
		assert.Error(t, err)
		assert.Equal(t, sql.ErrNoRows, err)
	})
}

func TestCreateAuthority(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	t.Run("Create authority successfully", func(t *testing.T) {
		auth := &models.Authority{
			ID:             uuid.New().String(),
			FriendlyName:   "Test CA",
			CommonName:     "Test CA",
			SerialNumber:   "123456",
			NotBefore:      time.Now(),
			NotAfter:       time.Now().Add(365 * 24 * time.Hour),
			CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			PrivateKeyEnc:  []byte("encrypted"),
			IssuerID:       sql.NullString{Valid: false},
			IsRoot:         true,
			CreatedAt:      time.Now(),
		}
		
		err := db.CreateAuthority(auth)
		assert.NoError(t, err)
	})
	
	t.Run("Create authority with duplicate serial number fails", func(t *testing.T) {
		serialNum := "duplicate-serial"
		auth1 := &models.Authority{
			ID:             uuid.New().String(),
			FriendlyName:   "CA 1",
			CommonName:     "CA 1",
			SerialNumber:   serialNum,
			NotBefore:      time.Now(),
			NotAfter:       time.Now().Add(365 * 24 * time.Hour),
			CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			PrivateKeyEnc:  []byte("encrypted"),
			IssuerID:       sql.NullString{Valid: false},
			IsRoot:         true,
			CreatedAt:      time.Now(),
		}
		
		err := db.CreateAuthority(auth1)
		require.NoError(t, err)
		
		// Try to create another with same serial number
		auth2 := &models.Authority{
			ID:             uuid.New().String(),
			FriendlyName:   "CA 2",
			CommonName:     "CA 2",
			SerialNumber:   serialNum,
			NotBefore:      time.Now(),
			NotAfter:       time.Now().Add(365 * 24 * time.Hour),
			CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			PrivateKeyEnc:  []byte("encrypted"),
			IssuerID:       sql.NullString{Valid: false},
			IsRoot:         true,
			CreatedAt:      time.Now(),
		}
		
		err = db.CreateAuthority(auth2)
		assert.Error(t, err)
	})
}

func TestGetAuthority(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	// Create an authority first
	auth := &models.Authority{
		ID:             uuid.New().String(),
		FriendlyName:   "Get Test CA",
		CommonName:     "Get Test CA",
		SerialNumber:   "get-serial",
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		PrivateKeyEnc:  []byte("encrypted"),
		IssuerID:       sql.NullString{Valid: false},
		IsRoot:         true,
		CreatedAt:      time.Now(),
	}
	err := db.CreateAuthority(auth)
	require.NoError(t, err)
	
	t.Run("Get existing authority", func(t *testing.T) {
		retrieved, err := db.GetAuthority(auth.ID)
		require.NoError(t, err)
		assert.Equal(t, auth.ID, retrieved.ID)
		assert.Equal(t, auth.FriendlyName, retrieved.FriendlyName)
		assert.Equal(t, auth.CommonName, retrieved.CommonName)
		assert.Equal(t, auth.SerialNumber, retrieved.SerialNumber)
		assert.Equal(t, auth.IsRoot, retrieved.IsRoot)
	})
	
	t.Run("Get non-existent authority fails", func(t *testing.T) {
		_, err := db.GetAuthority("non-existent-id")
		assert.Error(t, err)
		assert.Equal(t, sql.ErrNoRows, err)
	})
}

func TestListAuthorities(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	t.Run("List authorities when empty", func(t *testing.T) {
		authorities, err := db.ListAuthorities()
		require.NoError(t, err)
		assert.Empty(t, authorities)
	})
	
	t.Run("List authorities after creating some", func(t *testing.T) {
		// Create two authorities
		for i := 1; i <= 2; i++ {
			auth := &models.Authority{
				ID:             uuid.New().String(),
				FriendlyName:   "CA " + string(rune('0'+i)),
				CommonName:     "CA " + string(rune('0'+i)),
				SerialNumber:   "serial-" + string(rune('0'+i)),
				NotBefore:      time.Now(),
				NotAfter:       time.Now().Add(365 * 24 * time.Hour),
				CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
				PrivateKeyEnc:  []byte("encrypted"),
				IssuerID:       sql.NullString{Valid: false},
				IsRoot:         true,
				CreatedAt:      time.Now().Add(time.Duration(i) * time.Second),
			}
			err := db.CreateAuthority(auth)
			require.NoError(t, err)
		}
		
		authorities, err := db.ListAuthorities()
		require.NoError(t, err)
		assert.Len(t, authorities, 2)
		// Should be ordered by created_at DESC
		assert.Contains(t, authorities[0].FriendlyName, "CA")
	})
}

func TestDeleteAuthority(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	// Create an authority
	auth := &models.Authority{
		ID:             uuid.New().String(),
		FriendlyName:   "Delete Test CA",
		CommonName:     "Delete Test CA",
		SerialNumber:   "delete-serial",
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		PrivateKeyEnc:  []byte("encrypted"),
		IssuerID:       sql.NullString{Valid: false},
		IsRoot:         true,
		CreatedAt:      time.Now(),
	}
	err := db.CreateAuthority(auth)
	require.NoError(t, err)
	
	t.Run("Delete existing authority", func(t *testing.T) {
		err := db.DeleteAuthority(auth.ID)
		assert.NoError(t, err)
		
		// Verify it's deleted
		_, err = db.GetAuthority(auth.ID)
		assert.Error(t, err)
		assert.Equal(t, sql.ErrNoRows, err)
	})
	
	t.Run("Delete non-existent authority fails", func(t *testing.T) {
		err := db.DeleteAuthority("non-existent-id")
		assert.Error(t, err)
		assert.Equal(t, sql.ErrNoRows, err)
	})
}

func TestCreateCertificate(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	// Create an authority first for foreign key
	auth := &models.Authority{
		ID:             uuid.New().String(),
		FriendlyName:   "Test CA",
		CommonName:     "Test CA",
		SerialNumber:   "ca-serial",
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		PrivateKeyEnc:  []byte("encrypted"),
		IssuerID:       sql.NullString{Valid: false},
		IsRoot:         true,
		CreatedAt:      time.Now(),
	}
	err := db.CreateAuthority(auth)
	require.NoError(t, err)
	
	t.Run("Create certificate successfully", func(t *testing.T) {
		cert := &models.Certificate{
			ID:               uuid.New().String(),
			AuthorityID:      auth.ID,
			CommonName:       "example.com",
			SANsJSON:         `["www.example.com"]`,
			SerialNumber:     "cert-serial-1",
			CertificatePEM:   "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			PrivateKeyEnc:    []byte("encrypted"),
			Revoked:          false,
			RevokedAt:        sql.NullTime{Valid: false},
			NotBefore:        time.Now(),
			NotAfter:         time.Now().Add(365 * 24 * time.Hour),
			CreatedAt:        time.Now(),
			Organization:     sql.NullString{String: "Test Org", Valid: true},
			OrganizationUnit: sql.NullString{Valid: false},
			Country:          sql.NullString{String: "US", Valid: true},
			Province:         sql.NullString{Valid: false},
			Locality:         sql.NullString{Valid: false},
			Algorithm:        "rsa",
			KeySize:          sql.NullInt64{Int64: 2048, Valid: true},
			ECCurve:          sql.NullString{Valid: false},
			ValidityDays:     365,
			IsServerAuth:     true,
			IsClientAuth:     false,
		}
		
		err := db.CreateCertificate(cert)
		assert.NoError(t, err)
	})
	
	t.Run("Create certificate with duplicate serial number fails", func(t *testing.T) {
		serialNum := "dup-cert-serial"
		cert1 := &models.Certificate{
			ID:             uuid.New().String(),
			AuthorityID:    auth.ID,
			CommonName:     "cert1.com",
			SerialNumber:   serialNum,
			CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			PrivateKeyEnc:  []byte("encrypted"),
			NotBefore:      time.Now(),
			NotAfter:       time.Now().Add(365 * 24 * time.Hour),
			CreatedAt:      time.Now(),
			Algorithm:      "rsa",
			ValidityDays:   365,
		}
		
		err := db.CreateCertificate(cert1)
		require.NoError(t, err)
		
		// Try to create another with same serial number
		cert2 := &models.Certificate{
			ID:             uuid.New().String(),
			AuthorityID:    auth.ID,
			CommonName:     "cert2.com",
			SerialNumber:   serialNum,
			CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			PrivateKeyEnc:  []byte("encrypted"),
			NotBefore:      time.Now(),
			NotAfter:       time.Now().Add(365 * 24 * time.Hour),
			CreatedAt:      time.Now(),
			Algorithm:      "rsa",
			ValidityDays:   365,
		}
		
		err = db.CreateCertificate(cert2)
		assert.Error(t, err)
	})
}

func TestGetCertificate(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	// Create authority and certificate
	auth := &models.Authority{
		ID:             uuid.New().String(),
		FriendlyName:   "Test CA",
		CommonName:     "Test CA",
		SerialNumber:   "ca-serial",
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		PrivateKeyEnc:  []byte("encrypted"),
		IssuerID:       sql.NullString{Valid: false},
		IsRoot:         true,
		CreatedAt:      time.Now(),
	}
	err := db.CreateAuthority(auth)
	require.NoError(t, err)
	
	cert := &models.Certificate{
		ID:             uuid.New().String(),
		AuthorityID:    auth.ID,
		CommonName:     "get-test.com",
		SerialNumber:   "get-cert-serial",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		PrivateKeyEnc:  []byte("encrypted"),
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		CreatedAt:      time.Now(),
		Algorithm:      "rsa",
		ValidityDays:   365,
		IsServerAuth:   true,
	}
	err = db.CreateCertificate(cert)
	require.NoError(t, err)
	
	t.Run("Get existing certificate", func(t *testing.T) {
		retrieved, err := db.GetCertificate(cert.ID)
		require.NoError(t, err)
		assert.Equal(t, cert.ID, retrieved.ID)
		assert.Equal(t, cert.CommonName, retrieved.CommonName)
		assert.Equal(t, cert.SerialNumber, retrieved.SerialNumber)
		assert.Equal(t, cert.IsServerAuth, retrieved.IsServerAuth)
	})
	
	t.Run("Get non-existent certificate fails", func(t *testing.T) {
		_, err := db.GetCertificate("non-existent-id")
		assert.Error(t, err)
		assert.Equal(t, sql.ErrNoRows, err)
	})
}

func TestListCertificates(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	// Create authority
	auth := &models.Authority{
		ID:             uuid.New().String(),
		FriendlyName:   "Test CA",
		CommonName:     "Test CA",
		SerialNumber:   "ca-serial",
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		PrivateKeyEnc:  []byte("encrypted"),
		IssuerID:       sql.NullString{Valid: false},
		IsRoot:         true,
		CreatedAt:      time.Now(),
	}
	err := db.CreateAuthority(auth)
	require.NoError(t, err)
	
	t.Run("List certificates when empty", func(t *testing.T) {
		certificates, err := db.ListCertificates()
		require.NoError(t, err)
		assert.Empty(t, certificates)
	})
	
	t.Run("List certificates after creating some", func(t *testing.T) {
		// Create two certificates
		for i := 1; i <= 2; i++ {
			cert := &models.Certificate{
				ID:             uuid.New().String(),
				AuthorityID:    auth.ID,
				CommonName:     "cert" + string(rune('0'+i)) + ".com",
				SerialNumber:   "cert-serial-" + string(rune('0'+i)),
				CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
				PrivateKeyEnc:  []byte("encrypted"),
				NotBefore:      time.Now(),
				NotAfter:       time.Now().Add(365 * 24 * time.Hour),
				CreatedAt:      time.Now().Add(time.Duration(i) * time.Second),
				Algorithm:      "rsa",
				ValidityDays:   365,
			}
			err := db.CreateCertificate(cert)
			require.NoError(t, err)
		}
		
		certificates, err := db.ListCertificates()
		require.NoError(t, err)
		assert.Len(t, certificates, 2)
	})
}

func TestRevokeCertificate(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	// Create authority and certificate
	auth := &models.Authority{
		ID:             uuid.New().String(),
		FriendlyName:   "Test CA",
		CommonName:     "Test CA",
		SerialNumber:   "ca-serial",
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		PrivateKeyEnc:  []byte("encrypted"),
		IssuerID:       sql.NullString{Valid: false},
		IsRoot:         true,
		CreatedAt:      time.Now(),
	}
	err := db.CreateAuthority(auth)
	require.NoError(t, err)
	
	cert := &models.Certificate{
		ID:             uuid.New().String(),
		AuthorityID:    auth.ID,
		CommonName:     "revoke-test.com",
		SerialNumber:   "revoke-cert-serial",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		PrivateKeyEnc:  []byte("encrypted"),
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		CreatedAt:      time.Now(),
		Algorithm:      "rsa",
		ValidityDays:   365,
	}
	err = db.CreateCertificate(cert)
	require.NoError(t, err)
	
	t.Run("Revoke certificate successfully", func(t *testing.T) {
		err := db.RevokeCertificate(cert.ID)
		assert.NoError(t, err)
		
		// Verify it's revoked
		retrieved, err := db.GetCertificate(cert.ID)
		require.NoError(t, err)
		assert.True(t, retrieved.Revoked)
	})
}

func TestDeleteCertificate(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	// Create authority and certificate
	auth := &models.Authority{
		ID:             uuid.New().String(),
		FriendlyName:   "Test CA",
		CommonName:     "Test CA",
		SerialNumber:   "ca-serial",
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		PrivateKeyEnc:  []byte("encrypted"),
		IssuerID:       sql.NullString{Valid: false},
		IsRoot:         true,
		CreatedAt:      time.Now(),
	}
	err := db.CreateAuthority(auth)
	require.NoError(t, err)
	
	cert := &models.Certificate{
		ID:             uuid.New().String(),
		AuthorityID:    auth.ID,
		CommonName:     "delete-test.com",
		SerialNumber:   "delete-cert-serial",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		PrivateKeyEnc:  []byte("encrypted"),
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		CreatedAt:      time.Now(),
		Algorithm:      "rsa",
		ValidityDays:   365,
	}
	err = db.CreateCertificate(cert)
	require.NoError(t, err)
	
	t.Run("Delete existing certificate", func(t *testing.T) {
		err := db.DeleteCertificate(cert.ID)
		assert.NoError(t, err)
		
		// Verify it's deleted
		_, err = db.GetCertificate(cert.ID)
		assert.Error(t, err)
		assert.Equal(t, sql.ErrNoRows, err)
	})
	
	t.Run("Delete non-existent certificate fails", func(t *testing.T) {
		err := db.DeleteCertificate("non-existent-id")
		assert.Error(t, err)
		assert.Equal(t, sql.ErrNoRows, err)
	})
}

func TestSetSystemConfig(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	t.Run("Set system config successfully", func(t *testing.T) {
		err := db.SetSystemConfig("test_key", "test_value")
		assert.NoError(t, err)
	})
	
	t.Run("Update existing system config", func(t *testing.T) {
		err := db.SetSystemConfig("update_key", "initial_value")
		require.NoError(t, err)
		
		// Update with new value
		err = db.SetSystemConfig("update_key", "updated_value")
		assert.NoError(t, err)
		
		// Verify the value was updated
		value, err := db.GetSystemConfig("update_key")
		require.NoError(t, err)
		assert.Equal(t, "updated_value", value)
	})
}

func TestGetSystemConfig(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	// Set a config value first
	err := db.SetSystemConfig("get_test_key", "get_test_value")
	require.NoError(t, err)
	
	t.Run("Get existing system config", func(t *testing.T) {
		value, err := db.GetSystemConfig("get_test_key")
		require.NoError(t, err)
		assert.Equal(t, "get_test_value", value)
	})
	
	t.Run("Get non-existent system config fails", func(t *testing.T) {
		_, err := db.GetSystemConfig("non_existent_key")
		assert.Error(t, err)
		assert.Equal(t, sql.ErrNoRows, err)
	})
}

func TestIsSetupComplete(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	t.Run("Setup not complete when no users", func(t *testing.T) {
		isComplete, err := db.IsSetupComplete()
		require.NoError(t, err)
		assert.False(t, isComplete)
	})
	
	t.Run("Setup complete when users exist", func(t *testing.T) {
		user := &models.User{
			ID:           uuid.New().String(),
			Username:     "setuptest",
			PasswordHash: "hash123",
			Role:         "admin",
			CreatedAt:    time.Now(),
		}
		err := db.CreateUser(user)
		require.NoError(t, err)
		
		isComplete, err := db.IsSetupComplete()
		require.NoError(t, err)
		assert.True(t, isComplete)
	})
}

