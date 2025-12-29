package service

import (
	"testing"
	"time"

	"github.com/robcowart/ocm/internal/config"
	"github.com/robcowart/ocm/internal/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestDB creates a test database with migrations
func setupTestDB(t *testing.T) (*database.Database, *config.Config) {
	dbPath := t.TempDir() + "/test.db"
	
	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Type: "sqlite",
			SQLite: config.SQLiteConfig{
				Path: dbPath,
			},
		},
		JWT: config.JWTConfig{
			Secret:     "test-secret-12345",
			Expiration: 24 * time.Hour,
			Issuer:     "ocm-test",
		},
		Crypto: config.CryptoConfig{
			DefaultAlgorithm:      "rsa",
			DefaultCAValidity:     87600 * time.Hour,
			DefaultCertValidity:   8760 * time.Hour,
			DefaultRSABits:        2048,
			DefaultECCurve:        "P256",
		},
	}
	
	db, err := database.New(cfg)
	require.NoError(t, err, "Failed to create test database")
	
	err = db.Migrate()
	require.NoError(t, err, "Failed to run migrations")
	
	return db, cfg
}

func TestUserService_CreateUser(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	
	t.Run("Create user successfully", func(t *testing.T) {
		req := &CreateUserRequest{
			Username: "testuser",
			Password: "password123",
			Role:     "user",
		}
		
		user, err := userService.CreateUser(req)
		require.NoError(t, err)
		assert.NotEmpty(t, user.ID)
		assert.Equal(t, "testuser", user.Username)
		assert.Equal(t, "user", user.Role)
		assert.NotEmpty(t, user.PasswordHash)
		assert.NotZero(t, user.CreatedAt)
	})
	
	t.Run("Create user with weak password fails", func(t *testing.T) {
		req := &CreateUserRequest{
			Username: "testuser2",
			Password: "short",
			Role:     "user",
		}
		
		_, err := userService.CreateUser(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "weak password")
	})
	
	t.Run("Create duplicate username fails", func(t *testing.T) {
		req := &CreateUserRequest{
			Username: "duplicate",
			Password: "password123",
			Role:     "user",
		}
		
		_, err := userService.CreateUser(req)
		require.NoError(t, err)
		
		// Try to create again with same username
		_, err = userService.CreateUser(req)
		assert.Error(t, err)
	})
}

func TestUserService_AuthenticateUser(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	
	// Create a user first
	req := &CreateUserRequest{
		Username: "authuser",
		Password: "password123",
		Role:     "admin",
	}
	_, err := userService.CreateUser(req)
	require.NoError(t, err)
	
	t.Run("Authenticate with valid credentials", func(t *testing.T) {
		token, err := userService.AuthenticateUser("authuser", "password123")
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})
	
	t.Run("Authenticate with invalid password", func(t *testing.T) {
		_, err := userService.AuthenticateUser("authuser", "wrongpassword")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid credentials")
	})
	
	t.Run("Authenticate with non-existent user", func(t *testing.T) {
		_, err := userService.AuthenticateUser("nonexistent", "password123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid credentials")
	})
}

func TestUserService_PerformInitialSetup(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	
	t.Run("Perform initial setup successfully", func(t *testing.T) {
		req := &SetupRequest{
			Username: "admin",
			Password: "adminpass123",
		}
		
		response, err := userService.PerformInitialSetup(req)
		require.NoError(t, err)
		assert.NotNil(t, response.User)
		assert.Equal(t, "admin", response.User.Username)
		assert.Equal(t, "admin", response.User.Role)
		assert.NotEmpty(t, response.MasterKey)
		assert.NotEmpty(t, response.Token)
		
		// Verify master key is stored
		masterKey, err := userService.GetMasterKey()
		require.NoError(t, err)
		assert.Len(t, masterKey, 32) // AES-256 key
	})
	
	t.Run("Setup already complete fails", func(t *testing.T) {
		req := &SetupRequest{
			Username: "admin2",
			Password: "adminpass123",
		}
		
		_, err := userService.PerformInitialSetup(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "setup already complete")
	})
}

func TestUserService_IsSetupComplete(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	
	t.Run("Setup not complete initially", func(t *testing.T) {
		isComplete, err := userService.IsSetupComplete()
		require.NoError(t, err)
		assert.False(t, isComplete)
	})
	
	t.Run("Setup complete after creating user", func(t *testing.T) {
		req := &SetupRequest{
			Username: "admin",
			Password: "password123",
		}
		
		_, err := userService.PerformInitialSetup(req)
		require.NoError(t, err)
		
		isComplete, err := userService.IsSetupComplete()
		require.NoError(t, err)
		assert.True(t, isComplete)
	})
}

func TestUserService_GetMasterKey(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	userService := NewUserService(db, cfg)
	
	t.Run("Get master key before setup fails", func(t *testing.T) {
		_, err := userService.GetMasterKey()
		assert.Error(t, err)
	})
	
	t.Run("Get master key after setup", func(t *testing.T) {
		req := &SetupRequest{
			Username: "admin",
			Password: "password123",
		}
		
		response, err := userService.PerformInitialSetup(req)
		require.NoError(t, err)
		
		masterKey, err := userService.GetMasterKey()
		require.NoError(t, err)
		assert.Len(t, masterKey, 32)
		assert.NotEmpty(t, response.MasterKey)
	})
}

func TestUserService_LoadJWTSecret(t *testing.T) {
	db, cfg := setupTestDB(t)
	defer db.Close()
	
	// Clear JWT secret for this test
	cfg.JWT.Secret = ""
	userService := NewUserService(db, cfg)
	
	t.Run("Load JWT secret when not set", func(t *testing.T) {
		err := userService.LoadJWTSecret()
		require.NoError(t, err)
	})
	
	t.Run("Load JWT secret after setup", func(t *testing.T) {
		req := &SetupRequest{
			Username: "admin",
			Password: "password123",
		}
		
		response, err := userService.PerformInitialSetup(req)
		require.NoError(t, err)
		
		// The secret should have been generated during setup
		setupSecret := cfg.JWT.Secret
		require.NotEmpty(t, setupSecret)
		
		// Clear the secret to test loading
		cfg.JWT.Secret = ""
		
		err = userService.LoadJWTSecret()
		require.NoError(t, err)
		assert.Equal(t, setupSecret, cfg.JWT.Secret)
		assert.NotEmpty(t, response.Token)
	})
}

