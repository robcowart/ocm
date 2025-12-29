package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/robcowart/ocm/internal/api/handlers"
	"github.com/robcowart/ocm/internal/config"
	"github.com/robcowart/ocm/internal/database"
	"github.com/robcowart/ocm/internal/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestEnvironment holds all components needed for integration tests
type TestEnvironment struct {
	DB           *database.Database
	Config       *config.Config
	UserService  *service.UserService
	CAService    *service.CAService
	CertService  *service.CertificateService
	SetupHandler *handlers.SetupHandler
	AuthHandler  *handlers.AuthHandler
	CAHandler    *handlers.CAHandler
	CertHandler  *handlers.CertificateHandler
	Router       *gin.Engine
	Logger       *zap.Logger
	TestDBPath   string
}

// setupTestEnvironment creates a complete test environment with real services
func setupTestEnvironment(t *testing.T) *TestEnvironment {
	gin.SetMode(gin.TestMode)

	// Create temp database file
	dbPath := t.TempDir() + "/test.db"

	// Create test config
	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Type: "sqlite",
			SQLite: config.SQLiteConfig{
				Path: dbPath,
			},
		},
		JWT: config.JWTConfig{
			Secret:     "test-secret-key-for-testing-only-12345",
			Expiration: 24 * time.Hour,
			Issuer:     "ocm-test",
		},
		Crypto: config.CryptoConfig{
			DefaultAlgorithm:    "rsa",
			DefaultCAValidity:   87600 * time.Hour, // 10 years
			DefaultCertValidity: 8760 * time.Hour,  // 1 year
			DefaultRSABits:      2048,
			DefaultECCurve:      "P256",
		},
	}

	// Create database connection
	db, err := database.New(cfg)
	require.NoError(t, err, "Failed to create test database")

	// Run migrations
	err = db.Migrate()
	require.NoError(t, err, "Failed to run migrations")

	// Create logger
	logger := zap.NewNop()

	// Create services with dependencies
	userService := service.NewUserService(db, cfg)
	caService := service.NewCAService(db, cfg, userService)
	certService := service.NewCertificateService(db, caService, cfg, userService)

	// Create handlers
	setupHandler := handlers.NewSetupHandler(userService, logger)
	authHandler := handlers.NewAuthHandler(userService, logger)
	caHandler := handlers.NewCAHandler(caService, logger)
	certHandler := handlers.NewCertificateHandler(certService, logger)

	// Create router and register routes
	router := gin.New()

	// Setup routes
	v1 := router.Group("/api/v1")
	{
		// Setup routes
		setup := v1.Group("/setup")
		{
			setup.GET("/status", setupHandler.GetStatus)
			setup.POST("", setupHandler.PerformSetup)
		}

		// Auth routes
		auth := v1.Group("/auth")
		{
			auth.POST("/login", authHandler.Login)
			auth.GET("/me", authHandler.GetCurrentUser)
		}

		// CA routes
		authorities := v1.Group("/authorities")
		{
			authorities.GET("", caHandler.ListAuthorities)
			authorities.GET("/:id", caHandler.GetAuthority)
			authorities.POST("", caHandler.CreateRootCA)
			authorities.POST("/import", caHandler.ImportCA)
			authorities.POST("/:id/export", caHandler.ExportAuthority)
			authorities.DELETE("/:id", caHandler.DeleteAuthority)
		}

		// Certificate routes
		certificates := v1.Group("/certificates")
		{
			certificates.GET("", certHandler.ListCertificates)
			certificates.GET("/:id", certHandler.GetCertificate)
			certificates.POST("", certHandler.CreateCertificate)
			certificates.POST("/:id/export", certHandler.ExportCertificate)
			certificates.PUT("/:id/revoke", certHandler.RevokeCertificate)
			certificates.DELETE("/:id", certHandler.DeleteCertificate)
		}
	}

	return &TestEnvironment{
		DB:           db,
		Config:       cfg,
		UserService:  userService,
		CAService:    caService,
		CertService:  certService,
		SetupHandler: setupHandler,
		AuthHandler:  authHandler,
		CAHandler:    caHandler,
		CertHandler:  certHandler,
		Router:       router,
		Logger:       logger,
		TestDBPath:   dbPath,
	}
}

// cleanup closes database and removes test files
func (env *TestEnvironment) cleanup(t *testing.T) {
	if env.DB != nil {
		env.DB.Close()
	}
	os.RemoveAll(env.TestDBPath)
}

// TestSetupHandler_Integration tests the complete setup flow
func TestSetupHandler_Integration(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup(t)

	t.Run("GetStatus before setup", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/setup/status", nil)
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]bool
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.False(t, response["setup_complete"])
	})

	t.Run("PerformSetup successfully", func(t *testing.T) {
		body := map[string]string{
			"username": "admin",
			"password": "test1234",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/api/v1/setup", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "Setup completed successfully", response["message"])
		assert.NotEmpty(t, response["master_key"])
		assert.NotEmpty(t, response["token"])
		assert.Equal(t, "admin", response["username"])
	})

	t.Run("GetStatus after setup", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/setup/status", nil)
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]bool
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response["setup_complete"])
	})

	t.Run("PerformSetup fails when already complete", func(t *testing.T) {
		body := map[string]string{
			"username": "admin2",
			"password": "test1234",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/api/v1/setup", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestAuthHandler_Integration tests the authentication flow
func TestAuthHandler_Integration(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup(t)

	// Perform setup first
	body := map[string]string{
		"username": "testuser",
		"password": "password123",
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/setup", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	t.Run("Login with valid credentials", func(t *testing.T) {
		body := map[string]string{
			"username": "testuser",
			"password": "password123",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotEmpty(t, response["token"])
	})

	t.Run("Login with invalid credentials", func(t *testing.T) {
		body := map[string]string{
			"username": "testuser",
			"password": "wrongpassword",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Login with missing username", func(t *testing.T) {
		body := map[string]string{
			"password": "password123",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestCAHandler_Integration tests certificate authority operations
func TestCAHandler_Integration(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup(t)

	// Perform setup first to initialize master key
	setupBody := map[string]string{
		"username": "admin",
		"password": "admin123",
	}
	jsonBody, _ := json.Marshal(setupBody)
	req := httptest.NewRequest("POST", "/api/v1/setup", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var caID string

	t.Run("List authorities initially empty", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/authorities", nil)
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Empty(t, response)
	})

	t.Run("Create Root CA", func(t *testing.T) {
		body := map[string]interface{}{
			"friendly_name": "Test Root CA",
			"common_name":   "Test Root CA",
			"organization":  "Test Org",
			"country":       "US",
			"algorithm":     "rsa",
			"rsa_bits":      2048,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/api/v1/authorities", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotEmpty(t, response["id"])
		caID = response["id"].(string)
	})

	t.Run("List authorities after creation", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/authorities", nil)
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response, 1)
	})

	t.Run("Get specific authority", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/authorities/"+caID, nil)
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, caID, response["id"])
	})

	t.Run("Export authority as PEM", func(t *testing.T) {
		body := map[string]interface{}{
			"format":    "pem",
			"cert_only": false,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/api/v1/authorities/"+caID+"/export", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "pem")
		assert.NotEmpty(t, w.Body.Bytes())
	})

	t.Run("Delete authority", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/authorities/"+caID, nil)
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

// TestCertificateHandler_Integration tests certificate operations
func TestCertificateHandler_Integration(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup(t)

	// Perform setup first
	setupBody := map[string]string{
		"username": "admin",
		"password": "admin123",
	}
	jsonBody, _ := json.Marshal(setupBody)
	req := httptest.NewRequest("POST", "/api/v1/setup", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Create a CA first
	caBody := map[string]interface{}{
		"friendly_name": "Test CA",
		"common_name":   "Test CA",
		"organization":  "Test Org",
		"country":       "US",
	}
	jsonBody, _ = json.Marshal(caBody)
	req = httptest.NewRequest("POST", "/api/v1/authorities", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var caResponse map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &caResponse)
	caID := caResponse["id"].(string)

	var certID string

	t.Run("List certificates initially empty", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/certificates", nil)
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Empty(t, response)
	})

	t.Run("Create certificate", func(t *testing.T) {
		body := map[string]interface{}{
			"authority_id":   caID,
			"common_name":    "example.com",
			"organization":   "Example Inc",
			"country":        "US",
			"sans":           []string{"www.example.com", "*.example.com"},
			"is_server_auth": true,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/api/v1/certificates", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotEmpty(t, response["id"])
		certID = response["id"].(string)
	})

	t.Run("List certificates after creation", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/certificates", nil)
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response, 1)
	})

	t.Run("Get specific certificate", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/certificates/"+certID, nil)
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Export certificate as PEM", func(t *testing.T) {
		body := map[string]interface{}{
			"format": "pem",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/api/v1/certificates/"+certID+"/export", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "pem")
	})

	t.Run("Revoke certificate", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/api/v1/certificates/"+certID+"/revoke", nil)
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Delete certificate", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/certificates/"+certID, nil)
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

// TestEndToEnd_CompleteFlow tests a complete workflow
func TestEndToEnd_CompleteFlow(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup(t)

	// 1. Setup
	t.Log("Step 1: Perform initial setup")
	setupBody := map[string]string{
		"username": "admin",
		"password": "securepass123",
	}
	jsonBody, _ := json.Marshal(setupBody)
	req := httptest.NewRequest("POST", "/api/v1/setup", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// 2. Login
	t.Log("Step 2: Login as admin")
	loginBody := map[string]string{
		"username": "admin",
		"password": "securepass123",
	}
	jsonBody, _ = json.Marshal(loginBody)
	req = httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// 3. Create CA
	t.Log("Step 3: Create Certificate Authority")
	caBody := map[string]interface{}{
		"friendly_name": "My Root CA",
		"common_name":   "My Organization Root CA",
		"organization":  "My Organization",
		"country":       "US",
	}
	jsonBody, _ = json.Marshal(caBody)
	req = httptest.NewRequest("POST", "/api/v1/authorities", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var caResponse map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &caResponse)
	caID := caResponse["id"].(string)

	// 4. Create Certificate
	t.Log("Step 4: Create certificate")
	certBody := map[string]interface{}{
		"authority_id":   caID,
		"common_name":    "myapp.example.com",
		"organization":   "My Organization",
		"sans":           []string{"www.myapp.example.com", "api.myapp.example.com"},
		"is_server_auth": true,
	}
	jsonBody, _ = json.Marshal(certBody)
	req = httptest.NewRequest("POST", "/api/v1/certificates", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var certResponse map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &certResponse)
	certID := certResponse["id"].(string)

	// 5. Export Certificate
	t.Log("Step 5: Export certificate")
	exportBody := map[string]interface{}{
		"format": "pem",
	}
	jsonBody, _ = json.Marshal(exportBody)
	req = httptest.NewRequest("POST", "/api/v1/certificates/"+certID+"/export", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	pemData := w.Body.Bytes()
	assert.Contains(t, string(pemData), "BEGIN CERTIFICATE")

	t.Log("Complete workflow successful!")
}
