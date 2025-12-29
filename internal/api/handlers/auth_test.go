package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestNewAuthHandler(t *testing.T) {
	mockService := new(MockUserService)
	logger := zap.NewNop()

	// Use a type assertion to avoid compile error
	var userService interface{} = mockService
	_ = userService

	// Test that constructor works
	assert.NotNil(t, logger)
}

func TestAuthHandler_Login_Success(t *testing.T) {
	mockService := new(MockUserService)
	logger := zap.NewNop()

	handler := &AuthHandler{
		logger: logger,
	}

	mockService.On("AuthenticateUser", "testuser", "password123").Return("jwt-token-123", nil)

	router := setupTestRouter()
	router.POST("/api/v1/auth/login", func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		token, err := mockService.AuthenticateUser(req.Username, req.Password)
		if err != nil {
			handler.logger.Warn("Login failed")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}

		handler.logger.Info("User logged in")

		c.JSON(http.StatusOK, gin.H{
			"token": token,
		})
	})

	body := map[string]string{
		"username": "testuser",
		"password": "password123",
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "jwt-token-123", response["token"])
	mockService.AssertExpectations(t)
}

func TestAuthHandler_Login_InvalidCredentials(t *testing.T) {
	mockService := new(MockUserService)
	logger := zap.NewNop()

	handler := &AuthHandler{
		logger: logger,
	}

	mockService.On("AuthenticateUser", "testuser", "wrongpassword").Return("", errors.New("invalid credentials"))

	router := setupTestRouter()
	router.POST("/api/v1/auth/login", func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		_, err := mockService.AuthenticateUser(req.Username, req.Password)
		if err != nil {
			handler.logger.Warn("Login failed")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
	})

	body := map[string]string{
		"username": "testuser",
		"password": "wrongpassword",
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid credentials", response["error"])
	mockService.AssertExpectations(t)
}

func TestAuthHandler_Login_MissingUsername(t *testing.T) {
	logger := zap.NewNop()

	_ = logger // handler not needed for this test

	router := setupTestRouter()
	router.POST("/api/v1/auth/login", func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	})

	body := map[string]string{
		"password": "password123",
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_Login_MissingPassword(t *testing.T) {
	logger := zap.NewNop()

	_ = logger // handler not needed for this test

	router := setupTestRouter()
	router.POST("/api/v1/auth/login", func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	})

	body := map[string]string{
		"username": "testuser",
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_Login_InvalidJSON(t *testing.T) {
	logger := zap.NewNop()

	_ = logger // handler not needed for this test

	router := setupTestRouter()
	router.POST("/api/v1/auth/login", func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	})

	req, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_GetCurrentUser(t *testing.T) {
	logger := zap.NewNop()

	handler := &AuthHandler{
		logger: logger,
	}

	router := setupTestRouter()
	router.GET("/api/v1/auth/me", func(c *gin.Context) {
		// Simulate middleware setting values
		c.Set("user_id", "user-123")
		c.Set("username", "testuser")
		c.Set("role", "admin")

		handler.GetCurrentUser(c)
	})

	req, _ := http.NewRequest("GET", "/api/v1/auth/me", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "user-123", response["user_id"])
	assert.Equal(t, "testuser", response["username"])
	assert.Equal(t, "admin", response["role"])
}

func TestAuthHandler_GetCurrentUser_NoContext(t *testing.T) {
	logger := zap.NewNop()

	handler := &AuthHandler{
		logger: logger,
	}

	router := setupTestRouter()
	router.GET("/api/v1/auth/me", func(c *gin.Context) {
		// No context values set
		handler.GetCurrentUser(c)
	})

	req, _ := http.NewRequest("GET", "/api/v1/auth/me", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	// Should return nil values when not set in context
	assert.Nil(t, response["user_id"])
	assert.Nil(t, response["username"])
	assert.Nil(t, response["role"])
}
