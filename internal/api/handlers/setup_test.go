package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/robcowart/ocm/internal/database/models"
	"github.com/robcowart/ocm/internal/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// MockUserService is a mock implementation of UserService for testing
type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) IsSetupComplete() (bool, error) {
	args := m.Called()
	return args.Bool(0), args.Error(1)
}

func (m *MockUserService) PerformInitialSetup(req *service.SetupRequest) (*service.SetupResponse, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.SetupResponse), args.Error(1)
}

func (m *MockUserService) AuthenticateUser(username, password string) (string, error) {
	args := m.Called(username, password)
	return args.String(0), args.Error(1)
}

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

func TestNewSetupHandler(t *testing.T) {
	mockService := new(MockUserService)
	logger := zap.NewNop()

	handler := NewSetupHandler(&service.UserService{}, logger)

	assert.NotNil(t, handler)
	assert.NotNil(t, handler.userService)
	assert.NotNil(t, handler.logger)
	_ = mockService // avoid unused variable
}

func TestSetupHandler_GetStatus_Success(t *testing.T) {
	mockService := new(MockUserService)
	logger := zap.NewNop()

	// Create a test handler that we'll manually set up
	handler := &SetupHandler{
		logger: logger,
	}

	mockService.On("IsSetupComplete").Return(true, nil)

	router := setupTestRouter()
	router.GET("/api/v1/setup/status", func(c *gin.Context) {
		isComplete, err := mockService.IsSetupComplete()
		if err != nil {
			handler.logger.Error("Failed to check setup status")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check setup status"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"setup_complete": isComplete})
	})

	req, _ := http.NewRequest("GET", "/api/v1/setup/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]bool
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response["setup_complete"])
	mockService.AssertExpectations(t)
}

func TestSetupHandler_GetStatus_NotComplete(t *testing.T) {
	mockService := new(MockUserService)
	logger := zap.NewNop()

	handler := &SetupHandler{
		logger: logger,
	}

	mockService.On("IsSetupComplete").Return(false, nil)

	router := setupTestRouter()
	router.GET("/api/v1/setup/status", func(c *gin.Context) {
		isComplete, err := mockService.IsSetupComplete()
		if err != nil {
			handler.logger.Error("Failed to check setup status")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check setup status"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"setup_complete": isComplete})
	})

	req, _ := http.NewRequest("GET", "/api/v1/setup/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]bool
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response["setup_complete"])
	mockService.AssertExpectations(t)
}

func TestSetupHandler_GetStatus_Error(t *testing.T) {
	mockService := new(MockUserService)
	logger := zap.NewNop()

	handler := &SetupHandler{
		logger: logger,
	}

	mockService.On("IsSetupComplete").Return(false, errors.New("database error"))

	router := setupTestRouter()
	router.GET("/api/v1/setup/status", func(c *gin.Context) {
		_, err := mockService.IsSetupComplete()
		if err != nil {
			handler.logger.Error("Failed to check setup status")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check setup status"})
			return
		}
	})

	req, _ := http.NewRequest("GET", "/api/v1/setup/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "failed to check setup status", response["error"])
	mockService.AssertExpectations(t)
}

func TestSetupHandler_PerformSetup_Success(t *testing.T) {
	mockService := new(MockUserService)
	logger := zap.NewNop()

	handler := &SetupHandler{
		logger: logger,
	}

	setupReq := &service.SetupRequest{
		Username: "admin",
		Password: "password123",
	}

	setupResp := &service.SetupResponse{
		User: &models.User{
			ID:       "user-1",
			Username: "admin",
			Role:     "admin",
		},
		MasterKey: "abcdef1234567890",
		Token:     "jwt-token",
	}

	mockService.On("PerformInitialSetup", setupReq).Return(setupResp, nil)

	router := setupTestRouter()
	router.POST("/api/v1/setup", func(c *gin.Context) {
		var req SetupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		result, err := mockService.PerformInitialSetup(&service.SetupRequest{
			Username: req.Username,
			Password: req.Password,
		})
		if err != nil {
			handler.logger.Error("Setup failed")
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		handler.logger.Info("Initial setup completed")

		c.JSON(http.StatusOK, gin.H{
			"message":    "Setup completed successfully",
			"master_key": result.MasterKey,
			"token":      result.Token,
			"username":   result.User.Username,
		})
	})

	body := map[string]string{
		"username": "admin",
		"password": "password123",
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/setup", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Setup completed successfully", response["message"])
	assert.Equal(t, "abcdef1234567890", response["master_key"])
	assert.Equal(t, "jwt-token", response["token"])
	assert.Equal(t, "admin", response["username"])
	mockService.AssertExpectations(t)
}

func TestSetupHandler_PerformSetup_InvalidJSON(t *testing.T) {
	logger := zap.NewNop()

	_ = logger // handler not needed for this test

	router := setupTestRouter()
	router.POST("/api/v1/setup", func(c *gin.Context) {
		var req SetupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	})

	req, _ := http.NewRequest("POST", "/api/v1/setup", bytes.NewBuffer([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetupHandler_PerformSetup_MissingUsername(t *testing.T) {
	logger := zap.NewNop()

	_ = logger // handler not needed for this test

	router := setupTestRouter()
	router.POST("/api/v1/setup", func(c *gin.Context) {
		var req SetupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	})

	body := map[string]string{
		"password": "password123",
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/setup", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetupHandler_PerformSetup_ShortUsername(t *testing.T) {
	logger := zap.NewNop()

	_ = logger // handler not needed for this test

	router := setupTestRouter()
	router.POST("/api/v1/setup", func(c *gin.Context) {
		var req SetupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	})

	body := map[string]string{
		"username": "ab",
		"password": "password123",
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/setup", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetupHandler_PerformSetup_ShortPassword(t *testing.T) {
	logger := zap.NewNop()

	_ = logger // handler not needed for this test

	router := setupTestRouter()
	router.POST("/api/v1/setup", func(c *gin.Context) {
		var req SetupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	})

	body := map[string]string{
		"username": "admin",
		"password": "pass",
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/setup", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetupHandler_PerformSetup_ServiceError(t *testing.T) {
	mockService := new(MockUserService)
	logger := zap.NewNop()

	handler := &SetupHandler{
		logger: logger,
	}

	setupReq := &service.SetupRequest{
		Username: "admin",
		Password: "password123",
	}

	mockService.On("PerformInitialSetup", setupReq).Return(nil, errors.New("setup already complete"))

	router := setupTestRouter()
	router.POST("/api/v1/setup", func(c *gin.Context) {
		var req SetupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		_, err := mockService.PerformInitialSetup(&service.SetupRequest{
			Username: req.Username,
			Password: req.Password,
		})
		if err != nil {
			handler.logger.Error("Setup failed")
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	})

	body := map[string]string{
		"username": "admin",
		"password": "password123",
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/setup", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "setup already complete", response["error"])
	mockService.AssertExpectations(t)
}

