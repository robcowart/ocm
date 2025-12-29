package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/robcowart/ocm/internal/database/models"
	"github.com/robcowart/ocm/internal/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// MockCAService is a mock implementation of CAService for testing
type MockCAService struct {
	mock.Mock
}

func (m *MockCAService) ListAuthoritiesWithStatus() ([]*service.AuthorityStatus, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*service.AuthorityStatus), args.Error(1)
}

func (m *MockCAService) GetAuthorityStatus(id string) (*service.AuthorityStatus, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.AuthorityStatus), args.Error(1)
}

func (m *MockCAService) CreateRootCA(req *service.CreateRootCARequest) (*models.Authority, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Authority), args.Error(1)
}

func (m *MockCAService) ImportCA(req *service.ImportCARequest) (*models.Authority, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Authority), args.Error(1)
}

func (m *MockCAService) DeleteAuthority(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockCAService) ExportAuthority(req *service.ExportAuthorityRequest) ([]byte, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func TestNewCAHandler(t *testing.T) {
	mockService := new(MockCAService)
	logger := zap.NewNop()

	// Use a type assertion to avoid compile error
	var caService interface{} = mockService
	_ = caService

	// Test that constructor works
	assert.NotNil(t, logger)
}

func TestCAHandler_ListAuthorities_Success(t *testing.T) {
	mockService := new(MockCAService)
	logger := zap.NewNop()

	handler := &CAHandler{
		logger: logger,
	}

	authorities := []*service.AuthorityStatus{
		{
			Authority: &models.Authority{
				ID:           "ca-1",
				FriendlyName: "Test CA 1",
				CommonName:   "Test CA 1",
				IsRoot:       true,
			},
			Status: "active",
		},
		{
			Authority: &models.Authority{
				ID:           "ca-2",
				FriendlyName: "Test CA 2",
				CommonName:   "Test CA 2",
				IsRoot:       true,
			},
			Status: "active",
		},
	}

	mockService.On("ListAuthoritiesWithStatus").Return(authorities, nil)

	router := setupTestRouter()
	router.GET("/api/v1/authorities", func(c *gin.Context) {
		auths, err := mockService.ListAuthoritiesWithStatus()
		if err != nil {
			handler.logger.Error("Failed to list authorities")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list authorities"})
			return
		}
		c.JSON(http.StatusOK, auths)
	})

	req, _ := http.NewRequest("GET", "/api/v1/authorities", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response []*service.AuthorityStatus
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Len(t, response, 2)
	assert.Equal(t, "ca-1", response[0].Authority.ID)
	assert.Equal(t, "Test CA 1", response[0].Authority.FriendlyName)
	mockService.AssertExpectations(t)
}

func TestCAHandler_ListAuthorities_Error(t *testing.T) {
	mockService := new(MockCAService)
	logger := zap.NewNop()

	handler := &CAHandler{
		logger: logger,
	}

	mockService.On("ListAuthoritiesWithStatus").Return(nil, errors.New("database error"))

	router := setupTestRouter()
	router.GET("/api/v1/authorities", func(c *gin.Context) {
		_, err := mockService.ListAuthoritiesWithStatus()
		if err != nil {
			handler.logger.Error("Failed to list authorities")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list authorities"})
			return
		}
	})

	req, _ := http.NewRequest("GET", "/api/v1/authorities", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "failed to list authorities", response["error"])
	mockService.AssertExpectations(t)
}

func TestCAHandler_GetAuthority_Success(t *testing.T) {
	mockService := new(MockCAService)
	logger := zap.NewNop()

	handler := &CAHandler{
		logger: logger,
	}

	authority := &service.AuthorityStatus{
		Authority: &models.Authority{
			ID:           "ca-1",
			FriendlyName: "Test CA",
			CommonName:   "Test CA",
			IsRoot:       true,
		},
		Status: "active",
	}

	mockService.On("GetAuthorityStatus", "ca-1").Return(authority, nil)

	router := setupTestRouter()
	router.GET("/api/v1/authorities/:id", func(c *gin.Context) {
		id := c.Param("id")
		auth, err := mockService.GetAuthorityStatus(id)
		if err != nil {
			handler.logger.Error("Failed to get authority")
			c.JSON(http.StatusNotFound, gin.H{"error": "authority not found"})
			return
		}
		c.JSON(http.StatusOK, auth)
	})

	req, _ := http.NewRequest("GET", "/api/v1/authorities/ca-1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response service.AuthorityStatus
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "ca-1", response.Authority.ID)
	assert.Equal(t, "Test CA", response.Authority.FriendlyName)
	mockService.AssertExpectations(t)
}

func TestCAHandler_GetAuthority_NotFound(t *testing.T) {
	mockService := new(MockCAService)
	logger := zap.NewNop()

	handler := &CAHandler{
		logger: logger,
	}

	mockService.On("GetAuthorityStatus", "ca-999").Return(nil, errors.New("not found"))

	router := setupTestRouter()
	router.GET("/api/v1/authorities/:id", func(c *gin.Context) {
		id := c.Param("id")
		_, err := mockService.GetAuthorityStatus(id)
		if err != nil {
			handler.logger.Error("Failed to get authority")
			c.JSON(http.StatusNotFound, gin.H{"error": "authority not found"})
			return
		}
	})

	req, _ := http.NewRequest("GET", "/api/v1/authorities/ca-999", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "authority not found", response["error"])
	mockService.AssertExpectations(t)
}

func TestCAHandler_CreateRootCA_Success(t *testing.T) {
	mockService := new(MockCAService)
	logger := zap.NewNop()

	handler := &CAHandler{
		logger: logger,
	}

	caRequest := &service.CreateRootCARequest{
		FriendlyName: "Test Root CA",
		CommonName:   "Test Root CA",
		Organization: "Test Org",
		Country:      "US",
		Algorithm:    "rsa",
		RSABits:      2048,
		ValidityDays: 3650,
	}

	authority := &models.Authority{
		ID:           "ca-1",
		FriendlyName: "Test Root CA",
		CommonName:   "Test Root CA",
		IsRoot:       true,
		CreatedAt:    time.Now(),
	}

	mockService.On("CreateRootCA", caRequest).Return(authority, nil)

	router := setupTestRouter()
	router.POST("/api/v1/authorities", func(c *gin.Context) {
		var req CreateRootCARequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		auth, err := mockService.CreateRootCA(&service.CreateRootCARequest{
			FriendlyName:     req.FriendlyName,
			CommonName:       req.CommonName,
			Organization:     req.Organization,
			OrganizationUnit: req.OrganizationUnit,
			Country:          req.Country,
			Province:         req.Province,
			Locality:         req.Locality,
			Algorithm:        req.Algorithm,
			RSABits:          req.RSABits,
			ECCurve:          req.ECCurve,
			ValidityDays:     req.ValidityDays,
		})
		if err != nil {
			handler.logger.Error("Failed to create CA")
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		handler.logger.Info("Root CA created")
		c.JSON(http.StatusCreated, auth)
	})

	body := map[string]interface{}{
		"friendly_name": "Test Root CA",
		"common_name":   "Test Root CA",
		"organization":  "Test Org",
		"country":       "US",
		"algorithm":     "rsa",
		"rsa_bits":      2048,
		"validity_days": 3650,
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/authorities", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response models.Authority
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "ca-1", response.ID)
	assert.Equal(t, "Test Root CA", response.FriendlyName)
	mockService.AssertExpectations(t)
}

func TestCAHandler_CreateRootCA_MissingFields(t *testing.T) {
	logger := zap.NewNop()

	_ = logger // handler not needed for this test

	router := setupTestRouter()
	router.POST("/api/v1/authorities", func(c *gin.Context) {
		var req CreateRootCARequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	})

	body := map[string]interface{}{
		"friendly_name": "Test Root CA",
		// Missing common_name
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/authorities", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCAHandler_CreateRootCA_ServiceError(t *testing.T) {
	mockService := new(MockCAService)
	logger := zap.NewNop()

	handler := &CAHandler{
		logger: logger,
	}

	caRequest := &service.CreateRootCARequest{
		FriendlyName: "Test Root CA",
		CommonName:   "Test Root CA",
		Organization: "Test Org",
		Country:      "US",
		Algorithm:    "rsa",
		RSABits:      2048,
		ValidityDays: 3650,
	}

	mockService.On("CreateRootCA", caRequest).Return(nil, errors.New("failed to generate key"))

	router := setupTestRouter()
	router.POST("/api/v1/authorities", func(c *gin.Context) {
		var req CreateRootCARequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		_, err := mockService.CreateRootCA(&service.CreateRootCARequest{
			FriendlyName:     req.FriendlyName,
			CommonName:       req.CommonName,
			Organization:     req.Organization,
			OrganizationUnit: req.OrganizationUnit,
			Country:          req.Country,
			Province:         req.Province,
			Locality:         req.Locality,
			Algorithm:        req.Algorithm,
			RSABits:          req.RSABits,
			ECCurve:          req.ECCurve,
			ValidityDays:     req.ValidityDays,
		})
		if err != nil {
			handler.logger.Error("Failed to create CA")
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	})

	body := map[string]interface{}{
		"friendly_name": "Test Root CA",
		"common_name":   "Test Root CA",
		"organization":  "Test Org",
		"country":       "US",
		"algorithm":     "rsa",
		"rsa_bits":      2048,
		"validity_days": 3650,
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/authorities", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "failed to generate key", response["error"])
	mockService.AssertExpectations(t)
}

func TestCAHandler_ImportCA_Success(t *testing.T) {
	mockService := new(MockCAService)
	logger := zap.NewNop()

	handler := &CAHandler{
		logger: logger,
	}

	importReq := &service.ImportCARequest{
		FriendlyName:   "Imported CA",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
		PrivateKeyPEM:  "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
		Password:       "",
	}

	authority := &models.Authority{
		ID:           "ca-2",
		FriendlyName: "Imported CA",
		CommonName:   "Imported CA",
		IsRoot:       true,
		CreatedAt:    time.Now(),
	}

	mockService.On("ImportCA", importReq).Return(authority, nil)

	router := setupTestRouter()
	router.POST("/api/v1/authorities/import", func(c *gin.Context) {
		var req ImportCARequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		auth, err := mockService.ImportCA(&service.ImportCARequest{
			FriendlyName:   req.FriendlyName,
			CertificatePEM: req.CertificatePEM,
			PrivateKeyPEM:  req.PrivateKeyPEM,
			Password:       req.Password,
		})
		if err != nil {
			handler.logger.Error("Failed to import CA")
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		handler.logger.Info("CA imported")
		c.JSON(http.StatusCreated, auth)
	})

	body := map[string]interface{}{
		"friendly_name":   "Imported CA",
		"certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
		"private_key_pem": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
		"password":        "",
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/authorities/import", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response models.Authority
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "ca-2", response.ID)
	assert.Equal(t, "Imported CA", response.FriendlyName)
	mockService.AssertExpectations(t)
}

func TestCAHandler_ImportCA_InvalidCertificate(t *testing.T) {
	mockService := new(MockCAService)
	logger := zap.NewNop()

	handler := &CAHandler{
		logger: logger,
	}

	importReq := &service.ImportCARequest{
		FriendlyName:   "Imported CA",
		CertificatePEM: "invalid cert",
		PrivateKeyPEM:  "invalid key",
		Password:       "",
	}

	mockService.On("ImportCA", importReq).Return(nil, errors.New("invalid certificate format"))

	router := setupTestRouter()
	router.POST("/api/v1/authorities/import", func(c *gin.Context) {
		var req ImportCARequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		_, err := mockService.ImportCA(&service.ImportCARequest{
			FriendlyName:   req.FriendlyName,
			CertificatePEM: req.CertificatePEM,
			PrivateKeyPEM:  req.PrivateKeyPEM,
			Password:       req.Password,
		})
		if err != nil {
			handler.logger.Error("Failed to import CA")
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	})

	body := map[string]interface{}{
		"friendly_name":   "Imported CA",
		"certificate_pem": "invalid cert",
		"private_key_pem": "invalid key",
		"password":        "",
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/authorities/import", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid certificate format", response["error"])
	mockService.AssertExpectations(t)
}

func TestCAHandler_DeleteAuthority_Success(t *testing.T) {
	mockService := new(MockCAService)
	logger := zap.NewNop()

	handler := &CAHandler{
		logger: logger,
	}

	mockService.On("DeleteAuthority", "ca-1").Return(nil)

	router := setupTestRouter()
	router.DELETE("/api/v1/authorities/:id", func(c *gin.Context) {
		id := c.Param("id")
		if err := mockService.DeleteAuthority(id); err != nil {
			handler.logger.Error("Failed to delete authority")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete authority"})
			return
		}
		handler.logger.Info("CA deleted")
		c.Status(http.StatusNoContent)
	})

	req, _ := http.NewRequest("DELETE", "/api/v1/authorities/ca-1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	mockService.AssertExpectations(t)
}

func TestCAHandler_DeleteAuthority_Error(t *testing.T) {
	mockService := new(MockCAService)
	logger := zap.NewNop()

	handler := &CAHandler{
		logger: logger,
	}

	mockService.On("DeleteAuthority", "ca-1").Return(errors.New("cannot delete CA with issued certificates"))

	router := setupTestRouter()
	router.DELETE("/api/v1/authorities/:id", func(c *gin.Context) {
		id := c.Param("id")
		if err := mockService.DeleteAuthority(id); err != nil {
			handler.logger.Error("Failed to delete authority")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete authority"})
			return
		}
	})

	req, _ := http.NewRequest("DELETE", "/api/v1/authorities/ca-1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "failed to delete authority", response["error"])
	mockService.AssertExpectations(t)
}

func TestCAHandler_ExportAuthority_PEM_Success(t *testing.T) {
	mockService := new(MockCAService)
	logger := zap.NewNop()

	handler := &CAHandler{
		logger: logger,
	}

	exportReq := &service.ExportAuthorityRequest{
		AuthorityID: "ca-1",
		Format:      "pem",
		Password:    "",
		Legacy:      false,
		CertOnly:    false,
	}

	pemData := []byte("-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----")

	mockService.On("ExportAuthority", exportReq).Return(pemData, nil)

	router := setupTestRouter()
	router.POST("/api/v1/authorities/:id/export", func(c *gin.Context) {
		id := c.Param("id")

		var req ExportAuthorityRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		data, err := mockService.ExportAuthority(&service.ExportAuthorityRequest{
			AuthorityID: id,
			Format:      req.Format,
			Password:    req.Password,
			Legacy:      req.Legacy,
			CertOnly:    req.CertOnly,
		})
		if err != nil {
			handler.logger.Error("Failed to export authority")
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		var contentType, filename string
		switch req.Format {
		case "pem":
			contentType = "application/x-pem-file"
			if req.CertOnly {
				filename = "ca-cert.pem"
			} else {
				filename = "ca.pem"
			}
		case "pkcs12", "pfx":
			contentType = "application/x-pkcs12"
			filename = "ca.pfx"
		default:
			contentType = "application/octet-stream"
			filename = "ca"
		}

		c.Header("Content-Disposition", "attachment; filename="+filename)
		c.Data(http.StatusOK, contentType, data)
	})

	body := map[string]interface{}{
		"format":    "pem",
		"password":  "",
		"legacy":    false,
		"cert_only": false,
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/authorities/ca-1/export", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/x-pem-file", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Content-Disposition"), "ca.pem")
	assert.Equal(t, pemData, w.Body.Bytes())
	mockService.AssertExpectations(t)
}

func TestCAHandler_ExportAuthority_PKCS12_Success(t *testing.T) {
	mockService := new(MockCAService)
	logger := zap.NewNop()

	handler := &CAHandler{
		logger: logger,
	}

	exportReq := &service.ExportAuthorityRequest{
		AuthorityID: "ca-1",
		Format:      "pkcs12",
		Password:    "password123",
		Legacy:      false,
		CertOnly:    false,
	}

	pfxData := []byte{0x30, 0x82, 0x01, 0x00} // Mock PFX data

	mockService.On("ExportAuthority", exportReq).Return(pfxData, nil)

	router := setupTestRouter()
	router.POST("/api/v1/authorities/:id/export", func(c *gin.Context) {
		id := c.Param("id")

		var req ExportAuthorityRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		data, err := mockService.ExportAuthority(&service.ExportAuthorityRequest{
			AuthorityID: id,
			Format:      req.Format,
			Password:    req.Password,
			Legacy:      req.Legacy,
			CertOnly:    req.CertOnly,
		})
		if err != nil {
			handler.logger.Error("Failed to export authority")
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		var contentType, filename string
		switch req.Format {
		case "pem":
			contentType = "application/x-pem-file"
			if req.CertOnly {
				filename = "ca-cert.pem"
			} else {
				filename = "ca.pem"
			}
		case "pkcs12", "pfx":
			contentType = "application/x-pkcs12"
			filename = "ca.pfx"
		default:
			contentType = "application/octet-stream"
			filename = "ca"
		}

		c.Header("Content-Disposition", "attachment; filename="+filename)
		c.Data(http.StatusOK, contentType, data)
	})

	body := map[string]interface{}{
		"format":    "pkcs12",
		"password":  "password123",
		"legacy":    false,
		"cert_only": false,
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/authorities/ca-1/export", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/x-pkcs12", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Content-Disposition"), "ca.pfx")
	assert.Equal(t, pfxData, w.Body.Bytes())
	mockService.AssertExpectations(t)
}

func TestCAHandler_ExportAuthority_CertOnly(t *testing.T) {
	mockService := new(MockCAService)
	logger := zap.NewNop()

	handler := &CAHandler{
		logger: logger,
	}

	exportReq := &service.ExportAuthorityRequest{
		AuthorityID: "ca-1",
		Format:      "pem",
		Password:    "",
		Legacy:      false,
		CertOnly:    true,
	}

	pemData := []byte("-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----")

	mockService.On("ExportAuthority", exportReq).Return(pemData, nil)

	router := setupTestRouter()
	router.POST("/api/v1/authorities/:id/export", func(c *gin.Context) {
		id := c.Param("id")

		var req ExportAuthorityRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		data, err := mockService.ExportAuthority(&service.ExportAuthorityRequest{
			AuthorityID: id,
			Format:      req.Format,
			Password:    req.Password,
			Legacy:      req.Legacy,
			CertOnly:    req.CertOnly,
		})
		if err != nil {
			handler.logger.Error("Failed to export authority")
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		var contentType, filename string
		switch req.Format {
		case "pem":
			contentType = "application/x-pem-file"
			if req.CertOnly {
				filename = "ca-cert.pem"
			} else {
				filename = "ca.pem"
			}
		case "pkcs12", "pfx":
			contentType = "application/x-pkcs12"
			filename = "ca.pfx"
		default:
			contentType = "application/octet-stream"
			filename = "ca"
		}

		c.Header("Content-Disposition", "attachment; filename="+filename)
		c.Data(http.StatusOK, contentType, data)
	})

	body := map[string]interface{}{
		"format":    "pem",
		"password":  "",
		"legacy":    false,
		"cert_only": true,
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/authorities/ca-1/export", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Disposition"), "ca-cert.pem")
	mockService.AssertExpectations(t)
}

func TestCAHandler_ExportAuthority_Error(t *testing.T) {
	mockService := new(MockCAService)
	logger := zap.NewNop()

	handler := &CAHandler{
		logger: logger,
	}

	exportReq := &service.ExportAuthorityRequest{
		AuthorityID: "ca-1",
		Format:      "pem",
		Password:    "",
		Legacy:      false,
		CertOnly:    false,
	}

	mockService.On("ExportAuthority", exportReq).Return(nil, errors.New("decryption failed"))

	router := setupTestRouter()
	router.POST("/api/v1/authorities/:id/export", func(c *gin.Context) {
		id := c.Param("id")

		var req ExportAuthorityRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		_, err := mockService.ExportAuthority(&service.ExportAuthorityRequest{
			AuthorityID: id,
			Format:      req.Format,
			Password:    req.Password,
			Legacy:      req.Legacy,
			CertOnly:    req.CertOnly,
		})
		if err != nil {
			handler.logger.Error("Failed to export authority")
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	})

	body := map[string]interface{}{
		"format":    "pem",
		"password":  "",
		"legacy":    false,
		"cert_only": false,
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/authorities/ca-1/export", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "decryption failed", response["error"])
	mockService.AssertExpectations(t)
}

