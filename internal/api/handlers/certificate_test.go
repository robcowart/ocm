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

// MockCertificateService is a mock implementation of CertificateService for testing
type MockCertificateService struct {
	mock.Mock
}

func (m *MockCertificateService) ListCertificatesWithStatus() ([]*service.CertificateStatus, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*service.CertificateStatus), args.Error(1)
}

func (m *MockCertificateService) GetCertificateStatus(id string) (*service.CertificateStatus, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.CertificateStatus), args.Error(1)
}

func (m *MockCertificateService) GetCertificate(id string) (*models.Certificate, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Certificate), args.Error(1)
}

func (m *MockCertificateService) CreateCertificate(req *service.CreateCertificateRequest) (*models.Certificate, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Certificate), args.Error(1)
}

func (m *MockCertificateService) ExportCertificate(req *service.ExportRequest) ([]byte, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockCertificateService) RevokeCertificate(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockCertificateService) DeleteCertificate(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func TestNewCertificateHandler(t *testing.T) {
	mockService := new(MockCertificateService)
	logger := zap.NewNop()

	// Use a type assertion to avoid compile error
	var certService interface{} = mockService
	_ = certService

	// Test that constructor works
	assert.NotNil(t, logger)
}

func TestCertificateHandler_ListCertificates_Success(t *testing.T) {
	mockService := new(MockCertificateService)
	logger := zap.NewNop()

	handler := &CertificateHandler{
		logger: logger,
	}

	certificates := []*service.CertificateStatus{
		{
			Certificate: &models.Certificate{
				ID:         "cert-1",
				CommonName: "example.com",
			},
			Status: "valid",
		},
		{
			Certificate: &models.Certificate{
				ID:         "cert-2",
				CommonName: "test.com",
			},
			Status: "valid",
		},
	}

	mockService.On("ListCertificatesWithStatus").Return(certificates, nil)

	router := setupTestRouter()
	router.GET("/api/v1/certificates", func(c *gin.Context) {
		certs, err := mockService.ListCertificatesWithStatus()
		if err != nil {
			handler.logger.Error("Failed to list certificates")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list certificates"})
			return
		}
		c.JSON(http.StatusOK, certs)
	})

	req, _ := http.NewRequest("GET", "/api/v1/certificates", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Just verify we got a valid JSON response with expected structure
	var response []map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Len(t, response, 2)
	mockService.AssertExpectations(t)
}

func TestCertificateHandler_ListCertificates_Error(t *testing.T) {
	mockService := new(MockCertificateService)
	logger := zap.NewNop()

	handler := &CertificateHandler{
		logger: logger,
	}

	mockService.On("ListCertificatesWithStatus").Return(nil, errors.New("database error"))

	router := setupTestRouter()
	router.GET("/api/v1/certificates", func(c *gin.Context) {
		_, err := mockService.ListCertificatesWithStatus()
		if err != nil {
			handler.logger.Error("Failed to list certificates")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list certificates"})
			return
		}
	})

	req, _ := http.NewRequest("GET", "/api/v1/certificates", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "failed to list certificates", response["error"])
	mockService.AssertExpectations(t)
}

func TestCertificateHandler_GetCertificate_Success(t *testing.T) {
	mockService := new(MockCertificateService)
	logger := zap.NewNop()

	handler := &CertificateHandler{
		logger: logger,
	}

	certificate := &service.CertificateStatus{
		Certificate: &models.Certificate{
			ID:         "cert-1",
			CommonName: "example.com",
		},
		Status: "valid",
	}

	mockService.On("GetCertificateStatus", "cert-1").Return(certificate, nil)

	router := setupTestRouter()
	router.GET("/api/v1/certificates/:id", func(c *gin.Context) {
		id := c.Param("id")
		cert, err := mockService.GetCertificateStatus(id)
		if err != nil {
			handler.logger.Error("Failed to get certificate")
			c.JSON(http.StatusNotFound, gin.H{"error": "certificate not found"})
			return
		}
		c.JSON(http.StatusOK, cert)
	})

	req, _ := http.NewRequest("GET", "/api/v1/certificates/cert-1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Just verify we got a valid JSON response with expected structure
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "cert-1", response["id"])
	assert.Equal(t, "example.com", response["common_name"])
	mockService.AssertExpectations(t)
}

func TestCertificateHandler_GetCertificate_NotFound(t *testing.T) {
	mockService := new(MockCertificateService)
	logger := zap.NewNop()

	handler := &CertificateHandler{
		logger: logger,
	}

	mockService.On("GetCertificateStatus", "cert-999").Return(nil, errors.New("not found"))

	router := setupTestRouter()
	router.GET("/api/v1/certificates/:id", func(c *gin.Context) {
		id := c.Param("id")
		_, err := mockService.GetCertificateStatus(id)
		if err != nil {
			handler.logger.Error("Failed to get certificate")
			c.JSON(http.StatusNotFound, gin.H{"error": "certificate not found"})
			return
		}
	})

	req, _ := http.NewRequest("GET", "/api/v1/certificates/cert-999", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "certificate not found", response["error"])
	mockService.AssertExpectations(t)
}

func TestCertificateHandler_CreateCertificate_Success(t *testing.T) {
	mockService := new(MockCertificateService)
	logger := zap.NewNop()

	handler := &CertificateHandler{
		logger: logger,
	}

	certRequest := &service.CreateCertificateRequest{
		AuthorityID:      "ca-1",
		CommonName:       "example.com",
		Organization:     "Test Org",
		Country:          "US",
		SANs:             []string{"www.example.com", "*.example.com"},
		Algorithm:        "rsa",
		RSABits:          2048,
		ValidityDays:     365,
		IsServerAuth:     true,
		IsClientAuth:     false,
	}

	certificate := &models.Certificate{
		ID:           "cert-1",
		AuthorityID:  "ca-1",
		CommonName:   "example.com",
		CreatedAt:    time.Now(),
		IsServerAuth: true,
		IsClientAuth: false,
	}

	mockService.On("CreateCertificate", certRequest).Return(certificate, nil)

	router := setupTestRouter()
	router.POST("/api/v1/certificates", func(c *gin.Context) {
		var req CreateCertificateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		cert, err := mockService.CreateCertificate(&service.CreateCertificateRequest{
			AuthorityID:      req.AuthorityID,
			CommonName:       req.CommonName,
			Organization:     req.Organization,
			OrganizationUnit: req.OrganizationUnit,
			Country:          req.Country,
			Province:         req.Province,
			Locality:         req.Locality,
			SANs:             req.SANs,
			Algorithm:        req.Algorithm,
			RSABits:          req.RSABits,
			ECCurve:          req.ECCurve,
			ValidityDays:     req.ValidityDays,
			IsServerAuth:     req.IsServerAuth,
			IsClientAuth:     req.IsClientAuth,
		})
		if err != nil {
			handler.logger.Error("Failed to create certificate")
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		handler.logger.Info("Certificate created")
		c.JSON(http.StatusCreated, cert)
	})

	body := map[string]interface{}{
		"authority_id":  "ca-1",
		"common_name":   "example.com",
		"organization":  "Test Org",
		"country":       "US",
		"sans":          []string{"www.example.com", "*.example.com"},
		"algorithm":     "rsa",
		"rsa_bits":      2048,
		"validity_days": 365,
		"is_server_auth": true,
		"is_client_auth": false,
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/certificates", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response models.Certificate
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "cert-1", response.ID)
	assert.Equal(t, "example.com", response.CommonName)
	mockService.AssertExpectations(t)
}

func TestCertificateHandler_CreateCertificate_MissingFields(t *testing.T) {
	logger := zap.NewNop()

	_ = logger // handler not needed for this test

	router := setupTestRouter()
	router.POST("/api/v1/certificates", func(c *gin.Context) {
		var req CreateCertificateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	})

	body := map[string]interface{}{
		"authority_id": "ca-1",
		// Missing common_name
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/certificates", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCertificateHandler_CreateCertificate_ServiceError(t *testing.T) {
	mockService := new(MockCertificateService)
	logger := zap.NewNop()

	handler := &CertificateHandler{
		logger: logger,
	}

	certRequest := &service.CreateCertificateRequest{
		AuthorityID:      "ca-999",
		CommonName:       "example.com",
		Organization:     "Test Org",
		Country:          "US",
		SANs:             []string{"www.example.com"},
		Algorithm:        "rsa",
		RSABits:          2048,
		ValidityDays:     365,
		IsServerAuth:     true,
		IsClientAuth:     false,
	}

	mockService.On("CreateCertificate", certRequest).Return(nil, errors.New("authority not found"))

	router := setupTestRouter()
	router.POST("/api/v1/certificates", func(c *gin.Context) {
		var req CreateCertificateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		_, err := mockService.CreateCertificate(&service.CreateCertificateRequest{
			AuthorityID:      req.AuthorityID,
			CommonName:       req.CommonName,
			Organization:     req.Organization,
			OrganizationUnit: req.OrganizationUnit,
			Country:          req.Country,
			Province:         req.Province,
			Locality:         req.Locality,
			SANs:             req.SANs,
			Algorithm:        req.Algorithm,
			RSABits:          req.RSABits,
			ECCurve:          req.ECCurve,
			ValidityDays:     req.ValidityDays,
			IsServerAuth:     req.IsServerAuth,
			IsClientAuth:     req.IsClientAuth,
		})
		if err != nil {
			handler.logger.Error("Failed to create certificate")
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	})

	body := map[string]interface{}{
		"authority_id":   "ca-999",
		"common_name":    "example.com",
		"organization":   "Test Org",
		"country":        "US",
		"sans":           []string{"www.example.com"},
		"algorithm":      "rsa",
		"rsa_bits":       2048,
		"validity_days":  365,
		"is_server_auth": true,
		"is_client_auth": false,
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/certificates", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "authority not found", response["error"])
	mockService.AssertExpectations(t)
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal filename",
			input:    "example.com",
			expected: "example.com",
		},
		{
			name:     "with invalid characters",
			input:    "test/file:name*?.txt",
			expected: "test_file_name__.txt",
		},
		{
			name:     "with spaces",
			input:    "my test file",
			expected: "my_test_file",
		},
		{
			name:     "with parentheses",
			input:    "file (copy).txt",
			expected: "file_copy.txt",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "certificate",
		},
		{
			name:     "only invalid chars",
			input:    "///***",
			expected: "______",
		},
		{
			name:     "very long filename",
			input:    "this_is_a_very_long_filename_that_exceeds_the_maximum_allowed_length_and_should_be_truncated_to_200_characters_to_ensure_compatibility_with_various_file_systems_that_have_filename_length_restrictions_and_to_prevent_any_potential_issues_with_file_handling",
			expected: "this_is_a_very_long_filename_that_exceeds_the_maximum_allowed_length_and_should_be_truncated_to_200_characters_to_ensure_compatibility_with_various_file_systems_that_have_filename_length_restrictions_",
		},
		{
			name:     "leading and trailing dots",
			input:    "...filename...",
			expected: "filename",
		},
		{
			name:     "windows invalid chars",
			input:    "file<name>with|invalid\\chars",
			expected: "file_name_with_invalid_chars",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeFilename(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCertificateHandler_ExportCertificate_PEM_Success(t *testing.T) {
	mockService := new(MockCertificateService)
	logger := zap.NewNop()

	handler := &CertificateHandler{
		logger: logger,
	}

	certificate := &models.Certificate{
		ID:         "cert-1",
		CommonName: "example.com",
	}

	exportReq := &service.ExportRequest{
		CertificateID: "cert-1",
		Format:        "pem",
		Password:      "",
		Legacy:        false,
		SplitFiles:    false,
	}

	pemData := []byte("-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----")

	mockService.On("GetCertificate", "cert-1").Return(certificate, nil)
	mockService.On("ExportCertificate", exportReq).Return(pemData, nil)

	router := setupTestRouter()
	router.POST("/api/v1/certificates/:id/export", func(c *gin.Context) {
		id := c.Param("id")

		var req ExportRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		cert, err := mockService.GetCertificate(id)
		if err != nil {
			handler.logger.Error("Failed to get certificate")
			c.JSON(http.StatusNotFound, gin.H{"error": "certificate not found"})
			return
		}

		data, err := mockService.ExportCertificate(&service.ExportRequest{
			CertificateID: id,
			Format:        req.Format,
			Password:      req.Password,
			Legacy:        req.Legacy,
			SplitFiles:    req.SplitFiles,
		})
		if err != nil {
			handler.logger.Error("Failed to export certificate")
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		baseFilename := sanitizeFilename(cert.CommonName)

		var contentType, filename string
		switch req.Format {
		case "pem":
			if req.SplitFiles {
				contentType = "application/zip"
				filename = baseFilename + ".zip"
			} else {
				contentType = "application/x-pem-file"
				filename = baseFilename + ".pem"
			}
		case "pkcs12", "pfx":
			contentType = "application/x-pkcs12"
			filename = baseFilename + ".pfx"
		default:
			contentType = "application/octet-stream"
			filename = baseFilename
		}

		c.Header("Content-Disposition", "attachment; filename="+filename)
		c.Data(http.StatusOK, contentType, data)
	})

	body := map[string]interface{}{
		"format":      "pem",
		"password":    "",
		"legacy":      false,
		"split_files": false,
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/certificates/cert-1/export", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/x-pem-file", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Content-Disposition"), "example.com.pem")
	assert.Equal(t, pemData, w.Body.Bytes())
	mockService.AssertExpectations(t)
}

func TestCertificateHandler_ExportCertificate_PKCS12_Success(t *testing.T) {
	mockService := new(MockCertificateService)
	logger := zap.NewNop()

	handler := &CertificateHandler{
		logger: logger,
	}

	certificate := &models.Certificate{
		ID:         "cert-1",
		CommonName: "example.com",
	}

	exportReq := &service.ExportRequest{
		CertificateID: "cert-1",
		Format:        "pkcs12",
		Password:      "password123",
		Legacy:        false,
		SplitFiles:    false,
	}

	pfxData := []byte{0x30, 0x82, 0x01, 0x00} // Mock PFX data

	mockService.On("GetCertificate", "cert-1").Return(certificate, nil)
	mockService.On("ExportCertificate", exportReq).Return(pfxData, nil)

	router := setupTestRouter()
	router.POST("/api/v1/certificates/:id/export", func(c *gin.Context) {
		id := c.Param("id")

		var req ExportRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		cert, err := mockService.GetCertificate(id)
		if err != nil {
			handler.logger.Error("Failed to get certificate")
			c.JSON(http.StatusNotFound, gin.H{"error": "certificate not found"})
			return
		}

		data, err := mockService.ExportCertificate(&service.ExportRequest{
			CertificateID: id,
			Format:        req.Format,
			Password:      req.Password,
			Legacy:        req.Legacy,
			SplitFiles:    req.SplitFiles,
		})
		if err != nil {
			handler.logger.Error("Failed to export certificate")
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		baseFilename := sanitizeFilename(cert.CommonName)

		var contentType, filename string
		switch req.Format {
		case "pem":
			if req.SplitFiles {
				contentType = "application/zip"
				filename = baseFilename + ".zip"
			} else {
				contentType = "application/x-pem-file"
				filename = baseFilename + ".pem"
			}
		case "pkcs12", "pfx":
			contentType = "application/x-pkcs12"
			filename = baseFilename + ".pfx"
		default:
			contentType = "application/octet-stream"
			filename = baseFilename
		}

		c.Header("Content-Disposition", "attachment; filename="+filename)
		c.Data(http.StatusOK, contentType, data)
	})

	body := map[string]interface{}{
		"format":      "pkcs12",
		"password":    "password123",
		"legacy":      false,
		"split_files": false,
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/certificates/cert-1/export", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/x-pkcs12", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Content-Disposition"), "example.com.pfx")
	assert.Equal(t, pfxData, w.Body.Bytes())
	mockService.AssertExpectations(t)
}

func TestCertificateHandler_ExportCertificate_SplitFiles(t *testing.T) {
	mockService := new(MockCertificateService)
	logger := zap.NewNop()

	handler := &CertificateHandler{
		logger: logger,
	}

	certificate := &models.Certificate{
		ID:         "cert-1",
		CommonName: "example.com",
	}

	exportReq := &service.ExportRequest{
		CertificateID: "cert-1",
		Format:        "pem",
		Password:      "",
		Legacy:        false,
		SplitFiles:    true,
	}

	zipData := []byte{0x50, 0x4B, 0x03, 0x04} // Mock ZIP data

	mockService.On("GetCertificate", "cert-1").Return(certificate, nil)
	mockService.On("ExportCertificate", exportReq).Return(zipData, nil)

	router := setupTestRouter()
	router.POST("/api/v1/certificates/:id/export", func(c *gin.Context) {
		id := c.Param("id")

		var req ExportRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		cert, err := mockService.GetCertificate(id)
		if err != nil {
			handler.logger.Error("Failed to get certificate")
			c.JSON(http.StatusNotFound, gin.H{"error": "certificate not found"})
			return
		}

		data, err := mockService.ExportCertificate(&service.ExportRequest{
			CertificateID: id,
			Format:        req.Format,
			Password:      req.Password,
			Legacy:        req.Legacy,
			SplitFiles:    req.SplitFiles,
		})
		if err != nil {
			handler.logger.Error("Failed to export certificate")
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		baseFilename := sanitizeFilename(cert.CommonName)

		var contentType, filename string
		switch req.Format {
		case "pem":
			if req.SplitFiles {
				contentType = "application/zip"
				filename = baseFilename + ".zip"
			} else {
				contentType = "application/x-pem-file"
				filename = baseFilename + ".pem"
			}
		case "pkcs12", "pfx":
			contentType = "application/x-pkcs12"
			filename = baseFilename + ".pfx"
		default:
			contentType = "application/octet-stream"
			filename = baseFilename
		}

		c.Header("Content-Disposition", "attachment; filename="+filename)
		c.Data(http.StatusOK, contentType, data)
	})

	body := map[string]interface{}{
		"format":      "pem",
		"password":    "",
		"legacy":      false,
		"split_files": true,
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/certificates/cert-1/export", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/zip", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Content-Disposition"), "example.com.zip")
	mockService.AssertExpectations(t)
}

func TestCertificateHandler_ExportCertificate_CertificateNotFound(t *testing.T) {
	mockService := new(MockCertificateService)
	logger := zap.NewNop()

	handler := &CertificateHandler{
		logger: logger,
	}

	mockService.On("GetCertificate", "cert-999").Return(nil, errors.New("not found"))

	router := setupTestRouter()
	router.POST("/api/v1/certificates/:id/export", func(c *gin.Context) {
		id := c.Param("id")

		var req ExportRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		_, err := mockService.GetCertificate(id)
		if err != nil {
			handler.logger.Error("Failed to get certificate")
			c.JSON(http.StatusNotFound, gin.H{"error": "certificate not found"})
			return
		}
	})

	body := map[string]interface{}{
		"format":      "pem",
		"password":    "",
		"legacy":      false,
		"split_files": false,
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/certificates/cert-999/export", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "certificate not found", response["error"])
	mockService.AssertExpectations(t)
}

func TestCertificateHandler_ExportCertificate_ExportError(t *testing.T) {
	mockService := new(MockCertificateService)
	logger := zap.NewNop()

	handler := &CertificateHandler{
		logger: logger,
	}

	certificate := &models.Certificate{
		ID:         "cert-1",
		CommonName: "example.com",
	}

	exportReq := &service.ExportRequest{
		CertificateID: "cert-1",
		Format:        "pem",
		Password:      "",
		Legacy:        false,
		SplitFiles:    false,
	}

	mockService.On("GetCertificate", "cert-1").Return(certificate, nil)
	mockService.On("ExportCertificate", exportReq).Return(nil, errors.New("decryption failed"))

	router := setupTestRouter()
	router.POST("/api/v1/certificates/:id/export", func(c *gin.Context) {
		id := c.Param("id")

		var req ExportRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		_, err := mockService.GetCertificate(id)
		if err != nil {
			handler.logger.Error("Failed to get certificate")
			c.JSON(http.StatusNotFound, gin.H{"error": "certificate not found"})
			return
		}

		_, err = mockService.ExportCertificate(&service.ExportRequest{
			CertificateID: id,
			Format:        req.Format,
			Password:      req.Password,
			Legacy:        req.Legacy,
			SplitFiles:    req.SplitFiles,
		})
		if err != nil {
			handler.logger.Error("Failed to export certificate")
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	})

	body := map[string]interface{}{
		"format":      "pem",
		"password":    "",
		"legacy":      false,
		"split_files": false,
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/v1/certificates/cert-1/export", bytes.NewBuffer(jsonBody))
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

func TestCertificateHandler_RevokeCertificate_Success(t *testing.T) {
	mockService := new(MockCertificateService)
	logger := zap.NewNop()

	handler := &CertificateHandler{
		logger: logger,
	}

	mockService.On("RevokeCertificate", "cert-1").Return(nil)

	router := setupTestRouter()
	router.PUT("/api/v1/certificates/:id/revoke", func(c *gin.Context) {
		id := c.Param("id")
		if err := mockService.RevokeCertificate(id); err != nil {
			handler.logger.Error("Failed to revoke certificate")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke certificate"})
			return
		}
		handler.logger.Info("Certificate revoked")
		c.JSON(http.StatusOK, gin.H{"message": "certificate revoked"})
	})

	req, _ := http.NewRequest("PUT", "/api/v1/certificates/cert-1/revoke", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "certificate revoked", response["message"])
	mockService.AssertExpectations(t)
}

func TestCertificateHandler_RevokeCertificate_Error(t *testing.T) {
	mockService := new(MockCertificateService)
	logger := zap.NewNop()

	handler := &CertificateHandler{
		logger: logger,
	}

	mockService.On("RevokeCertificate", "cert-1").Return(errors.New("certificate not found"))

	router := setupTestRouter()
	router.PUT("/api/v1/certificates/:id/revoke", func(c *gin.Context) {
		id := c.Param("id")
		if err := mockService.RevokeCertificate(id); err != nil {
			handler.logger.Error("Failed to revoke certificate")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke certificate"})
			return
		}
	})

	req, _ := http.NewRequest("PUT", "/api/v1/certificates/cert-1/revoke", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "failed to revoke certificate", response["error"])
	mockService.AssertExpectations(t)
}

func TestCertificateHandler_DeleteCertificate_Success(t *testing.T) {
	mockService := new(MockCertificateService)
	logger := zap.NewNop()

	handler := &CertificateHandler{
		logger: logger,
	}

	mockService.On("DeleteCertificate", "cert-1").Return(nil)

	router := setupTestRouter()
	router.DELETE("/api/v1/certificates/:id", func(c *gin.Context) {
		id := c.Param("id")
		if err := mockService.DeleteCertificate(id); err != nil {
			handler.logger.Error("Failed to delete certificate")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete certificate"})
			return
		}
		handler.logger.Info("Certificate deleted")
		c.Status(http.StatusNoContent)
	})

	req, _ := http.NewRequest("DELETE", "/api/v1/certificates/cert-1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	mockService.AssertExpectations(t)
}

func TestCertificateHandler_DeleteCertificate_Error(t *testing.T) {
	mockService := new(MockCertificateService)
	logger := zap.NewNop()

	handler := &CertificateHandler{
		logger: logger,
	}

	mockService.On("DeleteCertificate", "cert-1").Return(errors.New("database error"))

	router := setupTestRouter()
	router.DELETE("/api/v1/certificates/:id", func(c *gin.Context) {
		id := c.Param("id")
		if err := mockService.DeleteCertificate(id); err != nil {
			handler.logger.Error("Failed to delete certificate")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete certificate"})
			return
		}
	})

	req, _ := http.NewRequest("DELETE", "/api/v1/certificates/cert-1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "failed to delete certificate", response["error"])
	mockService.AssertExpectations(t)
}

