package handlers

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/robcowart/ocm/internal/service"
	"go.uber.org/zap"
)

// CertificateHandler handles certificate operations
type CertificateHandler struct {
	certService *service.CertificateService
	logger      *zap.Logger
}

// NewCertificateHandler creates a new certificate handler
func NewCertificateHandler(certService *service.CertificateService, logger *zap.Logger) *CertificateHandler {
	return &CertificateHandler{
		certService: certService,
		logger:      logger,
	}
}

// ListCertificates lists all certificates
// @Summary List certificates
// @Description List all certificates
// @Produce json
// @Success 200 {array} service.CertificateStatus
// @Router /api/v1/certificates [get]
func (h *CertificateHandler) ListCertificates(c *gin.Context) {
	certificates, err := h.certService.ListCertificatesWithStatus()
	if err != nil {
		h.logger.Error("Failed to list certificates", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list certificates"})
		return
	}

	c.JSON(http.StatusOK, certificates)
}

// GetCertificate gets a specific certificate
// @Summary Get certificate
// @Description Get a specific certificate by ID
// @Produce json
// @Param id path string true "Certificate ID"
// @Success 200 {object} service.CertificateStatus
// @Router /api/v1/certificates/{id} [get]
func (h *CertificateHandler) GetCertificate(c *gin.Context) {
	id := c.Param("id")

	certificate, err := h.certService.GetCertificateStatus(id)
	if err != nil {
		h.logger.Error("Failed to get certificate", zap.String("id", id), zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "certificate not found"})
		return
	}

	c.JSON(http.StatusOK, certificate)
}

// CreateCertificateRequest represents a request to create a certificate
type CreateCertificateRequest struct {
	AuthorityID      string   `json:"authority_id" binding:"required"`
	CommonName       string   `json:"common_name" binding:"required"`
	Organization     string   `json:"organization"`
	OrganizationUnit string   `json:"organization_unit"`
	Country          string   `json:"country"`
	Province         string   `json:"province"`
	Locality         string   `json:"locality"`
	SANs             []string `json:"sans"`
	Algorithm        string   `json:"algorithm"`
	RSABits          int      `json:"rsa_bits"`
	ECCurve          string   `json:"ec_curve"`
	ValidityDays     int      `json:"validity_days"`
	IsServerAuth     bool     `json:"is_server_auth"`
	IsClientAuth     bool     `json:"is_client_auth"`
}

// CreateCertificate creates a new certificate
// @Summary Create certificate
// @Description Create a new certificate signed by a CA
// @Accept json
// @Produce json
// @Param request body CreateCertificateRequest true "Certificate request"
// @Success 201 {object} models.Certificate
// @Router /api/v1/certificates [post]
func (h *CertificateHandler) CreateCertificate(c *gin.Context) {
	var req CreateCertificateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	certificate, err := h.certService.CreateCertificate(&service.CreateCertificateRequest{
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
		h.logger.Error("Failed to create certificate", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.logger.Info("Certificate created", zap.String("id", certificate.ID), zap.String("cn", certificate.CommonName))

	c.JSON(http.StatusCreated, certificate)
}

// sanitizeFilename sanitizes a string to be safe for use as a filename
func sanitizeFilename(name string) string {
	// Replace invalid filename characters with underscores
	invalidChars := regexp.MustCompile(`[/\\:*?"<>|]`)
	sanitized := invalidChars.ReplaceAllString(name, "_")
	
	// Replace spaces with underscores
	sanitized = strings.ReplaceAll(sanitized, " ", "_")
	
	// Remove parentheses
	sanitized = strings.ReplaceAll(sanitized, "(", "")
	sanitized = strings.ReplaceAll(sanitized, ")", "")
	
	// Trim leading/trailing dots and spaces
	sanitized = strings.Trim(sanitized, ". ")
	
	// Limit length to 200 characters
	if len(sanitized) > 200 {
		sanitized = sanitized[:200]
	}
	
	// If empty after sanitization, use default
	if sanitized == "" {
		sanitized = "certificate"
	}
	
	return sanitized
}

// ExportRequest represents a request to export a certificate
type ExportRequest struct {
	Format     string `json:"format" binding:"required"` // "pem" or "pkcs12"
	Password   string `json:"password"`                  // For PKCS12
	Legacy     bool   `json:"legacy"`                    // Use legacy encryption
	SplitFiles bool   `json:"split_files"`               // Export cert and key as separate files (PEM only)
}

// ExportCertificate exports a certificate
// @Summary Export certificate
// @Description Export a certificate in PEM or PKCS#12 format. Use split_files for separate cert/key files.
// @Accept json
// @Produce application/octet-stream
// @Param id path string true "Certificate ID"
// @Param request body ExportRequest true "Export request"
// @Success 200 {file} binary
// @Router /api/v1/certificates/{id}/export [post]
func (h *CertificateHandler) ExportCertificate(c *gin.Context) {
	id := c.Param("id")

	var req ExportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get certificate to retrieve its common name
	cert, err := h.certService.GetCertificate(id)
	if err != nil {
		h.logger.Error("Failed to get certificate", zap.String("id", id), zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "certificate not found"})
		return
	}

	data, err := h.certService.ExportCertificate(&service.ExportRequest{
		CertificateID: id,
		Format:        req.Format,
		Password:      req.Password,
		Legacy:        req.Legacy,
		SplitFiles:    req.SplitFiles,
	})
	if err != nil {
		h.logger.Error("Failed to export certificate", zap.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Sanitize the common name for use as filename
	baseFilename := sanitizeFilename(cert.CommonName)

	// Set content type and filename based on format
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
}

// RevokeCertificate revokes a certificate
// @Summary Revoke certificate
// @Description Revoke a certificate
// @Param id path string true "Certificate ID"
// @Success 200 {object} map[string]string
// @Router /api/v1/certificates/{id}/revoke [put]
func (h *CertificateHandler) RevokeCertificate(c *gin.Context) {
	id := c.Param("id")

	if err := h.certService.RevokeCertificate(id); err != nil {
		h.logger.Error("Failed to revoke certificate", zap.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke certificate"})
		return
	}

	h.logger.Info("Certificate revoked", zap.String("id", id))

	c.JSON(http.StatusOK, gin.H{"message": "certificate revoked"})
}

// DeleteCertificate deletes a certificate
// @Summary Delete certificate
// @Description Delete a certificate by ID
// @Param id path string true "Certificate ID"
// @Success 204 "No Content"
// @Router /api/v1/certificates/{id} [delete]
func (h *CertificateHandler) DeleteCertificate(c *gin.Context) {
	id := c.Param("id")

	if err := h.certService.DeleteCertificate(id); err != nil {
		h.logger.Error("Failed to delete certificate", zap.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete certificate"})
		return
	}

	h.logger.Info("Certificate deleted", zap.String("id", id))

	c.Status(http.StatusNoContent)
}
