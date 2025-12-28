package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/robcowart/ocm/internal/service"
	"go.uber.org/zap"
)

// CAHandler handles Certificate Authority operations
type CAHandler struct {
	caService *service.CAService
	logger    *zap.Logger
}

// NewCAHandler creates a new CA handler
func NewCAHandler(caService *service.CAService, logger *zap.Logger) *CAHandler {
	return &CAHandler{
		caService: caService,
		logger:    logger,
	}
}

// ListAuthorities lists all Certificate Authorities
// @Summary List CAs
// @Description List all Certificate Authorities
// @Produce json
// @Success 200 {array} service.AuthorityStatus
// @Router /api/v1/authorities [get]
func (h *CAHandler) ListAuthorities(c *gin.Context) {
	authorities, err := h.caService.ListAuthoritiesWithStatus()
	if err != nil {
		h.logger.Error("Failed to list authorities", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list authorities"})
		return
	}

	c.JSON(http.StatusOK, authorities)
}

// GetAuthority gets a specific CA
// @Summary Get CA
// @Description Get a specific Certificate Authority by ID
// @Produce json
// @Param id path string true "Authority ID"
// @Success 200 {object} service.AuthorityStatus
// @Router /api/v1/authorities/{id} [get]
func (h *CAHandler) GetAuthority(c *gin.Context) {
	id := c.Param("id")

	authority, err := h.caService.GetAuthorityStatus(id)
	if err != nil {
		h.logger.Error("Failed to get authority", zap.String("id", id), zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "authority not found"})
		return
	}

	c.JSON(http.StatusOK, authority)
}

// CreateRootCARequest represents a request to create a Root CA
type CreateRootCARequest struct {
	FriendlyName     string `json:"friendly_name" binding:"required"`
	CommonName       string `json:"common_name" binding:"required"`
	Organization     string `json:"organization"`
	OrganizationUnit string `json:"organization_unit"`
	Country          string `json:"country"`
	Province         string `json:"province"`
	Locality         string `json:"locality"`
	Algorithm        string `json:"algorithm"` // "rsa" or "ecdsa"
	RSABits          int    `json:"rsa_bits"`
	ECCurve          string `json:"ec_curve"` // "P256" or "P384"
	ValidityDays     int    `json:"validity_days"`
}

// CreateRootCA creates a new self-signed Root CA
// @Summary Create Root CA
// @Description Create a new self-signed Root Certificate Authority
// @Accept json
// @Produce json
// @Param request body CreateRootCARequest true "CA request"
// @Success 201 {object} models.Authority
// @Router /api/v1/authorities [post]
func (h *CAHandler) CreateRootCA(c *gin.Context) {
	var req CreateRootCARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	authority, err := h.caService.CreateRootCA(&service.CreateRootCARequest{
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
		h.logger.Error("Failed to create CA", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.logger.Info("Root CA created", zap.String("id", authority.ID), zap.String("cn", authority.CommonName))

	c.JSON(http.StatusCreated, authority)
}

// ImportCARequest represents a request to import a CA
type ImportCARequest struct {
	FriendlyName   string `json:"friendly_name" binding:"required"`
	CertificatePEM string `json:"certificate_pem" binding:"required"`
	PrivateKeyPEM  string `json:"private_key_pem" binding:"required"`
	Password       string `json:"password"`
}

// ImportCA imports an existing CA
// @Summary Import CA
// @Description Import an existing Certificate Authority
// @Accept json
// @Produce json
// @Param request body ImportCARequest true "Import request"
// @Success 201 {object} models.Authority
// @Router /api/v1/authorities/import [post]
func (h *CAHandler) ImportCA(c *gin.Context) {
	var req ImportCARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	authority, err := h.caService.ImportCA(&service.ImportCARequest{
		FriendlyName:   req.FriendlyName,
		CertificatePEM: req.CertificatePEM,
		PrivateKeyPEM:  req.PrivateKeyPEM,
		Password:       req.Password,
	})
	if err != nil {
		h.logger.Error("Failed to import CA", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logger.Info("CA imported", zap.String("id", authority.ID), zap.String("cn", authority.CommonName))

	c.JSON(http.StatusCreated, authority)
}

// DeleteAuthority deletes a Certificate Authority
// @Summary Delete CA
// @Description Delete a Certificate Authority by ID
// @Param id path string true "Authority ID"
// @Success 204 "No Content"
// @Router /api/v1/authorities/{id} [delete]
func (h *CAHandler) DeleteAuthority(c *gin.Context) {
	id := c.Param("id")

	if err := h.caService.DeleteAuthority(id); err != nil {
		h.logger.Error("Failed to delete authority", zap.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete authority"})
		return
	}

	h.logger.Info("CA deleted", zap.String("id", id))
	c.Status(http.StatusNoContent)
}

// ExportAuthorityRequest represents a request to export a CA
type ExportAuthorityRequest struct {
	Format   string `json:"format" binding:"required"` // "pem" or "pkcs12"
	Password string `json:"password"`                  // For PKCS12
	Legacy   bool   `json:"legacy"`                    // Use legacy encryption
	CertOnly bool   `json:"cert_only"`                 // Export certificate only (no private key)
}

// ExportAuthority exports a CA certificate and optionally private key
// @Summary Export CA
// @Description Export a Certificate Authority in PEM or PKCS#12 format. Use cert_only=true for trust anchors.
// @Accept json
// @Produce application/octet-stream
// @Param id path string true "Authority ID"
// @Param request body ExportAuthorityRequest true "Export request"
// @Success 200 {file} binary
// @Router /api/v1/authorities/{id}/export [post]
func (h *CAHandler) ExportAuthority(c *gin.Context) {
	id := c.Param("id")

	var req ExportAuthorityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	data, err := h.caService.ExportAuthority(&service.ExportAuthorityRequest{
		AuthorityID: id,
		Format:      req.Format,
		Password:    req.Password,
		Legacy:      req.Legacy,
		CertOnly:    req.CertOnly,
	})
	if err != nil {
		h.logger.Error("Failed to export authority", zap.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Set content type and filename based on format and cert_only
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
}
