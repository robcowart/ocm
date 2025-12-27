// Package handlers provides HTTP request handlers for the Open Certificate Manager API.
// It includes handlers for setup, authentication, certificate authorities, and certificate
// management operations, implementing RESTful endpoints with request validation.
package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/robcowart/ocm/internal/service"
	"go.uber.org/zap"
)

// SetupHandler handles setup operations
type SetupHandler struct {
	userService *service.UserService
	logger      *zap.Logger
}

// NewSetupHandler creates a new setup handler
func NewSetupHandler(userService *service.UserService, logger *zap.Logger) *SetupHandler {
	return &SetupHandler{
		userService: userService,
		logger:      logger,
	}
}

// GetStatus checks if initial setup has been completed.
// @Summary Check setup status
// @Description Check if initial setup has been completed
// @Success 200 {object} map[string]bool
// @Router /api/v1/setup/status [get]
func (h *SetupHandler) GetStatus(c *gin.Context) {
	isComplete, err := h.userService.IsSetupComplete()
	if err != nil {
		h.logger.Error("Failed to check setup status", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check setup status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"setup_complete": isComplete,
	})
}

// SetupRequest represents initial setup request
type SetupRequest struct {
	Username string `json:"username" binding:"required,min=3"`
	Password string `json:"password" binding:"required,min=8"`
}

// PerformSetup handles initial setup
// @Summary Perform initial setup
// @Description Create admin user and generate master key
// @Accept json
// @Produce json
// @Param request body SetupRequest true "Setup request"
// @Success 200 {object} map[string]string
// @Router /api/v1/setup [post]
func (h *SetupHandler) PerformSetup(c *gin.Context) {
	var req SetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.userService.PerformInitialSetup(&service.SetupRequest{
		Username: req.Username,
		Password: req.Password,
	})
	if err != nil {
		h.logger.Error("Setup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.logger.Info("Initial setup completed", zap.String("username", req.Username))

	c.JSON(http.StatusOK, gin.H{
		"message":    "Setup completed successfully",
		"master_key": result.MasterKey,
		"token":      result.Token,
		"username":   result.User.Username,
	})
}
