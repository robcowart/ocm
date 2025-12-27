package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/robcowart/ocm/internal/service"
	"go.uber.org/zap"
)

// AuthHandler handles authentication operations
type AuthHandler struct {
	userService *service.UserService
	logger      *zap.Logger
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(userService *service.UserService, logger *zap.Logger) *AuthHandler {
	return &AuthHandler{
		userService: userService,
		logger:      logger,
	}
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// Login authenticates a user
// @Summary User login
// @Description Authenticate user and return JWT token
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Login credentials"
// @Success 200 {object} map[string]string
// @Router /api/v1/auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	token, err := h.userService.AuthenticateUser(req.Username, req.Password)
	if err != nil {
		h.logger.Warn("Login failed", zap.String("username", req.Username), zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	h.logger.Info("User logged in", zap.String("username", req.Username))

	c.JSON(http.StatusOK, gin.H{
		"token": token,
	})
}

// GetCurrentUser returns the currently authenticated user
// @Summary Get current user
// @Description Get information about the currently authenticated user
// @Success 200 {object} map[string]string
// @Router /api/v1/auth/me [get]
func (h *AuthHandler) GetCurrentUser(c *gin.Context) {
	userID, _ := c.Get("user_id")
	username, _ := c.Get("username")
	role, _ := c.Get("role")

	c.JSON(http.StatusOK, gin.H{
		"user_id":  userID,
		"username": username,
		"role":     role,
	})
}
