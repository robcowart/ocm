// Package api provides HTTP routing and server configuration for the Open Certificate Manager.
// It wires together handlers, middleware, and services to create the application's API endpoints.
package api

import (
	"github.com/gin-gonic/gin"
	"github.com/robcowart/ocm/internal/api/handlers"
	"github.com/robcowart/ocm/internal/api/middleware"
	"github.com/robcowart/ocm/internal/config"
	"github.com/robcowart/ocm/internal/database"
	"github.com/robcowart/ocm/internal/service"
	"go.uber.org/zap"
)

// NewRouter creates and configures the HTTP router
func NewRouter(cfg *config.Config, db *database.Database, logger *zap.Logger) *gin.Engine {
	// Set Gin mode
	if cfg.Logging.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Global middleware
	router.Use(gin.Recovery())
	router.Use(middleware.LoggerMiddleware(logger))
	router.Use(middleware.CORSMiddleware(cfg))

	// Initialize services
	userService := service.NewUserService(db, cfg)

	// Try to load JWT secret from database if it exists
	_ = userService.LoadJWTSecret()

	caService := service.NewCAService(db, cfg, userService)
	certService := service.NewCertificateService(db, caService, cfg, userService)

	// Initialize handlers
	setupHandler := handlers.NewSetupHandler(userService, logger)
	authHandler := handlers.NewAuthHandler(userService, logger)
	caHandler := handlers.NewCAHandler(caService, logger)
	certHandler := handlers.NewCertificateHandler(certService, logger)

	// Public routes
	public := router.Group("/api/v1")
	{
		// Setup routes (no auth required)
		public.GET("/setup/status", setupHandler.GetStatus)
		public.POST("/setup", setupHandler.PerformSetup)

		// Auth routes
		public.POST("/auth/login", authHandler.Login)
	}

	// Protected routes (require authentication)
	protected := router.Group("/api/v1")
	protected.Use(middleware.AuthMiddleware(cfg))
	{
		// Auth
		protected.GET("/auth/me", authHandler.GetCurrentUser)

		// Certificate Authorities
		protected.GET("/authorities", caHandler.ListAuthorities)
		protected.GET("/authorities/:id", caHandler.GetAuthority)
		protected.POST("/authorities", caHandler.CreateRootCA)
		protected.POST("/authorities/import", caHandler.ImportCA)
		protected.POST("/authorities/:id/export", caHandler.ExportAuthority)
		protected.DELETE("/authorities/:id", caHandler.DeleteAuthority)

		// Certificates
		protected.GET("/certificates", certHandler.ListCertificates)
		protected.GET("/certificates/:id", certHandler.GetCertificate)
		protected.POST("/certificates", certHandler.CreateCertificate)
		protected.POST("/certificates/:id/export", certHandler.ExportCertificate)
		protected.PUT("/certificates/:id/revoke", certHandler.RevokeCertificate)
		protected.DELETE("/certificates/:id", certHandler.DeleteCertificate)
	}

	// Serve static frontend files
	router.Static("/assets", "./static/assets")
	// router.StaticFile("/favicon.ico", "./static/favicon.ico")
	// router.StaticFile("/vite.svg", "./static/vite.svg")

	// SPA fallback - serve index.html for all other routes
	router.NoRoute(func(c *gin.Context) {
		c.File("./static/index.html")
	})

	return router
}
