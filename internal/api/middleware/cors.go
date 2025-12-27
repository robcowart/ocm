package middleware

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/robcowart/ocm/internal/config"
)

// CORSMiddleware configures CORS based on configuration
func CORSMiddleware(cfg *config.Config) gin.HandlerFunc {
	if !cfg.Security.CORSEnabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	config := cors.Config{
		AllowOrigins:     cfg.Security.CORSOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}

	return cors.New(config)
}
