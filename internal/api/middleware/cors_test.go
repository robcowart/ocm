package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/robcowart/ocm/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestCORSMiddleware(t *testing.T) {
	t.Run("CORS enabled with allowed origins", func(t *testing.T) {
		cfg := &config.Config{
			Security: config.SecurityConfig{
				CORSEnabled: true,
				CORSOrigins: []string{"http://localhost:3000", "http://localhost:8000"},
			},
		}

		router := setupTestRouter()
		router.Use(CORSMiddleware(cfg))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// Test preflight request
		req, _ := http.NewRequest(http.MethodOptions, "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		req.Header.Set("Access-Control-Request-Method", "GET")
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Origin"), "http://localhost:3000")
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "GET")
	})

	t.Run("CORS enabled allows actual request from allowed origin", func(t *testing.T) {
		cfg := &config.Config{
			Security: config.SecurityConfig{
				CORSEnabled: true,
				CORSOrigins: []string{"http://localhost:3000"},
			},
		}

		router := setupTestRouter()
		router.Use(CORSMiddleware(cfg))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("CORS enabled blocks request from disallowed origin", func(t *testing.T) {
		cfg := &config.Config{
			Security: config.SecurityConfig{
				CORSEnabled: true,
				CORSOrigins: []string{"http://localhost:3000"},
			},
		}

		router := setupTestRouter()
		router.Use(CORSMiddleware(cfg))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "http://evil.com")
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Request succeeds but CORS headers should not allow the origin
		assert.NotEqual(t, "http://evil.com", w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("CORS disabled allows all requests without CORS headers", func(t *testing.T) {
		cfg := &config.Config{
			Security: config.SecurityConfig{
				CORSEnabled: false,
			},
		}

		router := setupTestRouter()
		router.Use(CORSMiddleware(cfg))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		// When CORS is disabled, no CORS headers should be set
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("CORS allows standard HTTP methods", func(t *testing.T) {
		cfg := &config.Config{
			Security: config.SecurityConfig{
				CORSEnabled: true,
				CORSOrigins: []string{"http://localhost:3000"},
			},
		}

		router := setupTestRouter()
		router.Use(CORSMiddleware(cfg))
		
		// Add handlers for different methods
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"method": "GET"})
		})
		router.POST("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"method": "POST"})
		})
		router.PUT("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"method": "PUT"})
		})
		router.DELETE("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"method": "DELETE"})
		})

		methods := []string{"GET", "POST", "PUT", "DELETE"}
		for _, method := range methods {
			t.Run(method, func(t *testing.T) {
				// Preflight request
				req, _ := http.NewRequest(http.MethodOptions, "/test", nil)
				req.Header.Set("Origin", "http://localhost:3000")
				req.Header.Set("Access-Control-Request-Method", method)
				
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				assert.Equal(t, http.StatusNoContent, w.Code)
				assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), method)
			})
		}
	})

	t.Run("CORS allows required headers", func(t *testing.T) {
		cfg := &config.Config{
			Security: config.SecurityConfig{
				CORSEnabled: true,
				CORSOrigins: []string{"http://localhost:3000"},
			},
		}

		router := setupTestRouter()
		router.Use(CORSMiddleware(cfg))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// Preflight request with headers
		req, _ := http.NewRequest(http.MethodOptions, "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "Authorization,Content-Type")
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		allowedHeaders := w.Header().Get("Access-Control-Allow-Headers")
		assert.Contains(t, allowedHeaders, "Authorization")
		assert.Contains(t, allowedHeaders, "Content-Type")
	})

	t.Run("CORS allows credentials", func(t *testing.T) {
		cfg := &config.Config{
			Security: config.SecurityConfig{
				CORSEnabled: true,
				CORSOrigins: []string{"http://localhost:3000"},
			},
		}

		router := setupTestRouter()
		router.Use(CORSMiddleware(cfg))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
	})

	t.Run("CORS with multiple origins", func(t *testing.T) {
		cfg := &config.Config{
			Security: config.SecurityConfig{
				CORSEnabled: true,
				CORSOrigins: []string{"http://localhost:3000", "http://localhost:8000", "https://example.com"},
			},
		}

		router := setupTestRouter()
		router.Use(CORSMiddleware(cfg))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// Test each origin
		origins := []string{"http://localhost:3000", "http://localhost:8000", "https://example.com"}
		for _, origin := range origins {
			t.Run(origin, func(t *testing.T) {
				req, _ := http.NewRequest(http.MethodGet, "/test", nil)
				req.Header.Set("Origin", origin)
				
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				assert.Equal(t, http.StatusOK, w.Code)
				assert.Equal(t, origin, w.Header().Get("Access-Control-Allow-Origin"))
			})
		}
	})
}

