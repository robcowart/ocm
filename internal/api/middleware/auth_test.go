package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/robcowart/ocm/internal/auth"
	"github.com/robcowart/ocm/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

func TestAuthMiddleware(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:     "test-secret-key-for-testing",
			Expiration: 24 * time.Hour,
			Issuer:     "test-issuer",
		},
	}

	t.Run("Valid token allows access", func(t *testing.T) {
		router := setupTestRouter()
		
		// Add middleware and test endpoint
		router.Use(AuthMiddleware(cfg))
		router.GET("/protected", func(c *gin.Context) {
			userID, _ := c.Get("user_id")
			username, _ := c.Get("username")
			role, _ := c.Get("role")
			
			c.JSON(http.StatusOK, gin.H{
				"user_id":  userID,
				"username": username,
				"role":     role,
			})
		})

		// Generate valid token
		token, err := auth.GenerateToken("user123", "testuser", "admin", cfg.JWT.Secret, cfg.JWT.Issuer, cfg.JWT.Expiration)
		require.NoError(t, err)

		// Make request with valid token
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "user123")
		assert.Contains(t, w.Body.String(), "testuser")
		assert.Contains(t, w.Body.String(), "admin")
	})

	t.Run("Missing Authorization header returns 401", func(t *testing.T) {
		router := setupTestRouter()
		router.Use(AuthMiddleware(cfg))
		router.GET("/protected", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "authorization header required")
	})

	t.Run("Invalid Authorization header format returns 401", func(t *testing.T) {
		router := setupTestRouter()
		router.Use(AuthMiddleware(cfg))
		router.GET("/protected", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		testCases := []struct {
			name   string
			header string
		}{
			{"No Bearer prefix", "invalid-token"},
			{"Wrong prefix", "Basic invalid-token"},
			{"Only Bearer", "Bearer"},
			{"Empty after Bearer", "Bearer "},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
				req.Header.Set("Authorization", tc.header)
				
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				assert.Equal(t, http.StatusUnauthorized, w.Code)
			})
		}
	})

	t.Run("Invalid token returns 401", func(t *testing.T) {
		router := setupTestRouter()
		router.Use(AuthMiddleware(cfg))
		router.GET("/protected", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "invalid or expired token")
	})

	t.Run("Expired token returns 401", func(t *testing.T) {
		router := setupTestRouter()
		router.Use(AuthMiddleware(cfg))
		router.GET("/protected", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// Generate token with very short expiration (already expired)
		token, err := auth.GenerateToken("user123", "testuser", "admin", cfg.JWT.Secret, cfg.JWT.Issuer, -1*time.Hour)
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "invalid or expired token")
	})

	t.Run("Token signed with wrong secret returns 401", func(t *testing.T) {
		router := setupTestRouter()
		router.Use(AuthMiddleware(cfg))
		router.GET("/protected", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// Generate token with different secret
		wrongSecret := "wrong-secret-key"
		token, err := auth.GenerateToken("user123", "testuser", "admin", wrongSecret, cfg.JWT.Issuer, 24*time.Hour)
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "invalid or expired token")
	})

	t.Run("User context is properly set", func(t *testing.T) {
		router := setupTestRouter()
		router.Use(AuthMiddleware(cfg))
		
		var capturedUserID, capturedUsername, capturedRole string
		router.GET("/protected", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if exists {
				capturedUserID = userID.(string)
			}
			username, exists := c.Get("username")
			if exists {
				capturedUsername = username.(string)
			}
			role, exists := c.Get("role")
			if exists {
				capturedRole = role.(string)
			}
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		token, err := auth.GenerateToken("user456", "anotheruser", "user", cfg.JWT.Secret, cfg.JWT.Issuer, cfg.JWT.Expiration)
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "user456", capturedUserID)
		assert.Equal(t, "anotheruser", capturedUsername)
		assert.Equal(t, "user", capturedRole)
	})
}

func TestRequireRole(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:     "test-secret-key-for-testing",
			Expiration: 24 * time.Hour,
			Issuer:     "test-issuer",
		},
	}

	t.Run("Admin can access admin-only endpoint", func(t *testing.T) {
		router := setupTestRouter()
		router.Use(AuthMiddleware(cfg))
		router.Use(RequireRole("admin"))
		router.GET("/admin", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "admin access granted"})
		})

		token, err := auth.GenerateToken("user123", "adminuser", "admin", cfg.JWT.Secret, cfg.JWT.Issuer, cfg.JWT.Expiration)
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "admin access granted")
	})

	t.Run("Non-admin cannot access admin-only endpoint", func(t *testing.T) {
		router := setupTestRouter()
		router.Use(AuthMiddleware(cfg))
		router.Use(RequireRole("admin"))
		router.GET("/admin", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "admin access granted"})
		})

		token, err := auth.GenerateToken("user123", "regularuser", "user", cfg.JWT.Secret, cfg.JWT.Issuer, cfg.JWT.Expiration)
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "insufficient permissions")
	})

	t.Run("Admin can access user-level endpoint", func(t *testing.T) {
		router := setupTestRouter()
		router.Use(AuthMiddleware(cfg))
		router.Use(RequireRole("user"))
		router.GET("/user", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "user access granted"})
		})

		token, err := auth.GenerateToken("user123", "adminuser", "admin", cfg.JWT.Secret, cfg.JWT.Issuer, cfg.JWT.Expiration)
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "/user", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "user access granted")
	})

	t.Run("User can access user-level endpoint", func(t *testing.T) {
		router := setupTestRouter()
		router.Use(AuthMiddleware(cfg))
		router.Use(RequireRole("user"))
		router.GET("/user", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "user access granted"})
		})

		token, err := auth.GenerateToken("user123", "regularuser", "user", cfg.JWT.Secret, cfg.JWT.Issuer, cfg.JWT.Expiration)
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "/user", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "user access granted")
	})

	t.Run("Missing role in context returns 403", func(t *testing.T) {
		router := setupTestRouter()
		// Don't use AuthMiddleware, so role is not set in context
		router.Use(RequireRole("admin"))
		router.GET("/admin", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "admin access granted"})
		})

		req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "no role in context")
	})

	t.Run("Custom role cannot access different role endpoint", func(t *testing.T) {
		router := setupTestRouter()
		router.Use(AuthMiddleware(cfg))
		router.Use(RequireRole("manager"))
		router.GET("/manager", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "manager access granted"})
		})

		token, err := auth.GenerateToken("user123", "regularuser", "user", cfg.JWT.Secret, cfg.JWT.Issuer, cfg.JWT.Expiration)
		require.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "/manager", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "insufficient permissions")
	})
}

