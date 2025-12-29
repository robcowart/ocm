package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestLoggerMiddleware(t *testing.T) {
	t.Run("Logs successful request", func(t *testing.T) {
		// Create a test logger with observer
		core, recorded := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		router := setupTestRouter()
		router.Use(LoggerMiddleware(logger))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Check logs
		logs := recorded.All()
		assert.Len(t, logs, 1)
		assert.Equal(t, "HTTP request", logs[0].Message)
		
		// Check log fields
		fields := logs[0].ContextMap()
		assert.Equal(t, "GET", fields["method"])
		assert.Equal(t, "/test", fields["path"])
		assert.Equal(t, int64(200), fields["status"])
		assert.NotNil(t, fields["latency"])
		assert.NotNil(t, fields["ip"])
	})

	t.Run("Logs request with query parameters", func(t *testing.T) {
		core, recorded := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		router := setupTestRouter()
		router.Use(LoggerMiddleware(logger))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req, _ := http.NewRequest(http.MethodGet, "/test?foo=bar&baz=qux", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		logs := recorded.All()
		assert.Len(t, logs, 1)
		fields := logs[0].ContextMap()
		assert.Equal(t, "foo=bar&baz=qux", fields["query"])
	})

	t.Run("Logs failed request with error status", func(t *testing.T) {
		core, recorded := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		router := setupTestRouter()
		router.Use(LoggerMiddleware(logger))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
		})

		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		logs := recorded.All()
		assert.Len(t, logs, 1)
		fields := logs[0].ContextMap()
		assert.Equal(t, int64(500), fields["status"])
	})

	t.Run("Logs different HTTP methods", func(t *testing.T) {
		methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}

		for _, method := range methods {
			t.Run(method, func(t *testing.T) {
				core, recorded := observer.New(zapcore.InfoLevel)
				logger := zap.New(core)

				router := setupTestRouter()
				router.Use(LoggerMiddleware(logger))
				router.Handle(method, "/test", func(c *gin.Context) {
					c.JSON(http.StatusOK, gin.H{"method": method})
				})

				req, _ := http.NewRequest(method, "/test", nil)
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				assert.Equal(t, http.StatusOK, w.Code)

				logs := recorded.All()
				assert.Len(t, logs, 1)
				fields := logs[0].ContextMap()
				assert.Equal(t, method, fields["method"])
			})
		}
	})

	t.Run("Logs client IP address", func(t *testing.T) {
		core, recorded := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		router := setupTestRouter()
		router.Use(LoggerMiddleware(logger))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		logs := recorded.All()
		assert.Len(t, logs, 1)
		fields := logs[0].ContextMap()
		assert.NotEmpty(t, fields["ip"])
	})

	t.Run("Logs user agent", func(t *testing.T) {
		core, recorded := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		router := setupTestRouter()
		router.Use(LoggerMiddleware(logger))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Test Browser)")
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		logs := recorded.All()
		assert.Len(t, logs, 1)
		fields := logs[0].ContextMap()
		assert.Equal(t, "Mozilla/5.0 (Test Browser)", fields["user_agent"])
	})

	t.Run("Logs request latency", func(t *testing.T) {
		core, recorded := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		router := setupTestRouter()
		router.Use(LoggerMiddleware(logger))
		router.GET("/test", func(c *gin.Context) {
			// Simulate some processing time
			time.Sleep(10 * time.Millisecond)
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		logs := recorded.All()
		assert.Len(t, logs, 1)
		fields := logs[0].ContextMap()
		
		// Verify latency is recorded and is at least 10ms
		latency, ok := fields["latency"].(time.Duration)
		assert.True(t, ok)
		assert.GreaterOrEqual(t, latency, 10*time.Millisecond)
	})

	t.Run("Logs POST request", func(t *testing.T) {
		core, recorded := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		router := setupTestRouter()
		router.Use(LoggerMiddleware(logger))
		router.POST("/test", func(c *gin.Context) {
			c.JSON(http.StatusCreated, gin.H{"message": "created"})
		})

		body := bytes.NewBufferString(`{"key":"value"}`)
		req, _ := http.NewRequest(http.MethodPost, "/test", body)
		req.Header.Set("Content-Type", "application/json")
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		logs := recorded.All()
		assert.Len(t, logs, 1)
		fields := logs[0].ContextMap()
		assert.Equal(t, "POST", fields["method"])
		assert.Equal(t, int64(201), fields["status"])
	})

	t.Run("Logs 404 not found", func(t *testing.T) {
		core, recorded := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		router := setupTestRouter()
		router.Use(LoggerMiddleware(logger))
		router.GET("/exists", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req, _ := http.NewRequest(http.MethodGet, "/notfound", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		logs := recorded.All()
		assert.Len(t, logs, 1)
		fields := logs[0].ContextMap()
		assert.Equal(t, "/notfound", fields["path"])
		assert.Equal(t, int64(404), fields["status"])
	})

	t.Run("Logs empty query string", func(t *testing.T) {
		core, recorded := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		router := setupTestRouter()
		router.Use(LoggerMiddleware(logger))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		logs := recorded.All()
		assert.Len(t, logs, 1)
		fields := logs[0].ContextMap()
		assert.Equal(t, "", fields["query"])
	})

	t.Run("Logs multiple requests", func(t *testing.T) {
		core, recorded := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		router := setupTestRouter()
		router.Use(LoggerMiddleware(logger))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// Make 3 requests
		for i := 0; i < 3; i++ {
			req, _ := http.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
		}

		logs := recorded.All()
		assert.Len(t, logs, 3)
		
		// Verify all logs are for the same endpoint
		for _, log := range logs {
			fields := log.ContextMap()
			assert.Equal(t, "/test", fields["path"])
			assert.Equal(t, int64(200), fields["status"])
		}
	})
}

