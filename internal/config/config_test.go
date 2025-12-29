package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	t.Run("Load config from file", func(t *testing.T) {
		// Create temp config file
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")

		configContent := `
server:
  port: 9000
  host: 127.0.0.1
database:
  type: sqlite
  sqlite:
    path: /tmp/test.db
jwt:
  secret: test-secret
  expiration: 48h
  issuer: test-ocm
crypto:
  default_algorithm: rsa
  default_rsa_bits: 2048
  default_ec_curve: P256
logging:
  level: debug
  format: console
  output: stdout
`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		cfg, err := Load(configPath, nil)
		require.NoError(t, err)
		assert.NotNil(t, cfg)
		assert.Equal(t, 9000, cfg.Server.Port)
		assert.Equal(t, "127.0.0.1", cfg.Server.Host)
		assert.Equal(t, "sqlite", cfg.Database.Type)
		assert.Equal(t, "test-secret", cfg.JWT.Secret)
		assert.Equal(t, "debug", cfg.Logging.Level)
	})

	t.Run("Load with non-existent file uses defaults", func(t *testing.T) {
		cfg, err := Load("/non/existent/path.yaml", nil)
		require.NoError(t, err)
		assert.NotNil(t, cfg)
		// Should have default values
		assert.Equal(t, 8000, cfg.Server.Port)
		assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	})

	t.Run("Load with invalid YAML fails", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")

		configContent := `invalid: yaml: content:`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		_, err = Load(configPath, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse config file")
	})

	t.Run("Load with invalid config values fails validation", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")

		configContent := `
server:
  port: 70000
database:
  type: sqlite
  sqlite:
    path: /tmp/test.db
`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		_, err = Load(configPath, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid configuration")
	})
}

func TestDefaultConfig(t *testing.T) {
	t.Run("Default config has sensible values", func(t *testing.T) {
		cfg := defaultConfig()
		assert.Equal(t, 8000, cfg.Server.Port)
		assert.Equal(t, "0.0.0.0", cfg.Server.Host)
		assert.Equal(t, 30*time.Second, cfg.Server.ReadTimeout)
		assert.Equal(t, 30*time.Second, cfg.Server.WriteTimeout)
		assert.False(t, cfg.Server.TLSEnabled)

		assert.Equal(t, "sqlite", cfg.Database.Type)
		assert.Equal(t, "./data/ocm.db", cfg.Database.SQLite.Path)

		assert.Equal(t, 24*time.Hour, cfg.JWT.Expiration)
		assert.Equal(t, "ocm", cfg.JWT.Issuer)

		assert.Equal(t, "rsa", cfg.Crypto.DefaultAlgorithm)
		assert.Equal(t, 2048, cfg.Crypto.DefaultRSABits)
		assert.Equal(t, "P256", cfg.Crypto.DefaultECCurve)

		assert.Equal(t, "info", cfg.Logging.Level)
		assert.Equal(t, "json", cfg.Logging.Format)

		assert.True(t, cfg.Security.CORSEnabled)
		assert.True(t, cfg.Security.RateLimitEnabled)
	})
}

func TestApplyEnvOverrides(t *testing.T) {
	t.Run("Override server port", func(t *testing.T) {
		os.Setenv("OCM_SERVER_PORT", "9090")
		defer os.Unsetenv("OCM_SERVER_PORT")

		cfg := defaultConfig()
		cfg.applyEnvOverrides()
		assert.Equal(t, 9090, cfg.Server.Port)
	})

	t.Run("Override server host", func(t *testing.T) {
		os.Setenv("OCM_SERVER_HOST", "localhost")
		defer os.Unsetenv("OCM_SERVER_HOST")

		cfg := defaultConfig()
		cfg.applyEnvOverrides()
		assert.Equal(t, "localhost", cfg.Server.Host)
	})

	t.Run("Override database type", func(t *testing.T) {
		os.Setenv("OCM_DB_TYPE", "postgres")
		defer os.Unsetenv("OCM_DB_TYPE")

		cfg := defaultConfig()
		cfg.applyEnvOverrides()
		assert.Equal(t, "postgres", cfg.Database.Type)
	})

	t.Run("Override SQLite path", func(t *testing.T) {
		os.Setenv("OCM_DB_SQLITE_PATH", "/custom/path/db.sqlite")
		defer os.Unsetenv("OCM_DB_SQLITE_PATH")

		cfg := defaultConfig()
		cfg.applyEnvOverrides()
		assert.Equal(t, "/custom/path/db.sqlite", cfg.Database.SQLite.Path)
	})

	t.Run("Override PostgreSQL settings", func(t *testing.T) {
		os.Setenv("OCM_DB_POSTGRES_HOST", "postgres.example.com")
		os.Setenv("OCM_DB_POSTGRES_PORT", "5433")
		os.Setenv("OCM_DB_POSTGRES_DATABASE", "ocm_db")
		os.Setenv("OCM_DB_POSTGRES_USER", "ocm_user")
		os.Setenv("OCM_DB_POSTGRES_PASSWORD", "secret_pass")
		defer func() {
			os.Unsetenv("OCM_DB_POSTGRES_HOST")
			os.Unsetenv("OCM_DB_POSTGRES_PORT")
			os.Unsetenv("OCM_DB_POSTGRES_DATABASE")
			os.Unsetenv("OCM_DB_POSTGRES_USER")
			os.Unsetenv("OCM_DB_POSTGRES_PASSWORD")
		}()

		cfg := defaultConfig()
		cfg.applyEnvOverrides()
		assert.Equal(t, "postgres.example.com", cfg.Database.Postgres.Host)
		assert.Equal(t, 5433, cfg.Database.Postgres.Port)
		assert.Equal(t, "ocm_db", cfg.Database.Postgres.Database)
		assert.Equal(t, "ocm_user", cfg.Database.Postgres.User)
		assert.Equal(t, "secret_pass", cfg.Database.Postgres.Password)
	})

	t.Run("Override JWT secret", func(t *testing.T) {
		os.Setenv("OCM_JWT_SECRET", "env-secret")
		defer os.Unsetenv("OCM_JWT_SECRET")

		cfg := defaultConfig()
		cfg.applyEnvOverrides()
		assert.Equal(t, "env-secret", cfg.JWT.Secret)
	})

	t.Run("Override log level", func(t *testing.T) {
		os.Setenv("OCM_LOG_LEVEL", "debug")
		defer os.Unsetenv("OCM_LOG_LEVEL")

		cfg := defaultConfig()
		cfg.applyEnvOverrides()
		assert.Equal(t, "debug", cfg.Logging.Level)
	})

	t.Run("Invalid port number is ignored", func(t *testing.T) {
		os.Setenv("OCM_SERVER_PORT", "invalid")
		defer os.Unsetenv("OCM_SERVER_PORT")

		cfg := defaultConfig()
		originalPort := cfg.Server.Port
		cfg.applyEnvOverrides()
		assert.Equal(t, originalPort, cfg.Server.Port)
	})
}

func TestValidate(t *testing.T) {
	t.Run("Valid default config", func(t *testing.T) {
		cfg := defaultConfig()
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("Invalid server port - too low", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.Server.Port = 0
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid server port")
	})

	t.Run("Invalid server port - too high", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.Server.Port = 70000
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid server port")
	})

	t.Run("Valid server port range", func(t *testing.T) {
		cfg := defaultConfig()
		validPorts := []int{1, 80, 443, 8000, 65535}
		for _, port := range validPorts {
			cfg.Server.Port = port
			err := cfg.Validate()
			assert.NoError(t, err)
		}
	})

	t.Run("TLS enabled without cert", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.Server.TLSEnabled = true
		cfg.Server.TLSCert = ""
		cfg.Server.TLSKey = "/path/to/key"
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "TLS enabled")
	})

	t.Run("TLS enabled without key", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.Server.TLSEnabled = true
		cfg.Server.TLSCert = "/path/to/cert"
		cfg.Server.TLSKey = ""
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "TLS enabled")
	})

	t.Run("TLS enabled with both cert and key", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.Server.TLSEnabled = true
		cfg.Server.TLSCert = "/path/to/cert"
		cfg.Server.TLSKey = "/path/to/key"
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("Invalid database type", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.Database.Type = "mysql"
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid database type")
	})

	t.Run("SQLite without path", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.Database.Type = "sqlite"
		cfg.Database.SQLite.Path = ""
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SQLite path")
	})

	t.Run("PostgreSQL without host", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.Database.Type = "postgres"
		cfg.Database.Postgres.Host = ""
		cfg.Database.Postgres.Database = "ocm"
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "PostgreSQL host and database")
	})

	t.Run("PostgreSQL without database", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.Database.Type = "postgres"
		cfg.Database.Postgres.Host = "localhost"
		cfg.Database.Postgres.Database = ""
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "PostgreSQL host and database")
	})

	t.Run("Invalid crypto algorithm", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.Crypto.DefaultAlgorithm = "aes"
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid default algorithm")
	})

	t.Run("RSA bits too small", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.Crypto.DefaultRSABits = 1024
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least 2048 bits")
	})

	t.Run("Invalid EC curve", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.Crypto.DefaultECCurve = "P521"
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid EC curve")
	})

	t.Run("Valid EC curves", func(t *testing.T) {
		cfg := defaultConfig()
		validCurves := []string{"P256", "P384"}
		for _, curve := range validCurves {
			cfg.Crypto.DefaultECCurve = curve
			err := cfg.Validate()
			assert.NoError(t, err)
		}
	})

	t.Run("Invalid log level", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.Logging.Level = "trace"
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid log level")
	})

	t.Run("Valid log levels", func(t *testing.T) {
		cfg := defaultConfig()
		validLevels := []string{"debug", "info", "warn", "error"}
		for _, level := range validLevels {
			cfg.Logging.Level = level
			err := cfg.Validate()
			assert.NoError(t, err)
		}
	})
}

func TestGetDSN(t *testing.T) {
	t.Run("SQLite DSN", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.Database.Type = "sqlite"
		cfg.Database.SQLite.Path = "/path/to/db.sqlite"

		dsn := cfg.GetDSN()
		assert.Equal(t, "/path/to/db.sqlite", dsn)
	})

	t.Run("PostgreSQL DSN", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.Database.Type = "postgres"
		cfg.Database.Postgres.Host = "localhost"
		cfg.Database.Postgres.Port = 5432
		cfg.Database.Postgres.User = "testuser"
		cfg.Database.Postgres.Password = "testpass"
		cfg.Database.Postgres.Database = "testdb"
		cfg.Database.Postgres.SSLMode = "disable"

		dsn := cfg.GetDSN()
		expected := "host=localhost port=5432 user=testuser password=testpass dbname=testdb sslmode=disable"
		assert.Equal(t, expected, dsn)
	})

	t.Run("PostgreSQL DSN with SSL", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.Database.Type = "postgres"
		cfg.Database.Postgres.Host = "postgres.example.com"
		cfg.Database.Postgres.Port = 5433
		cfg.Database.Postgres.User = "admin"
		cfg.Database.Postgres.Password = "secret"
		cfg.Database.Postgres.Database = "production"
		cfg.Database.Postgres.SSLMode = "require"

		dsn := cfg.GetDSN()
		assert.Contains(t, dsn, "host=postgres.example.com")
		assert.Contains(t, dsn, "port=5433")
		assert.Contains(t, dsn, "user=admin")
		assert.Contains(t, dsn, "password=secret")
		assert.Contains(t, dsn, "dbname=production")
		assert.Contains(t, dsn, "sslmode=require")
	})

	t.Run("Unknown database type returns empty", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.Database.Type = "unknown"

		dsn := cfg.GetDSN()
		assert.Empty(t, dsn)
	})
}

func TestLoadWithEnvAndFlags_Integration(t *testing.T) {
	t.Run("Priority: flags > env > file > defaults", func(t *testing.T) {
		// Create config file
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")

		configContent := `
server:
  port: 7000
database:
  type: sqlite
  sqlite:
    path: /file/path.db
crypto:
  default_algorithm: rsa
  default_rsa_bits: 2048
  default_ec_curve: P256
logging:
  level: info
  format: json
  output: stdout
`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		// Set env var
		os.Setenv("OCM_SERVER_PORT", "8000")
		defer os.Unsetenv("OCM_SERVER_PORT")

		// Load without flags - should use env (8000) over file (7000)
		cfg, err := Load(configPath, nil)
		require.NoError(t, err)
		assert.Equal(t, 8000, cfg.Server.Port)
	})
}

