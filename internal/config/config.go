// Package config provides configuration management for the OCM application.
// It handles loading configuration from YAML files, applying environment variable
// overrides, and validating configuration values for server, database, JWT, crypto,
// logging, and security settings.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all application configuration
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	JWT      JWTConfig      `yaml:"jwt"`
	Crypto   CryptoConfig   `yaml:"crypto"`
	Logging  LoggingConfig  `yaml:"logging"`
	Security SecurityConfig `yaml:"security"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Port         int           `yaml:"port"`
	Host         string        `yaml:"host"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	TLSEnabled   bool          `yaml:"tls_enabled"`
	TLSCert      string        `yaml:"tls_cert"`
	TLSKey       string        `yaml:"tls_key"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Type     string         `yaml:"type"`
	SQLite   SQLiteConfig   `yaml:"sqlite"`
	Postgres PostgresConfig `yaml:"postgres"`
}

// SQLiteConfig holds SQLite-specific configuration
type SQLiteConfig struct {
	Path string `yaml:"path"`
}

// PostgresConfig holds PostgreSQL-specific configuration
type PostgresConfig struct {
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	Database     string `yaml:"database"`
	User         string `yaml:"user"`
	Password     string `yaml:"password"`
	SSLMode      string `yaml:"ssl_mode"`
	MaxOpenConns int    `yaml:"max_open_conns"`
	MaxIdleConns int    `yaml:"max_idle_conns"`
}

// JWTConfig holds JWT authentication configuration
type JWTConfig struct {
	Secret     string        `yaml:"secret"`
	Expiration time.Duration `yaml:"expiration"`
	Issuer     string        `yaml:"issuer"`
}

// CryptoConfig holds cryptographic defaults
type CryptoConfig struct {
	DefaultCAValidity   time.Duration `yaml:"default_ca_validity"`
	DefaultCertValidity time.Duration `yaml:"default_cert_validity"`
	DefaultAlgorithm    string        `yaml:"default_algorithm"`
	DefaultRSABits      int           `yaml:"default_rsa_bits"`
	DefaultECCurve      string        `yaml:"default_ec_curve"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	CORSEnabled       bool     `yaml:"cors_enabled"`
	CORSOrigins       []string `yaml:"cors_origins"`
	RateLimitEnabled  bool     `yaml:"rate_limit_enabled"`
	RateLimitRequests int      `yaml:"rate_limit_requests"`
	RateLimitWindow   string   `yaml:"rate_limit_window"`
}

// Load reads and parses the configuration file
func Load(path string, flags interface{}) (*Config, error) {
	// Initialize with defaults
	cfg := &Config{}

	// Try to load config file (it's optional if using defaults/flags)
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			// File exists but can't be read (permissions, etc)
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file doesn't exist, use defaults
		cfg = defaultConfig()
	} else {
		// Parse config file
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	// Apply environment variable overrides
	cfg.applyEnvOverrides()

	// Apply command line flag overrides
	if flags != nil {
		cfg.applyFlagOverrides(flags)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// defaultConfig returns a Config with sensible defaults
func defaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Port:         8000,
			Host:         "0.0.0.0",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			TLSEnabled:   false,
		},
		Database: DatabaseConfig{
			Type: "sqlite",
			SQLite: SQLiteConfig{
				Path: "./data/ocm.db",
			},
			Postgres: PostgresConfig{
				Port:         5432,
				SSLMode:      "disable",
				MaxOpenConns: 25,
				MaxIdleConns: 5,
			},
		},
		JWT: JWTConfig{
			Expiration: 24 * time.Hour,
			Issuer:     "ocm",
		},
		Crypto: CryptoConfig{
			DefaultCAValidity:   87600 * time.Hour, // 10 years
			DefaultCertValidity: 8760 * time.Hour,  // 1 year
			DefaultAlgorithm:    "rsa",
			DefaultRSABits:      2048,
			DefaultECCurve:      "P256",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
		Security: SecurityConfig{
			CORSEnabled:       true,
			CORSOrigins:       []string{"http://localhost:3000", "http://localhost:8000"},
			RateLimitEnabled:  true,
			RateLimitRequests: 100,
			RateLimitWindow:   "1m",
		},
	}
}

// applyEnvOverrides applies environment variable overrides to the configuration
func (c *Config) applyEnvOverrides() {
	// Server overrides
	if port := os.Getenv("OCM_SERVER_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			c.Server.Port = p
		}
	}
	if host := os.Getenv("OCM_SERVER_HOST"); host != "" {
		c.Server.Host = host
	}

	// Database overrides
	if dbType := os.Getenv("OCM_DB_TYPE"); dbType != "" {
		c.Database.Type = dbType
	}
	if dbPath := os.Getenv("OCM_DB_SQLITE_PATH"); dbPath != "" {
		c.Database.SQLite.Path = dbPath
	}
	if pgHost := os.Getenv("OCM_DB_POSTGRES_HOST"); pgHost != "" {
		c.Database.Postgres.Host = pgHost
	}
	if pgPort := os.Getenv("OCM_DB_POSTGRES_PORT"); pgPort != "" {
		if p, err := strconv.Atoi(pgPort); err == nil {
			c.Database.Postgres.Port = p
		}
	}
	if pgDB := os.Getenv("OCM_DB_POSTGRES_DATABASE"); pgDB != "" {
		c.Database.Postgres.Database = pgDB
	}
	if pgUser := os.Getenv("OCM_DB_POSTGRES_USER"); pgUser != "" {
		c.Database.Postgres.User = pgUser
	}
	if pgPass := os.Getenv("OCM_DB_POSTGRES_PASSWORD"); pgPass != "" {
		c.Database.Postgres.Password = pgPass
	}

	// JWT overrides
	if jwtSecret := os.Getenv("OCM_JWT_SECRET"); jwtSecret != "" {
		c.JWT.Secret = jwtSecret
	}

	// Logging overrides
	if logLevel := os.Getenv("OCM_LOG_LEVEL"); logLevel != "" {
		c.Logging.Level = logLevel
	}
}

// FlagOverrides defines the interface for command line flag overrides
type FlagOverrides interface {
	GetServerPort() (int, bool)
	GetServerHost() (string, bool)
	GetServerReadTimeout() (string, bool)
	GetServerWriteTimeout() (string, bool)
	GetServerTLSEnabled() (bool, bool)
	GetServerTLSCert() (string, bool)
	GetServerTLSKey() (string, bool)
	GetDBType() (string, bool)
	GetDBSQLitePath() (string, bool)
	GetDBPostgresHost() (string, bool)
	GetDBPostgresPort() (int, bool)
	GetDBPostgresDatabase() (string, bool)
	GetDBPostgresUser() (string, bool)
	GetDBPostgresPassword() (string, bool)
	GetDBPostgresSSLMode() (string, bool)
	GetDBPostgresMaxOpenConns() (int, bool)
	GetDBPostgresMaxIdleConns() (int, bool)
	GetJWTSecret() (string, bool)
	GetJWTExpiration() (string, bool)
	GetJWTIssuer() (string, bool)
	GetCryptoDefaultCAValidity() (string, bool)
	GetCryptoDefaultCertValidity() (string, bool)
	GetCryptoDefaultAlgorithm() (string, bool)
	GetCryptoDefaultRSABits() (int, bool)
	GetCryptoDefaultECCurve() (string, bool)
	GetLogLevel() (string, bool)
	GetLogFormat() (string, bool)
	GetLogOutput() (string, bool)
	GetSecurityCORSEnabled() (bool, bool)
	GetSecurityCORSOrigins() ([]string, bool)
	GetSecurityRateLimitEnabled() (bool, bool)
	GetSecurityRateLimitRequests() (int, bool)
	GetSecurityRateLimitWindow() (string, bool)
}

// applyFlagOverrides applies command line flag overrides to the configuration
func (c *Config) applyFlagOverrides(flags interface{}) {
	fo, ok := flags.(FlagOverrides)
	if !ok {
		return
	}

	// Server overrides
	if port, set := fo.GetServerPort(); set && port > 0 {
		c.Server.Port = port
	}
	if host, set := fo.GetServerHost(); set && host != "" {
		c.Server.Host = host
	}
	if timeout, set := fo.GetServerReadTimeout(); set && timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
			c.Server.ReadTimeout = d
		}
	}
	if timeout, set := fo.GetServerWriteTimeout(); set && timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
			c.Server.WriteTimeout = d
		}
	}
	if enabled, set := fo.GetServerTLSEnabled(); set {
		c.Server.TLSEnabled = enabled
	}
	if cert, set := fo.GetServerTLSCert(); set && cert != "" {
		c.Server.TLSCert = cert
	}
	if key, set := fo.GetServerTLSKey(); set && key != "" {
		c.Server.TLSKey = key
	}

	// Database overrides
	if dbType, set := fo.GetDBType(); set && dbType != "" {
		c.Database.Type = dbType
	}
	if path, set := fo.GetDBSQLitePath(); set && path != "" {
		c.Database.SQLite.Path = path
	}
	if host, set := fo.GetDBPostgresHost(); set && host != "" {
		c.Database.Postgres.Host = host
	}
	if port, set := fo.GetDBPostgresPort(); set && port > 0 {
		c.Database.Postgres.Port = port
	}
	if database, set := fo.GetDBPostgresDatabase(); set && database != "" {
		c.Database.Postgres.Database = database
	}
	if user, set := fo.GetDBPostgresUser(); set && user != "" {
		c.Database.Postgres.User = user
	}
	if password, set := fo.GetDBPostgresPassword(); set && password != "" {
		c.Database.Postgres.Password = password
	}
	if sslMode, set := fo.GetDBPostgresSSLMode(); set && sslMode != "" {
		c.Database.Postgres.SSLMode = sslMode
	}
	if maxOpen, set := fo.GetDBPostgresMaxOpenConns(); set && maxOpen > 0 {
		c.Database.Postgres.MaxOpenConns = maxOpen
	}
	if maxIdle, set := fo.GetDBPostgresMaxIdleConns(); set && maxIdle > 0 {
		c.Database.Postgres.MaxIdleConns = maxIdle
	}

	// JWT overrides
	if secret, set := fo.GetJWTSecret(); set && secret != "" {
		c.JWT.Secret = secret
	}
	if expiration, set := fo.GetJWTExpiration(); set && expiration != "" {
		if d, err := time.ParseDuration(expiration); err == nil {
			c.JWT.Expiration = d
		}
	}
	if issuer, set := fo.GetJWTIssuer(); set && issuer != "" {
		c.JWT.Issuer = issuer
	}

	// Crypto overrides
	if validity, set := fo.GetCryptoDefaultCAValidity(); set && validity != "" {
		if d, err := time.ParseDuration(validity); err == nil {
			c.Crypto.DefaultCAValidity = d
		}
	}
	if validity, set := fo.GetCryptoDefaultCertValidity(); set && validity != "" {
		if d, err := time.ParseDuration(validity); err == nil {
			c.Crypto.DefaultCertValidity = d
		}
	}
	if algo, set := fo.GetCryptoDefaultAlgorithm(); set && algo != "" {
		c.Crypto.DefaultAlgorithm = algo
	}
	if bits, set := fo.GetCryptoDefaultRSABits(); set && bits > 0 {
		c.Crypto.DefaultRSABits = bits
	}
	if curve, set := fo.GetCryptoDefaultECCurve(); set && curve != "" {
		c.Crypto.DefaultECCurve = curve
	}

	// Logging overrides
	if level, set := fo.GetLogLevel(); set && level != "" {
		c.Logging.Level = level
	}
	if format, set := fo.GetLogFormat(); set && format != "" {
		c.Logging.Format = format
	}
	if output, set := fo.GetLogOutput(); set && output != "" {
		c.Logging.Output = output
	}

	// Security overrides
	if enabled, set := fo.GetSecurityCORSEnabled(); set {
		c.Security.CORSEnabled = enabled
	}
	if origins, set := fo.GetSecurityCORSOrigins(); set && len(origins) > 0 {
		c.Security.CORSOrigins = origins
	}
	if enabled, set := fo.GetSecurityRateLimitEnabled(); set {
		c.Security.RateLimitEnabled = enabled
	}
	if requests, set := fo.GetSecurityRateLimitRequests(); set && requests > 0 {
		c.Security.RateLimitRequests = requests
	}
	if window, set := fo.GetSecurityRateLimitWindow(); set && window != "" {
		c.Security.RateLimitWindow = window
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Validate server config
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}
	if c.Server.TLSEnabled {
		if c.Server.TLSCert == "" || c.Server.TLSKey == "" {
			return fmt.Errorf("TLS enabled but cert or key not specified")
		}
	}

	// Validate database config
	if c.Database.Type != "sqlite" && c.Database.Type != "postgres" {
		return fmt.Errorf("invalid database type: %s (must be 'sqlite' or 'postgres')", c.Database.Type)
	}
	if c.Database.Type == "sqlite" && c.Database.SQLite.Path == "" {
		return fmt.Errorf("SQLite path not specified")
	}
	if c.Database.Type == "postgres" {
		if c.Database.Postgres.Host == "" || c.Database.Postgres.Database == "" {
			return fmt.Errorf("PostgreSQL host and database must be specified")
		}
	}

	// Validate crypto config
	if c.Crypto.DefaultAlgorithm != "rsa" && c.Crypto.DefaultAlgorithm != "ecdsa" {
		return fmt.Errorf("invalid default algorithm: %s", c.Crypto.DefaultAlgorithm)
	}
	if c.Crypto.DefaultRSABits < 2048 {
		return fmt.Errorf("RSA key size must be at least 2048 bits")
	}
	if c.Crypto.DefaultECCurve != "P256" && c.Crypto.DefaultECCurve != "P384" {
		return fmt.Errorf("invalid EC curve: %s (must be P256 or P384)", c.Crypto.DefaultECCurve)
	}

	// Validate logging config
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[c.Logging.Level] {
		return fmt.Errorf("invalid log level: %s", c.Logging.Level)
	}

	return nil
}

// GetDSN returns the database connection string based on the configured type
func (c *Config) GetDSN() string {
	switch c.Database.Type {
	case "sqlite":
		return c.Database.SQLite.Path
	case "postgres":
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			c.Database.Postgres.Host,
			c.Database.Postgres.Port,
			c.Database.Postgres.User,
			c.Database.Postgres.Password,
			c.Database.Postgres.Database,
			c.Database.Postgres.SSLMode,
		)
	default:
		return ""
	}
}
