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
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Apply environment variable overrides
	cfg.applyEnvOverrides()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
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
