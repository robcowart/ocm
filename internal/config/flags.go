package config

import (
	"fmt"
	"os"

	flag "github.com/spf13/pflag"
)

// Flags holds all command line flag values
type Flags struct {
	// General
	configFile *string
	version    *bool

	// Server
	serverPort         *int
	serverHost         *string
	serverReadTimeout  *string
	serverWriteTimeout *string
	serverTLSEnabled   *bool
	serverTLSCert      *string
	serverTLSKey       *string

	// Database
	dbType                 *string
	dbSQLitePath           *string
	dbPostgresHost         *string
	dbPostgresPort         *int
	dbPostgresDatabase     *string
	dbPostgresUser         *string
	dbPostgresPassword     *string
	dbPostgresSSLMode      *string
	dbPostgresMaxOpenConns *int
	dbPostgresMaxIdleConns *int

	// JWT
	jwtSecret     *string
	jwtExpiration *string
	jwtIssuer     *string

	// Crypto
	cryptoDefaultCAValidity   *string
	cryptoDefaultCertValidity *string
	cryptoDefaultAlgorithm    *string
	cryptoDefaultRSABits      *int
	cryptoDefaultECCurve      *string

	// Logging
	logLevel  *string
	logFormat *string
	logOutput *string

	// Security
	securityCORSEnabled       *bool
	securityCORSOrigins       *[]string
	securityRateLimitEnabled  *bool
	securityRateLimitRequests *int
	securityRateLimitWindow   *string
}

// ParseFlags defines and parses all command line flags
func ParseFlags() (*Flags, string, bool) {
	f := &Flags{}

	// General flags
	f.configFile = flag.StringP("config", "c", "config.yaml", "Path to configuration file")
	f.version = flag.BoolP("version", "v", false, "Print version and exit")

	// Server flags
	f.serverPort = flag.Int("server.port", 0, "HTTP server port")
	f.serverHost = flag.String("server.host", "", "HTTP server bind address")
	f.serverReadTimeout = flag.String("server.read-timeout", "", "Server read timeout (e.g., 30s)")
	f.serverWriteTimeout = flag.String("server.write-timeout", "", "Server write timeout (e.g., 30s)")
	f.serverTLSEnabled = flag.Bool("server.tls-enabled", false, "Enable HTTPS")
	f.serverTLSCert = flag.String("server.tls-cert", "", "Path to TLS certificate")
	f.serverTLSKey = flag.String("server.tls-key", "", "Path to TLS key")

	// Database flags
	f.dbType = flag.String("db.type", "", "Database type (sqlite or postgres)")
	f.dbSQLitePath = flag.String("db.sqlite.path", "", "SQLite database file path")
	f.dbPostgresHost = flag.String("db.postgres.host", "", "PostgreSQL host")
	f.dbPostgresPort = flag.Int("db.postgres.port", 0, "PostgreSQL port")
	f.dbPostgresDatabase = flag.String("db.postgres.database", "", "PostgreSQL database name")
	f.dbPostgresUser = flag.String("db.postgres.user", "", "PostgreSQL user")
	f.dbPostgresPassword = flag.String("db.postgres.password", "", "PostgreSQL password")
	f.dbPostgresSSLMode = flag.String("db.postgres.ssl-mode", "", "PostgreSQL SSL mode")
	f.dbPostgresMaxOpenConns = flag.Int("db.postgres.max-open-conns", 0, "PostgreSQL max open connections")
	f.dbPostgresMaxIdleConns = flag.Int("db.postgres.max-idle-conns", 0, "PostgreSQL max idle connections")

	// JWT flags
	f.jwtSecret = flag.String("jwt.secret", "", "JWT secret key")
	f.jwtExpiration = flag.String("jwt.expiration", "", "JWT expiration duration (e.g., 24h)")
	f.jwtIssuer = flag.String("jwt.issuer", "", "JWT issuer")

	// Crypto flags
	f.cryptoDefaultCAValidity = flag.String("crypto.default-ca-validity", "", "Default CA validity period (e.g., 87600h)")
	f.cryptoDefaultCertValidity = flag.String("crypto.default-cert-validity", "", "Default certificate validity period (e.g., 8760h)")
	f.cryptoDefaultAlgorithm = flag.String("crypto.default-algorithm", "", "Default algorithm (rsa or ecdsa)")
	f.cryptoDefaultRSABits = flag.Int("crypto.default-rsa-bits", 0, "Default RSA key size in bits")
	f.cryptoDefaultECCurve = flag.String("crypto.default-ec-curve", "", "Default EC curve (P256 or P384)")

	// Logging flags
	f.logLevel = flag.StringP("log.level", "l", "", "Log level (debug, info, warn, error)")
	f.logFormat = flag.String("log.format", "", "Log format (json or console)")
	f.logOutput = flag.String("log.output", "", "Log output (stdout or file path)")

	// Security flags
	f.securityCORSEnabled = flag.Bool("security.cors-enabled", false, "Enable CORS")
	f.securityCORSOrigins = flag.StringSlice("security.cors-origins", nil, "CORS allowed origins (can be specified multiple times)")
	f.securityRateLimitEnabled = flag.Bool("security.rate-limit-enabled", false, "Enable rate limiting")
	f.securityRateLimitRequests = flag.Int("security.rate-limit-requests", 0, "Rate limit requests per window")
	f.securityRateLimitWindow = flag.String("security.rate-limit-window", "", "Rate limit window duration (e.g., 1m)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Open Certificate Manager (OCM) - A secure PKI certificate management system\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nConfiguration priority (highest to lowest):\n")
		fmt.Fprintf(os.Stderr, "  1. Command line flags\n")
		fmt.Fprintf(os.Stderr, "  2. Environment variables (OCM_*)\n")
		fmt.Fprintf(os.Stderr, "  3. Configuration file (default: config.yaml)\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  # Start with custom config file\n")
		fmt.Fprintf(os.Stderr, "  %s --config /etc/ocm/config.yaml\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Override port and database type\n")
		fmt.Fprintf(os.Stderr, "  %s --server.port 9000 --db.type postgres\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Use PostgreSQL with all settings\n")
		fmt.Fprintf(os.Stderr, "  %s --db.type postgres --db.postgres.host db.example.com --db.postgres.user ocm\n\n", os.Args[0])
	}

	flag.Parse()

	return f, *f.configFile, *f.version
}

// GetServerPort returns the server port flag value and whether it was set
func (f *Flags) GetServerPort() (int, bool) {
	return *f.serverPort, flag.Lookup("server.port").Changed
}

// GetServerHost returns the server host flag value and whether it was set
func (f *Flags) GetServerHost() (string, bool) {
	return *f.serverHost, flag.Lookup("server.host").Changed
}

// GetServerReadTimeout returns the server read timeout flag value and whether it was set
func (f *Flags) GetServerReadTimeout() (string, bool) {
	return *f.serverReadTimeout, flag.Lookup("server.read-timeout").Changed
}

// GetServerWriteTimeout returns the server write timeout flag value and whether it was set
func (f *Flags) GetServerWriteTimeout() (string, bool) {
	return *f.serverWriteTimeout, flag.Lookup("server.write-timeout").Changed
}

// GetServerTLSEnabled returns the server TLS enabled flag value and whether it was set
func (f *Flags) GetServerTLSEnabled() (bool, bool) {
	return *f.serverTLSEnabled, flag.Lookup("server.tls-enabled").Changed
}

// GetServerTLSCert returns the server TLS cert flag value and whether it was set
func (f *Flags) GetServerTLSCert() (string, bool) {
	return *f.serverTLSCert, flag.Lookup("server.tls-cert").Changed
}

// GetServerTLSKey returns the server TLS key flag value and whether it was set
func (f *Flags) GetServerTLSKey() (string, bool) {
	return *f.serverTLSKey, flag.Lookup("server.tls-key").Changed
}

// GetDBType returns the database type flag value and whether it was set
func (f *Flags) GetDBType() (string, bool) {
	return *f.dbType, flag.Lookup("db.type").Changed
}

// GetDBSQLitePath returns the SQLite path flag value and whether it was set
func (f *Flags) GetDBSQLitePath() (string, bool) {
	return *f.dbSQLitePath, flag.Lookup("db.sqlite.path").Changed
}

// GetDBPostgresHost returns the PostgreSQL host flag value and whether it was set
func (f *Flags) GetDBPostgresHost() (string, bool) {
	return *f.dbPostgresHost, flag.Lookup("db.postgres.host").Changed
}

// GetDBPostgresPort returns the PostgreSQL port flag value and whether it was set
func (f *Flags) GetDBPostgresPort() (int, bool) {
	return *f.dbPostgresPort, flag.Lookup("db.postgres.port").Changed
}

// GetDBPostgresDatabase returns the PostgreSQL database flag value and whether it was set
func (f *Flags) GetDBPostgresDatabase() (string, bool) {
	return *f.dbPostgresDatabase, flag.Lookup("db.postgres.database").Changed
}

// GetDBPostgresUser returns the PostgreSQL user flag value and whether it was set
func (f *Flags) GetDBPostgresUser() (string, bool) {
	return *f.dbPostgresUser, flag.Lookup("db.postgres.user").Changed
}

// GetDBPostgresPassword returns the PostgreSQL password flag value and whether it was set
func (f *Flags) GetDBPostgresPassword() (string, bool) {
	return *f.dbPostgresPassword, flag.Lookup("db.postgres.password").Changed
}

// GetDBPostgresSSLMode returns the PostgreSQL SSL mode flag value and whether it was set
func (f *Flags) GetDBPostgresSSLMode() (string, bool) {
	return *f.dbPostgresSSLMode, flag.Lookup("db.postgres.ssl-mode").Changed
}

// GetDBPostgresMaxOpenConns returns the PostgreSQL max open connections flag value and whether it was set
func (f *Flags) GetDBPostgresMaxOpenConns() (int, bool) {
	return *f.dbPostgresMaxOpenConns, flag.Lookup("db.postgres.max-open-conns").Changed
}

// GetDBPostgresMaxIdleConns returns the PostgreSQL max idle connections flag value and whether it was set
func (f *Flags) GetDBPostgresMaxIdleConns() (int, bool) {
	return *f.dbPostgresMaxIdleConns, flag.Lookup("db.postgres.max-idle-conns").Changed
}

// GetJWTSecret returns the JWT secret flag value and whether it was set
func (f *Flags) GetJWTSecret() (string, bool) {
	return *f.jwtSecret, flag.Lookup("jwt.secret").Changed
}

// GetJWTExpiration returns the JWT expiration flag value and whether it was set
func (f *Flags) GetJWTExpiration() (string, bool) {
	return *f.jwtExpiration, flag.Lookup("jwt.expiration").Changed
}

// GetJWTIssuer returns the JWT issuer flag value and whether it was set
func (f *Flags) GetJWTIssuer() (string, bool) {
	return *f.jwtIssuer, flag.Lookup("jwt.issuer").Changed
}

// GetCryptoDefaultCAValidity returns the default CA validity flag value and whether it was set
func (f *Flags) GetCryptoDefaultCAValidity() (string, bool) {
	return *f.cryptoDefaultCAValidity, flag.Lookup("crypto.default-ca-validity").Changed
}

// GetCryptoDefaultCertValidity returns the default certificate validity flag value and whether it was set
func (f *Flags) GetCryptoDefaultCertValidity() (string, bool) {
	return *f.cryptoDefaultCertValidity, flag.Lookup("crypto.default-cert-validity").Changed
}

// GetCryptoDefaultAlgorithm returns the default algorithm flag value and whether it was set
func (f *Flags) GetCryptoDefaultAlgorithm() (string, bool) {
	return *f.cryptoDefaultAlgorithm, flag.Lookup("crypto.default-algorithm").Changed
}

// GetCryptoDefaultRSABits returns the default RSA bits flag value and whether it was set
func (f *Flags) GetCryptoDefaultRSABits() (int, bool) {
	return *f.cryptoDefaultRSABits, flag.Lookup("crypto.default-rsa-bits").Changed
}

// GetCryptoDefaultECCurve returns the default EC curve flag value and whether it was set
func (f *Flags) GetCryptoDefaultECCurve() (string, bool) {
	return *f.cryptoDefaultECCurve, flag.Lookup("crypto.default-ec-curve").Changed
}

// GetLogLevel returns the log level flag value and whether it was set
func (f *Flags) GetLogLevel() (string, bool) {
	return *f.logLevel, flag.Lookup("log.level").Changed
}

// GetLogFormat returns the log format flag value and whether it was set
func (f *Flags) GetLogFormat() (string, bool) {
	return *f.logFormat, flag.Lookup("log.format").Changed
}

// GetLogOutput returns the log output flag value and whether it was set
func (f *Flags) GetLogOutput() (string, bool) {
	return *f.logOutput, flag.Lookup("log.output").Changed
}

// GetSecurityCORSEnabled returns the CORS enabled flag value and whether it was set
func (f *Flags) GetSecurityCORSEnabled() (bool, bool) {
	return *f.securityCORSEnabled, flag.Lookup("security.cors-enabled").Changed
}

// GetSecurityCORSOrigins returns the CORS origins flag value and whether it was set
func (f *Flags) GetSecurityCORSOrigins() ([]string, bool) {
	return *f.securityCORSOrigins, flag.Lookup("security.cors-origins").Changed
}

// GetSecurityRateLimitEnabled returns the rate limit enabled flag value and whether it was set
func (f *Flags) GetSecurityRateLimitEnabled() (bool, bool) {
	return *f.securityRateLimitEnabled, flag.Lookup("security.rate-limit-enabled").Changed
}

// GetSecurityRateLimitRequests returns the rate limit requests flag value and whether it was set
func (f *Flags) GetSecurityRateLimitRequests() (int, bool) {
	return *f.securityRateLimitRequests, flag.Lookup("security.rate-limit-requests").Changed
}

// GetSecurityRateLimitWindow returns the rate limit window flag value and whether it was set
func (f *Flags) GetSecurityRateLimitWindow() (string, bool) {
	return *f.securityRateLimitWindow, flag.Lookup("security.rate-limit-window").Changed
}

