// Package database provides database connection management, migrations, and data access methods for the OCM application.
package database

import (
	"database/sql"
	"embed"
	"fmt"
	"strings"

	"github.com/robcowart/ocm/internal/config"
	"github.com/robcowart/ocm/internal/database/models"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Database represents the database connection and operations
type Database struct {
	db     *sql.DB
	dbType string
}

// New creates a new database connection
func New(cfg *config.Config) (*Database, error) {
	var db *sql.DB
	var err error

	switch cfg.Database.Type {
	case "sqlite":
		db, err = sql.Open("sqlite3", cfg.Database.SQLite.Path+"?_foreign_keys=on")
		if err != nil {
			return nil, fmt.Errorf("failed to open SQLite database: %w", err)
		}
		// SQLite specific settings
		db.SetMaxOpenConns(1) // SQLite only allows one writer at a time
	case "postgres":
		db, err = sql.Open("postgres", cfg.GetDSN())
		if err != nil {
			return nil, fmt.Errorf("failed to open PostgreSQL database: %w", err)
		}
		db.SetMaxOpenConns(cfg.Database.Postgres.MaxOpenConns)
		db.SetMaxIdleConns(cfg.Database.Postgres.MaxIdleConns)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", cfg.Database.Type)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Database{
		db:     db,
		dbType: cfg.Database.Type,
	}, nil
}

// Close closes the database connection
func (d *Database) Close() error {
	return d.db.Close()
}

// Migrate runs database migrations
func (d *Database) Migrate() error {
	// List of migration files to run in order
	var migrationFiles []string
	if d.dbType == "postgres" {
		migrationFiles = []string{
			"migrations/000001_init_schema.postgres.up.sql",
			"migrations/000002_add_certificate_metadata.postgres.up.sql",
		}
	} else {
		migrationFiles = []string{
			"migrations/000001_init_schema.up.sql",
			"migrations/000002_add_certificate_metadata.up.sql",
		}
	}

	// Run each migration file
	for _, migrationFile := range migrationFiles {
		content, err := migrationsFS.ReadFile(migrationFile)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", migrationFile, err)
		}

		// Remove comments and split into statements
		var statements []string
		lines := strings.Split(string(content), "\n")
		var currentStmt strings.Builder
		
		for _, line := range lines {
			line = strings.TrimSpace(line)
			// Skip comment lines
			if strings.HasPrefix(line, "--") || line == "" {
				continue
			}
			
			currentStmt.WriteString(line)
			currentStmt.WriteString("\n")
			
			// If line ends with semicolon, we have a complete statement
			if strings.HasSuffix(line, ";") {
				stmt := strings.TrimSpace(currentStmt.String())
				if stmt != "" {
					statements = append(statements, stmt)
				}
				currentStmt.Reset()
			}
		}
		
		// Execute statements in order
		for _, stmt := range statements {
			if _, err := d.db.Exec(stmt); err != nil {
				// Ignore "duplicate column" errors for idempotent migrations
				if !strings.Contains(err.Error(), "duplicate column") && !strings.Contains(err.Error(), "already exists") {
					return fmt.Errorf("migration %s failed: %w\nStatement: %s", migrationFile, err, stmt)
				}
			}
		}
	}

	return nil
}

// DB returns the underlying database connection for direct queries
func (d *Database) DB() *sql.DB {
	return d.db
}

// User operations

// CreateUser creates a new user
func (d *Database) CreateUser(user *models.User) error {
	query := `INSERT INTO users (id, username, password_hash, role, created_at) 
	          VALUES (?, ?, ?, ?, ?)`
	
	if d.dbType == "postgres" {
		query = `INSERT INTO users (id, username, password_hash, role, created_at) 
		         VALUES ($1, $2, $3, $4, $5)`
	}

	_, err := d.db.Exec(query, user.ID, user.Username, user.PasswordHash, user.Role, user.CreatedAt)
	return err
}

// GetUserByUsername retrieves a user by username
func (d *Database) GetUserByUsername(username string) (*models.User, error) {
	query := `SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?`
	if d.dbType == "postgres" {
		query = `SELECT id, username, password_hash, role, created_at FROM users WHERE username = $1`
	}

	var user models.User
	err := d.db.QueryRow(query, username).Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// Authority operations

// CreateAuthority creates a new Certificate Authority
func (d *Database) CreateAuthority(auth *models.Authority) error {
	query := `INSERT INTO authorities 
	          (id, friendly_name, common_name, serial_number, not_before, not_after, 
	           certificate_pem, private_key_enc, issuer_id, is_root, created_at) 
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	
	if d.dbType == "postgres" {
		query = `INSERT INTO authorities 
		         (id, friendly_name, common_name, serial_number, not_before, not_after, 
		          certificate_pem, private_key_enc, issuer_id, is_root, created_at) 
		         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	}

	_, err := d.db.Exec(query,
		auth.ID, auth.FriendlyName, auth.CommonName, auth.SerialNumber,
		auth.NotBefore, auth.NotAfter, auth.CertificatePEM, auth.PrivateKeyEnc,
		auth.IssuerID, auth.IsRoot, auth.CreatedAt,
	)
	return err
}

// GetAuthority retrieves an authority by ID
func (d *Database) GetAuthority(id string) (*models.Authority, error) {
	query := `SELECT id, friendly_name, common_name, serial_number, not_before, not_after, 
	                 certificate_pem, private_key_enc, issuer_id, is_root, created_at 
	          FROM authorities WHERE id = ?`
	if d.dbType == "postgres" {
		query = `SELECT id, friendly_name, common_name, serial_number, not_before, not_after, 
		                certificate_pem, private_key_enc, issuer_id, is_root, created_at 
		         FROM authorities WHERE id = $1`
	}

	var auth models.Authority
	err := d.db.QueryRow(query, id).Scan(
		&auth.ID, &auth.FriendlyName, &auth.CommonName, &auth.SerialNumber,
		&auth.NotBefore, &auth.NotAfter, &auth.CertificatePEM, &auth.PrivateKeyEnc,
		&auth.IssuerID, &auth.IsRoot, &auth.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &auth, nil
}

// ListAuthorities retrieves all authorities
func (d *Database) ListAuthorities() ([]*models.Authority, error) {
	query := `SELECT id, friendly_name, common_name, serial_number, not_before, not_after, 
	                 certificate_pem, private_key_enc, issuer_id, is_root, created_at 
	          FROM authorities ORDER BY created_at DESC`

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var authorities []*models.Authority
	for rows.Next() {
		var auth models.Authority
		err := rows.Scan(
			&auth.ID, &auth.FriendlyName, &auth.CommonName, &auth.SerialNumber,
			&auth.NotBefore, &auth.NotAfter, &auth.CertificatePEM, &auth.PrivateKeyEnc,
			&auth.IssuerID, &auth.IsRoot, &auth.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		authorities = append(authorities, &auth)
	}

	return authorities, rows.Err()
}

// DeleteAuthority deletes an authority by ID
func (d *Database) DeleteAuthority(id string) error {
	query := `DELETE FROM authorities WHERE id = ?`
	if d.dbType == "postgres" {
		query = `DELETE FROM authorities WHERE id = $1`
	}

	result, err := d.db.Exec(query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// Certificate operations

// CreateCertificate creates a new certificate
func (d *Database) CreateCertificate(cert *models.Certificate) error {
	query := `INSERT INTO certificates 
	          (id, authority_id, common_name, sans_json, serial_number, certificate_pem, 
	           private_key_enc, revoked, revoked_at, not_before, not_after, created_at,
	           organization, organization_unit, country, province, locality,
	           algorithm, key_size, ec_curve, validity_days, is_server_auth, is_client_auth) 
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	
	if d.dbType == "postgres" {
		query = `INSERT INTO certificates 
		         (id, authority_id, common_name, sans_json, serial_number, certificate_pem, 
		          private_key_enc, revoked, revoked_at, not_before, not_after, created_at,
		          organization, organization_unit, country, province, locality,
		          algorithm, key_size, ec_curve, validity_days, is_server_auth, is_client_auth) 
		         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)`
	}

	_, err := d.db.Exec(query,
		cert.ID, cert.AuthorityID, cert.CommonName, cert.SANsJSON, cert.SerialNumber,
		cert.CertificatePEM, cert.PrivateKeyEnc, cert.Revoked, cert.RevokedAt,
		cert.NotBefore, cert.NotAfter, cert.CreatedAt,
		cert.Organization, cert.OrganizationUnit, cert.Country, cert.Province, cert.Locality,
		cert.Algorithm, cert.KeySize, cert.ECCurve, cert.ValidityDays, cert.IsServerAuth, cert.IsClientAuth,
	)
	return err
}

// GetCertificate retrieves a certificate by ID
func (d *Database) GetCertificate(id string) (*models.Certificate, error) {
	query := `SELECT id, authority_id, common_name, sans_json, serial_number, certificate_pem, 
	                 private_key_enc, revoked, revoked_at, not_before, not_after, created_at,
	                 organization, organization_unit, country, province, locality,
	                 algorithm, key_size, ec_curve, validity_days, is_server_auth, is_client_auth
	          FROM certificates WHERE id = ?`
	if d.dbType == "postgres" {
		query = `SELECT id, authority_id, common_name, sans_json, serial_number, certificate_pem, 
		                private_key_enc, revoked, revoked_at, not_before, not_after, created_at,
		                organization, organization_unit, country, province, locality,
		                algorithm, key_size, ec_curve, validity_days, is_server_auth, is_client_auth
		         FROM certificates WHERE id = $1`
	}

	var cert models.Certificate
	err := d.db.QueryRow(query, id).Scan(
		&cert.ID, &cert.AuthorityID, &cert.CommonName, &cert.SANsJSON, &cert.SerialNumber,
		&cert.CertificatePEM, &cert.PrivateKeyEnc, &cert.Revoked, &cert.RevokedAt,
		&cert.NotBefore, &cert.NotAfter, &cert.CreatedAt,
		&cert.Organization, &cert.OrganizationUnit, &cert.Country, &cert.Province, &cert.Locality,
		&cert.Algorithm, &cert.KeySize, &cert.ECCurve, &cert.ValidityDays, &cert.IsServerAuth, &cert.IsClientAuth,
	)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// ListCertificates retrieves all certificates
func (d *Database) ListCertificates() ([]*models.Certificate, error) {
	query := `SELECT id, authority_id, common_name, sans_json, serial_number, certificate_pem, 
	                 private_key_enc, revoked, revoked_at, not_before, not_after, created_at,
	                 organization, organization_unit, country, province, locality,
	                 algorithm, key_size, ec_curve, validity_days, is_server_auth, is_client_auth
	          FROM certificates ORDER BY created_at DESC`

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certificates []*models.Certificate
	for rows.Next() {
		var cert models.Certificate
		err := rows.Scan(
			&cert.ID, &cert.AuthorityID, &cert.CommonName, &cert.SANsJSON, &cert.SerialNumber,
			&cert.CertificatePEM, &cert.PrivateKeyEnc, &cert.Revoked, &cert.RevokedAt,
			&cert.NotBefore, &cert.NotAfter, &cert.CreatedAt,
			&cert.Organization, &cert.OrganizationUnit, &cert.Country, &cert.Province, &cert.Locality,
			&cert.Algorithm, &cert.KeySize, &cert.ECCurve, &cert.ValidityDays, &cert.IsServerAuth, &cert.IsClientAuth,
		)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, &cert)
	}

	return certificates, rows.Err()
}

// RevokeCertificate marks a certificate as revoked
func (d *Database) RevokeCertificate(id string) error {
	query := `UPDATE certificates SET revoked = ?, revoked_at = ? WHERE id = ?`
	if d.dbType == "postgres" {
		query = `UPDATE certificates SET revoked = $1, revoked_at = $2 WHERE id = $3`
	}

	_, err := d.db.Exec(query, true, sql.NullTime{Time: sql.NullTime{}.Time, Valid: true}, id)
	return err
}

// DeleteCertificate deletes a certificate by ID
func (d *Database) DeleteCertificate(id string) error {
	query := `DELETE FROM certificates WHERE id = ?`
	if d.dbType == "postgres" {
		query = `DELETE FROM certificates WHERE id = $1`
	}

	res, err := d.db.Exec(query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// System config operations

// SetSystemConfig sets a system configuration value
func (d *Database) SetSystemConfig(key, value string) error {
	query := `INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES (?, ?, ?)`
	if d.dbType == "postgres" {
		query = `INSERT INTO system_config (key, value, updated_at) 
		         VALUES ($1, $2, $3) 
		         ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = $3`
	}

	_, err := d.db.Exec(query, key, value, sql.NullTime{}.Time)
	return err
}

// GetSystemConfig retrieves a system configuration value
func (d *Database) GetSystemConfig(key string) (string, error) {
	query := `SELECT value FROM system_config WHERE key = ?`
	if d.dbType == "postgres" {
		query = `SELECT value FROM system_config WHERE key = $1`
	}

	var value string
	err := d.db.QueryRow(query, key).Scan(&value)
	if err != nil {
		return "", err
	}
	return value, nil
}

// IsSetupComplete checks if initial setup has been completed
func (d *Database) IsSetupComplete() (bool, error) {
	query := `SELECT COUNT(*) FROM users`
	var count int
	err := d.db.QueryRow(query).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
