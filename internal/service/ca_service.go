// Package service provides business logic for certificate management operations.
// It orchestrates the crypto engine and database layers to implement CA and certificate
// management workflows including creation, import, export, and revocation.
package service

import (
	"crypto/x509/pkix"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/robcowart/ocm/internal/config"
	"github.com/robcowart/ocm/internal/crypto"
	"github.com/robcowart/ocm/internal/database"
	"github.com/robcowart/ocm/internal/database/models"
)

// CAService handles Certificate Authority operations
type CAService struct {
	db          *database.Database
	cfg         *config.Config
	userService *UserService
}

// NewCAService creates a new CA service
func NewCAService(db *database.Database, cfg *config.Config, userService *UserService) *CAService {
	return &CAService{
		db:          db,
		cfg:         cfg,
		userService: userService,
	}
}

// getMasterKey retrieves the master key (helper method)
func (s *CAService) getMasterKey() ([]byte, error) {
	return s.userService.GetMasterKey()
}

// CreateRootCARequest represents a request to create a Root CA
type CreateRootCARequest struct {
	FriendlyName     string
	CommonName       string
	Organization     string
	OrganizationUnit string
	Country          string
	Province         string
	Locality         string
	Algorithm        string // "rsa" or "ecdsa"
	RSABits          int
	ECCurve          string
	ValidityDays     int
}

// CreateRootCA creates a new self-signed Root CA
func (s *CAService) CreateRootCA(req *CreateRootCARequest) (*models.Authority, error) {
	// Get master key
	masterKey, err := s.getMasterKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get master key: %w", err)
	}
	if len(masterKey) == 0 {
		return nil, fmt.Errorf("master key not available - service not properly initialized")
	}

	// Set defaults
	if req.Algorithm == "" {
		req.Algorithm = s.cfg.Crypto.DefaultAlgorithm
	}
	if req.RSABits == 0 {
		req.RSABits = s.cfg.Crypto.DefaultRSABits
	}
	if req.ECCurve == "" {
		req.ECCurve = s.cfg.Crypto.DefaultECCurve
	}
	if req.ValidityDays == 0 {
		validityHours := int(s.cfg.Crypto.DefaultCAValidity.Hours())
		req.ValidityDays = validityHours / 24
	}

	// Create subject
	subject := pkix.Name{
		CommonName: req.CommonName,
	}
	if req.Organization != "" {
		subject.Organization = []string{req.Organization}
	}
	if req.OrganizationUnit != "" {
		subject.OrganizationalUnit = []string{req.OrganizationUnit}
	}
	if req.Country != "" {
		subject.Country = []string{req.Country}
	}
	if req.Province != "" {
		subject.Province = []string{req.Province}
	}
	if req.Locality != "" {
		subject.Locality = []string{req.Locality}
	}

	// Generate the CA
	caReq := &crypto.CARequest{
		FriendlyName: req.FriendlyName,
		Subject:      subject,
		Algorithm:    req.Algorithm,
		RSABits:      req.RSABits,
		ECCurve:      req.ECCurve,
		ValidityDays: req.ValidityDays,
	}

	result, err := crypto.GenerateSelfSignedCA(caReq)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA: %w", err)
	}

	// Format serial number as hex (for both storage and encryption associated data)
	serialNumberHex := fmt.Sprintf("%X", result.Certificate.SerialNumber)

	// Encrypt the private key using the hex serial number as associated data
	encryptedKey, err := crypto.EncryptPrivateKey(result.PrivateKeyDER, masterKey, serialNumberHex)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Store in database
	authority := &models.Authority{
		ID:             uuid.New().String(),
		FriendlyName:   req.FriendlyName,
		CommonName:     req.CommonName,
		SerialNumber:   serialNumberHex,
		NotBefore:      result.Certificate.NotBefore,
		NotAfter:       result.Certificate.NotAfter,
		CertificatePEM: result.CertificatePEM,
		PrivateKeyEnc:  encryptedKey,
		IssuerID:       sql.NullString{Valid: false},
		IsRoot:         true,
		CreatedAt:      time.Now(),
	}

	if err := s.db.CreateAuthority(authority); err != nil {
		return nil, fmt.Errorf("failed to store authority: %w", err)
	}

	return authority, nil
}

// ImportCARequest represents a request to import an existing CA
type ImportCARequest struct {
	FriendlyName   string
	CertificatePEM string
	PrivateKeyPEM  string
	Password       string
}

// ImportCA imports an existing CA certificate and private key
func (s *CAService) ImportCA(req *ImportCARequest) (*models.Authority, error) {
	// Get master key
	masterKey, err := s.getMasterKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get master key: %w", err)
	}

	result, err := crypto.ImportCA([]byte(req.CertificatePEM), []byte(req.PrivateKeyPEM), req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to import CA: %w", err)
	}

	// Format serial number as hex (for both storage and encryption associated data)
	serialNumberHex := fmt.Sprintf("%X", result.Certificate.SerialNumber)

	// Encrypt the private key using the hex serial number as associated data
	encryptedKey, err := crypto.EncryptPrivateKey(result.PrivateKeyDER, masterKey, serialNumberHex)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Store in database
	authority := &models.Authority{
		ID:             uuid.New().String(),
		FriendlyName:   req.FriendlyName,
		CommonName:     result.Certificate.Subject.CommonName,
		SerialNumber:   serialNumberHex,
		NotBefore:      result.Certificate.NotBefore,
		NotAfter:       result.Certificate.NotAfter,
		CertificatePEM: result.CertificatePEM,
		PrivateKeyEnc:  encryptedKey,
		IssuerID:       sql.NullString{Valid: false},
		IsRoot:         result.Certificate.IsCA,
		CreatedAt:      time.Now(),
	}

	if err := s.db.CreateAuthority(authority); err != nil {
		return nil, fmt.Errorf("failed to store authority: %w", err)
	}

	return authority, nil
}

// ListAuthorities returns all Certificate Authorities
func (s *CAService) ListAuthorities() ([]*models.Authority, error) {
	return s.db.ListAuthorities()
}

// GetAuthority returns a specific CA by ID
func (s *CAService) GetAuthority(id string) (*models.Authority, error) {
	return s.db.GetAuthority(id)
}

// GetCAPrivateKey retrieves and decrypts a CA's private key
func (s *CAService) GetCAPrivateKey(authority *models.Authority) (interface{}, error) {
	// Get master key
	masterKey, err := s.getMasterKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get master key: %w", err)
	}

	// Debug: Log master key length
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("invalid master key length: got %d bytes, expected 32", len(masterKey))
	}

	// Decrypt the private key
	privateKeyDER, err := crypto.DecryptPrivateKey(authority.PrivateKeyEnc, masterKey, authority.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	// Parse the certificate to determine algorithm
	cert, err := crypto.ParseCertificatePEM([]byte(authority.CertificatePEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	algorithm := crypto.GetAlgorithmFromCert(cert)

	// Parse the private key
	privateKey, err := crypto.ParsePrivateKey(privateKeyDER, algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, nil
}

// AuthorityStatus represents a Certificate Authority with computed status information
// including validity state and days until expiration.
type AuthorityStatus struct {
	*models.Authority
	Status       string `json:"status"` // "valid", "expired", "expiring_soon"
	DaysUntilExp int    `json:"days_until_exp"`
}

// GetAuthorityStatus returns CA with status information
func (s *CAService) GetAuthorityStatus(id string) (*AuthorityStatus, error) {
	auth, err := s.db.GetAuthority(id)
	if err != nil {
		return nil, err
	}

	status := &AuthorityStatus{
		Authority: auth,
	}

	now := time.Now()
	if now.After(auth.NotAfter) {
		status.Status = "expired"
		status.DaysUntilExp = 0
	} else {
		daysUntil := int(auth.NotAfter.Sub(now).Hours() / 24)
		status.DaysUntilExp = daysUntil

		if daysUntil <= 30 {
			status.Status = "expiring_soon"
		} else {
			status.Status = "valid"
		}
	}

	return status, nil
}

// ListAuthoritiesWithStatus returns all CAs with status information
func (s *CAService) ListAuthoritiesWithStatus() ([]*AuthorityStatus, error) {
	authorities, err := s.db.ListAuthorities()
	if err != nil {
		return nil, err
	}

	result := make([]*AuthorityStatus, len(authorities))
	now := time.Now()

	for i, auth := range authorities {
		status := &AuthorityStatus{
			Authority: auth,
		}

		if now.After(auth.NotAfter) {
			status.Status = "expired"
			status.DaysUntilExp = 0
		} else {
			daysUntil := int(auth.NotAfter.Sub(now).Hours() / 24)
			status.DaysUntilExp = daysUntil

			if daysUntil <= 30 {
				status.Status = "expiring_soon"
			} else {
				status.Status = "valid"
			}
		}

		result[i] = status
	}

	return result, nil
}

// DeleteAuthority deletes a Certificate Authority
func (s *CAService) DeleteAuthority(id string) error {
	// TODO: Check if CA has issued certificates before deletion
	// For now, we'll allow deletion - foreign key constraints will handle dependent records
	return s.db.DeleteAuthority(id)
}

// ExportAuthorityRequest represents a request to export a CA
type ExportAuthorityRequest struct {
	AuthorityID string
	Format      string // "pem" or "pkcs12"
	Password    string // For PKCS12
	Legacy      bool   // Use legacy encryption for PKCS12
	CertOnly    bool   // Export certificate only (no private key) - for PEM format only
}

// ExportAuthority exports a CA certificate and optionally private key
func (s *CAService) ExportAuthority(req *ExportAuthorityRequest) ([]byte, error) {
	// Get the CA
	authority, err := s.db.GetAuthority(req.AuthorityID)
	if err != nil {
		return nil, fmt.Errorf("failed to get authority: %w", err)
	}

	// Export based on format
	switch req.Format {
	case "pem":
		// If CertOnly is true, return just the certificate
		if req.CertOnly {
			return []byte(authority.CertificatePEM), nil
		}

		// Otherwise, export certificate + private key
		// Parse CA certificate
		caCert, err := crypto.ParseCertificatePEM([]byte(authority.CertificatePEM))
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
		}

		// Determine algorithm
		algorithm := crypto.GetAlgorithmFromCert(caCert)

		// Get master key to decrypt private key
		masterKey, err := s.getMasterKey()
		if err != nil {
			return nil, fmt.Errorf("failed to get master key: %w", err)
		}

		// Decrypt private key
		privateKeyDER, err := crypto.DecryptPrivateKey(authority.PrivateKeyEnc, masterKey, authority.SerialNumber)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}

		// Export as PEM (certificate + private key)
		pemBundle, err := crypto.ExportPEM(authority.CertificatePEM, privateKeyDER, algorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to export PEM: %w", err)
		}
		return []byte(pemBundle), nil

	case "pkcs12", "pfx":
		// PKCS12 always needs both certificate and private key
		// Get the CA private key
		privateKey, err := s.GetCAPrivateKey(authority)
		if err != nil {
			return nil, fmt.Errorf("failed to get CA private key: %w", err)
		}

		// Parse CA certificate
		caCert, err := crypto.ParseCertificatePEM([]byte(authority.CertificatePEM))
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
		}

		// Export as PKCS12/PFX
		var pfxData []byte
		if req.Legacy {
			pfxData, err = crypto.ExportPKCS12Legacy(caCert, privateKey, req.Password)
		} else {
			pfxData, err = crypto.ExportPKCS12(caCert, privateKey, req.Password)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to export PKCS12: %w", err)
		}
		return pfxData, nil

	default:
		return nil, fmt.Errorf("unsupported export format: %s", req.Format)
	}
}
