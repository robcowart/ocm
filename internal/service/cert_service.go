package service

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/robcowart/ocm/internal/config"
	"github.com/robcowart/ocm/internal/crypto"
	"github.com/robcowart/ocm/internal/database"
	"github.com/robcowart/ocm/internal/database/models"
)

// CertificateService handles certificate operations
type CertificateService struct {
	db          *database.Database
	caService   *CAService
	cfg         *config.Config
	userService *UserService
}

// NewCertificateService creates a new certificate service
func NewCertificateService(db *database.Database, caService *CAService, cfg *config.Config, userService *UserService) *CertificateService {
	return &CertificateService{
		db:          db,
		caService:   caService,
		cfg:         cfg,
		userService: userService,
	}
}

// getMasterKey retrieves the master key (helper method)
func (s *CertificateService) getMasterKey() ([]byte, error) {
	return s.userService.GetMasterKey()
}

// CreateCertificateRequest represents a request to create a certificate
type CreateCertificateRequest struct {
	AuthorityID      string
	CommonName       string
	Organization     string
	OrganizationUnit string
	Country          string
	Province         string
	Locality         string
	SANs             []string // DNS names and IPs
	Algorithm        string
	RSABits          int
	ECCurve          string
	ValidityDays     int
	IsServerAuth     bool
	IsClientAuth     bool
}

// CreateCertificate generates a new certificate signed by the specified CA
func (s *CertificateService) CreateCertificate(req *CreateCertificateRequest) (*models.Certificate, error) {
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
		validityHours := int(s.cfg.Crypto.DefaultCertValidity.Hours())
		req.ValidityDays = validityHours / 24
	}

	// Get the CA
	authority, err := s.caService.GetAuthority(req.AuthorityID)
	if err != nil {
		return nil, fmt.Errorf("failed to get authority: %w", err)
	}

	// Parse CA certificate
	caCert, err := crypto.ParseCertificatePEM([]byte(authority.CertificatePEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Get CA private key
	caPrivateKey, err := s.caService.GetCAPrivateKey(authority)
	if err != nil {
		return nil, fmt.Errorf("failed to get CA private key: %w", err)
	}

	// Create certificate request
	certReq := &crypto.CertificateRequest{
		CommonName:   req.CommonName,
		SANs:         req.SANs,
		Algorithm:    req.Algorithm,
		RSABits:      req.RSABits,
		ECCurve:      req.ECCurve,
		ValidityDays: req.ValidityDays,
		IsServerAuth: req.IsServerAuth,
		IsClientAuth: req.IsClientAuth,
	}

	if req.Organization != "" {
		certReq.Organization = []string{req.Organization}
	}
	if req.OrganizationUnit != "" {
		certReq.OrganizationUnit = []string{req.OrganizationUnit}
	}
	if req.Country != "" {
		certReq.Country = []string{req.Country}
	}
	if req.Province != "" {
		certReq.Province = []string{req.Province}
	}
	if req.Locality != "" {
		certReq.Locality = []string{req.Locality}
	}

	// Generate certificate
	result, err := crypto.GenerateCertificate(certReq, caCert, caPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Get master key for encryption
	masterKey, err := s.getMasterKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get master key: %w", err)
	}

	// Encrypt private key
	encryptedKey, err := crypto.EncryptPrivateKey(result.PrivateKeyDER, masterKey, result.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Serialize SANs to JSON
	sansJSON, err := json.Marshal(req.SANs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SANs: %w", err)
	}

	// Store in database
	certificate := &models.Certificate{
		ID:               uuid.New().String(),
		AuthorityID:      req.AuthorityID,
		CommonName:       req.CommonName,
		SANsJSON:         string(sansJSON),
		SerialNumber:     result.SerialNumber,
		CertificatePEM:   result.CertificatePEM,
		PrivateKeyEnc:    encryptedKey,
		Revoked:          false,
		RevokedAt:        sql.NullTime{Valid: false},
		NotBefore:        result.Certificate.NotBefore,
		NotAfter:         result.Certificate.NotAfter,
		CreatedAt:        time.Now(),
		Organization:     sql.NullString{String: req.Organization, Valid: req.Organization != ""},
		OrganizationUnit: sql.NullString{String: req.OrganizationUnit, Valid: req.OrganizationUnit != ""},
		Country:          sql.NullString{String: req.Country, Valid: req.Country != ""},
		Province:         sql.NullString{String: req.Province, Valid: req.Province != ""},
		Locality:         sql.NullString{String: req.Locality, Valid: req.Locality != ""},
		Algorithm:        req.Algorithm,
		KeySize:          sql.NullInt64{Int64: int64(req.RSABits), Valid: req.RSABits > 0},
		ECCurve:          sql.NullString{String: req.ECCurve, Valid: req.ECCurve != ""},
		ValidityDays:     req.ValidityDays,
		IsServerAuth:     req.IsServerAuth,
		IsClientAuth:     req.IsClientAuth,
	}

	if err := s.db.CreateCertificate(certificate); err != nil {
		return nil, fmt.Errorf("failed to store certificate: %w", err)
	}

	return certificate, nil
}

// ListCertificates returns all certificates
func (s *CertificateService) ListCertificates() ([]*models.Certificate, error) {
	return s.db.ListCertificates()
}

// GetCertificate returns a specific certificate by ID
func (s *CertificateService) GetCertificate(id string) (*models.Certificate, error) {
	return s.db.GetCertificate(id)
}

// RevokeCertificate marks a certificate as revoked
func (s *CertificateService) RevokeCertificate(id string) error {
	return s.db.RevokeCertificate(id)
}

// DeleteCertificate deletes a certificate by ID
func (s *CertificateService) DeleteCertificate(id string) error {
	return s.db.DeleteCertificate(id)
}

// ExportRequest represents a request to export a certificate
type ExportRequest struct {
	CertificateID string
	Format        string // "pem" or "pkcs12"
	Password      string // For PKCS12
	Legacy        bool   // Use legacy encryption for PKCS12
	SplitFiles    bool   // Export cert and key as separate files (PEM only)
}

// ExportCertificate exports a certificate in the requested format
func (s *CertificateService) ExportCertificate(req *ExportRequest) ([]byte, error) {
	// Get the certificate
	cert, err := s.db.GetCertificate(req.CertificateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	// Parse certificate
	x509Cert, err := crypto.ParseCertificatePEM([]byte(cert.CertificatePEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Get master key for decryption
	masterKey, err := s.getMasterKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get master key: %w", err)
	}

	// Decrypt private key
	privateKeyDER, err := crypto.DecryptPrivateKey(cert.PrivateKeyEnc, masterKey, cert.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	// Determine algorithm
	algorithm := crypto.GetAlgorithmFromCert(x509Cert)

	// Parse private key
	privateKey, err := crypto.ParsePrivateKey(privateKeyDER, algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Get CA certificate for chain
	authority, err := s.caService.GetAuthority(cert.AuthorityID)
	if err != nil {
		return nil, fmt.Errorf("failed to get authority: %w", err)
	}

	caCert, err := crypto.ParseCertificatePEM([]byte(authority.CertificatePEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Export based on format
	switch req.Format {
	case "pem":
		if req.SplitFiles {
			// Export as separate certificate and key files in a ZIP
			certFile, keyFile, err := crypto.ExportPEMSeparate(cert.CertificatePEM, privateKeyDER, algorithm, authority.CertificatePEM)
			if err != nil {
				return nil, fmt.Errorf("failed to export PEM separately: %w", err)
			}

			// Create ZIP archive with both files
			zipData, err := createZIPWithFiles(map[string]string{
				cert.CommonName + "_cert.pem": certFile,
				cert.CommonName + "_key.pem":  keyFile,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create ZIP archive: %w", err)
			}
			return zipData, nil
		}

		// Export as single combined PEM file (default behavior)
		pemBundle, err := crypto.ExportPEM(cert.CertificatePEM, privateKeyDER, algorithm, authority.CertificatePEM)
		if err != nil {
			return nil, fmt.Errorf("failed to export PEM: %w", err)
		}
		return []byte(pemBundle), nil

	case "pkcs12", "pfx":
		var pfxData []byte
		if req.Legacy {
			pfxData, err = crypto.ExportPKCS12Legacy(x509Cert, privateKey, req.Password, caCert)
		} else {
			pfxData, err = crypto.ExportPKCS12(x509Cert, privateKey, req.Password, caCert)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to export PKCS12: %w", err)
		}
		return pfxData, nil

	default:
		return nil, fmt.Errorf("unsupported export format: %s", req.Format)
	}
}

// CertificateStatus represents certificate with status information
type CertificateStatus struct {
	*models.Certificate
	Status       string   `json:"status"`
	DaysUntilExp int      `json:"days_until_exp"`
	SANs         []string `json:"sans"`
	IssuerName   string   `json:"issuer_name"`
}

// MarshalJSON implements custom JSON marshaling to flatten sql.Null* types
func (cs *CertificateStatus) MarshalJSON() ([]byte, error) {
	type Alias CertificateStatus
	return json.Marshal(&struct {
		*Alias
		Organization     string `json:"organization"`
		OrganizationUnit string `json:"organization_unit"`
		Country          string `json:"country"`
		Province         string `json:"province"`
		Locality         string `json:"locality"`
		KeySize          int    `json:"key_size"`
		ECCurve          string `json:"ec_curve"`
	}{
		Alias:            (*Alias)(cs),
		Organization:     cs.Certificate.Organization.String,
		OrganizationUnit: cs.Certificate.OrganizationUnit.String,
		Country:          cs.Certificate.Country.String,
		Province:         cs.Certificate.Province.String,
		Locality:         cs.Certificate.Locality.String,
		KeySize:          int(cs.Certificate.KeySize.Int64),
		ECCurve:          cs.Certificate.ECCurve.String,
	})
}

// GetCertificateStatus returns certificate with status information
func (s *CertificateService) GetCertificateStatus(id string) (*CertificateStatus, error) {
	cert, err := s.db.GetCertificate(id)
	if err != nil {
		return nil, err
	}

	return s.buildCertificateStatus(cert)
}

// ListCertificatesWithStatus returns all certificates with status information
func (s *CertificateService) ListCertificatesWithStatus() ([]*CertificateStatus, error) {
	certs, err := s.db.ListCertificates()
	if err != nil {
		return nil, err
	}

	result := make([]*CertificateStatus, len(certs))
	for i, cert := range certs {
		status, err := s.buildCertificateStatus(cert)
		if err != nil {
			return nil, err
		}
		result[i] = status
	}

	return result, nil
}

func (s *CertificateService) buildCertificateStatus(cert *models.Certificate) (*CertificateStatus, error) {
	status := &CertificateStatus{
		Certificate: cert,
	}

	// Parse SANs
	var sans []string
	if cert.SANsJSON != "" {
		if err := json.Unmarshal([]byte(cert.SANsJSON), &sans); err == nil {
			status.SANs = sans
		}
	}

	// Get issuer name
	if authority, err := s.caService.GetAuthority(cert.AuthorityID); err == nil {
		status.IssuerName = authority.FriendlyName
	}

	// Determine status
	now := time.Now()
	if cert.Revoked {
		status.Status = "revoked"
		status.DaysUntilExp = 0
	} else if now.After(cert.NotAfter) {
		status.Status = "expired"
		status.DaysUntilExp = 0
	} else {
		daysUntil := int(cert.NotAfter.Sub(now).Hours() / 24)
		status.DaysUntilExp = daysUntil

		if daysUntil <= 30 {
			status.Status = "expiring_soon"
		} else {
			status.Status = "valid"
		}
	}

	return status, nil
}

// createZIPWithFiles creates a ZIP archive containing the provided files
// files is a map of filename -> content
func createZIPWithFiles(files map[string]string) ([]byte, error) {
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	for filename, content := range files {
		fileWriter, err := zipWriter.Create(filename)
		if err != nil {
			return nil, fmt.Errorf("failed to create file in ZIP: %w", err)
		}

		_, err = fileWriter.Write([]byte(content))
		if err != nil {
			return nil, fmt.Errorf("failed to write file content: %w", err)
		}
	}

	err := zipWriter.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close ZIP writer: %w", err)
	}

	return buf.Bytes(), nil
}
