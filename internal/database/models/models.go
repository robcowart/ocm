// Package models defines the data structures for database entities in OCM.
// It includes models for users, certificate authorities, certificates, and
// system configuration, representing the core data model for the application.
package models

import (
	"database/sql"
	"time"
)

// User represents a system user
type User struct {
	ID           string    `db:"id"`
	Username     string    `db:"username"`
	PasswordHash string    `db:"password_hash"`
	Role         string    `db:"role"`
	CreatedAt    time.Time `db:"created_at"`
}

// Authority represents a Certificate Authority
type Authority struct {
	ID             string         `db:"id" json:"id"`
	FriendlyName   string         `db:"friendly_name" json:"friendly_name"`
	CommonName     string         `db:"common_name" json:"common_name"`
	SerialNumber   string         `db:"serial_number" json:"serial_number"`
	NotBefore      time.Time      `db:"not_before" json:"not_before"`
	NotAfter       time.Time      `db:"not_after" json:"not_after"`
	CertificatePEM string         `db:"certificate_pem" json:"certificate_pem"`
	PrivateKeyEnc  []byte         `db:"private_key_enc" json:"private_key_enc"`
	IssuerID       sql.NullString `db:"issuer_id" json:"issuer_id"`
	IsRoot         bool           `db:"is_root" json:"is_root"`
	CreatedAt      time.Time      `db:"created_at" json:"created_at"`
}

// Certificate represents a leaf certificate
type Certificate struct {
	ID               string         `db:"id" json:"id"`
	AuthorityID      string         `db:"authority_id" json:"authority_id"`
	CommonName       string         `db:"common_name" json:"common_name"`
	SANsJSON         string         `db:"sans_json" json:"sans_json"`
	SerialNumber     string         `db:"serial_number" json:"serial_number"`
	CertificatePEM   string         `db:"certificate_pem" json:"certificate_pem"`
	PrivateKeyEnc    []byte         `db:"private_key_enc" json:"private_key_enc"`
	Revoked          bool           `db:"revoked" json:"revoked"`
	RevokedAt        sql.NullTime   `db:"revoked_at" json:"revoked_at"`
	NotBefore        time.Time      `db:"not_before" json:"not_before"`
	NotAfter         time.Time      `db:"not_after" json:"not_after"`
	CreatedAt        time.Time      `db:"created_at" json:"created_at"`
	Organization     sql.NullString `db:"organization" json:"organization"`
	OrganizationUnit sql.NullString `db:"organization_unit" json:"organization_unit"`
	Country          sql.NullString `db:"country" json:"country"`
	Province         sql.NullString `db:"province" json:"province"`
	Locality         sql.NullString `db:"locality" json:"locality"`
	Algorithm        string         `db:"algorithm" json:"algorithm"`
	KeySize          sql.NullInt64  `db:"key_size" json:"key_size"`
	ECCurve          sql.NullString `db:"ec_curve" json:"ec_curve"`
	ValidityDays     int            `db:"validity_days" json:"validity_days"`
	IsServerAuth     bool           `db:"is_server_auth" json:"is_server_auth"`
	IsClientAuth     bool           `db:"is_client_auth" json:"is_client_auth"`
}

// SystemConfig represents system-wide configuration stored in the database
type SystemConfig struct {
	Key       string    `db:"key"`
	Value     string    `db:"value"`
	UpdatedAt time.Time `db:"updated_at"`
}
