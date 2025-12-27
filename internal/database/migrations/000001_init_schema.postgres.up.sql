-- PostgreSQL schema
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS authorities (
    id UUID PRIMARY KEY,
    friendly_name VARCHAR(255) NOT NULL,
    common_name VARCHAR(255) NOT NULL,
    serial_number VARCHAR(64) UNIQUE NOT NULL,
    not_before TIMESTAMP NOT NULL,
    not_after TIMESTAMP NOT NULL,
    certificate_pem TEXT NOT NULL,
    private_key_enc BYTEA NOT NULL,
    issuer_id UUID,
    is_root BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (issuer_id) REFERENCES authorities(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS certificates (
    id UUID PRIMARY KEY,
    authority_id UUID NOT NULL,
    common_name VARCHAR(255) NOT NULL,
    sans_json JSONB,
    serial_number VARCHAR(64) UNIQUE NOT NULL,
    certificate_pem TEXT NOT NULL,
    private_key_enc BYTEA NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMP,
    not_before TIMESTAMP NOT NULL,
    not_after TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (authority_id) REFERENCES authorities(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS system_config (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_authorities_serial ON authorities(serial_number);
CREATE INDEX IF NOT EXISTS idx_authorities_issuer ON authorities(issuer_id);
CREATE INDEX IF NOT EXISTS idx_certificates_authority ON certificates(authority_id);
CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates(serial_number);
CREATE INDEX IF NOT EXISTS idx_certificates_revoked ON certificates(revoked);
CREATE INDEX IF NOT EXISTS idx_certificates_sans ON certificates USING GIN (sans_json);
