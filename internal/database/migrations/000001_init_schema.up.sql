-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create authorities table (Certificate Authorities)
CREATE TABLE IF NOT EXISTS authorities (
    id TEXT PRIMARY KEY,
    friendly_name TEXT NOT NULL,
    common_name TEXT NOT NULL,
    serial_number TEXT UNIQUE NOT NULL,
    not_before DATETIME NOT NULL,
    not_after DATETIME NOT NULL,
    certificate_pem TEXT NOT NULL,
    private_key_enc BLOB NOT NULL,
    issuer_id TEXT,
    is_root INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (issuer_id) REFERENCES authorities(id) ON DELETE SET NULL
);

-- Create certificates table
CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    authority_id TEXT NOT NULL,
    common_name TEXT NOT NULL,
    sans_json TEXT,
    serial_number TEXT UNIQUE NOT NULL,
    certificate_pem TEXT NOT NULL,
    private_key_enc BLOB NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    revoked_at DATETIME,
    not_before DATETIME NOT NULL,
    not_after DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (authority_id) REFERENCES authorities(id) ON DELETE CASCADE
);

-- Create system_config table for storing master key and other system settings
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_authorities_serial ON authorities(serial_number);
CREATE INDEX IF NOT EXISTS idx_authorities_issuer ON authorities(issuer_id);
CREATE INDEX IF NOT EXISTS idx_certificates_authority ON certificates(authority_id);
CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates(serial_number);
CREATE INDEX IF NOT EXISTS idx_certificates_revoked ON certificates(revoked);
