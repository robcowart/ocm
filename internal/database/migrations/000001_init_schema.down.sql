-- Drop tables in reverse order
DROP INDEX IF EXISTS idx_certificates_revoked;
DROP INDEX IF EXISTS idx_certificates_serial;
DROP INDEX IF EXISTS idx_certificates_authority;
DROP INDEX IF EXISTS idx_authorities_issuer;
DROP INDEX IF EXISTS idx_authorities_serial;

DROP TABLE IF EXISTS system_config;
DROP TABLE IF EXISTS certificates;
DROP TABLE IF EXISTS authorities;
DROP TABLE IF EXISTS users;
