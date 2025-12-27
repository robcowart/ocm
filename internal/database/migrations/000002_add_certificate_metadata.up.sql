-- Add certificate metadata columns for full cloning support
ALTER TABLE certificates ADD COLUMN organization TEXT;
ALTER TABLE certificates ADD COLUMN organization_unit TEXT;
ALTER TABLE certificates ADD COLUMN country TEXT;
ALTER TABLE certificates ADD COLUMN province TEXT;
ALTER TABLE certificates ADD COLUMN locality TEXT;
ALTER TABLE certificates ADD COLUMN algorithm TEXT NOT NULL DEFAULT 'rsa';
ALTER TABLE certificates ADD COLUMN key_size INTEGER;
ALTER TABLE certificates ADD COLUMN ec_curve TEXT;
ALTER TABLE certificates ADD COLUMN validity_days INTEGER NOT NULL DEFAULT 365;
ALTER TABLE certificates ADD COLUMN is_server_auth INTEGER NOT NULL DEFAULT 1;
ALTER TABLE certificates ADD COLUMN is_client_auth INTEGER NOT NULL DEFAULT 0;

