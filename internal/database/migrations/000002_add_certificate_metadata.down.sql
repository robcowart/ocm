-- SQLite doesn't support DROP COLUMN directly without recreating the table
-- This migration file documents the rollback process but doesn't implement it
-- To rollback: manually recreate the certificates table without the metadata columns

-- For reference, the added columns were:
-- organization, organization_unit, country, province, locality
-- algorithm, key_size, ec_curve, validity_days
-- is_server_auth, is_client_auth

