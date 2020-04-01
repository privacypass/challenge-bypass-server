CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

ALTER TABLE issuers ADD COLUMN id uuid NOT NULL DEFAULT uuid_generate_v4();
ALTER TABLE issuers ADD COLUMN created_at timestamp NOT NULL DEFAULT NOW();
ALTER TABLE issuers ADD COLUMN expires_at timestamp;
ALTER TABLE issuers ADD COLUMN rotated_at timestamp;
ALTER TABLE issuers DROP CONSTRAINT issuers_pkey;
ALTER TABLE issuers ADD PRIMARY KEY (id);
ALTER TABLE issuers ADD COLUMN version integer DEFAULT 1;

-- DROP INDEX CONCURRENTLY IF EXISTS redemptions_type;