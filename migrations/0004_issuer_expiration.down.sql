ALTER TABLE redemptions RENAME CONSTRAINT new_redemptions_pkey TO redemptions_pkey;

ALTER TABLE issuers DROP CONSTRAINT issuers_pkey;
ALTER TABLE issuers ADD PRIMARY KEY (issuer_type);
ALTER TABLE issuers DROP COLUMN id;
ALTER TABLE issuers DROP COLUMN created_at;
ALTER TABLE issuers DROP COLUMN expires_at;
ALTER TABLE issuers DROP COLUMN rotated_at;