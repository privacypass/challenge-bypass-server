alter table issuers rename column "issuerType" to issuer_type;
alter table issuers rename column "signingKey" to signing_key;
alter table issuers rename column "maxTokens" to max_tokens;

drop index redemptions_type;
alter table redemptions rename column "issuerType" to issuer_type;

create index redemptions_type on redemptions using hash (issuer_type);
