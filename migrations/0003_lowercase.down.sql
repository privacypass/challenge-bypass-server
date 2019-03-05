alter table issuers rename column issuer_type to "issuerType";
alter table issuers rename column signing_key to "signingKey";
alter table issuers rename column max_tokens to "maxTokens";

drop index redemptions_type;
alter table redemptions rename column issuer_type to "issuerType";

create index redemptions_type on redemptions using hash ("issuerType");
