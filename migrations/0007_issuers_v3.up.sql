-- v3_issuer - new issuer structure
CREATE TABLE v3_issuers(
    issuer_id uuid primary key default uuid_generate_v4(),
    issuer_type text not null,
    created_at timestamp not null default now(),
    expires_at timestamp,
    last_rotated_at timestamp,
    valid_from timestamp not null default now(),
    buffer integer not null default 1,
    days_out integer not null default 1,
    overlap integer not null default 0,
    issuer_cohort integer not null default 1,
    redemption_repository text not null default 'dynamodb',
    version integer default 3,
    max_tokens integer default 40,
    duration text default null,
    constraint issuer_type_uniq unique (issuer_type)
);


-- v3_issuer_keys - holds all sign/redeem keys for issuers v3
CREATE TABLE v3_issuer_keys (
    key_id uuid primary key default uuid_generate_v4(),
    issuer_id uuid references v3_issuers(issuer_id),
    created_at timestamp not null default now(),
    start_at timestamp,
    end_at timestamp,
    signing_key text not null,
    public_key text,
    cohort smallint not null default 1
);
-- lookups will be done on the public key
CREATE index keys_public_key_idx on v3_issuer_keys(public_key);

-- v1 migrations
insert into v3_issuers (
    issuer_id, issuer_type, created_at, expires_at, last_rotated_at, valid_from,
    buffer, days_out, overlap, issuer_cohort, redemption_repository, version, max_tokens)
select
    id, issuer_type, created_at, expires_at, rotated_at, created_at,
    1, 30*3, 0, 1, 'postgres', version, max_tokens
from issuers
where version = 1;

-- v2 migrations
insert into v3_issuers (
    issuer_id, issuer_type, created_at, expires_at, last_rotated_at, valid_from,
    buffer, days_out, overlap, issuer_cohort, redemption_repository, version, max_tokens)
select
    id, issuer_type, created_at, expires_at, rotated_at, created_at,
    1, 30, 7, 1, 'dynamodb', version, max_tokens
from issuers
where version = 2;

-- keys introduction
insert into v3_issuer_keys (
    issuer_id, created_at, signing_key, cohort)
select
    id, created_at, signing_key, issuer_cohort
from issuers;
