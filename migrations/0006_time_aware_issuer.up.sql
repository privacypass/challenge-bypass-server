-- Time Aware Issuers have a duration and buffer
CREATE TABLE time_aware_issuer(
    id uuid primary key default uuid_generate_v4(),
    issuer_type text not null,
    issuer_cohort smallint default 1,
    created_at timestamp not null default now(),
    expires_at timestamp,
    last_rotated_at timestamp,
    valid_from timestamp not null default now(),
    version integer default 3,
    max_tokens integer,
    buffer integer,
    duration text
);

-- Time Aware Keys are signing keys used by time aware issuers
create table time_aware_keys (
    id uuid primary key default uuid_generate_v4(),
    time_aware_issuer_id uuid references time_aware_issuer(id),
    created_at timestamp not null default now(),
    start_at timestamp not null,
    end_at timestamp not null,
    signing_key text not null,
    cohort smallint not null default 1
);
