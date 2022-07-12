# Time Aware Issuers

There exists a need to have issuers support different signing keys for configurable
intervals of times, whereby an issuer can sign with a particular key representing a
finite interval of time, and on that period of time the signature will be valid for
redemption.

## Database Changes Required

To support this feature, the following new tables will need to be created:

```sql
-- time_aware_issuer will represent the v3 issuer, which has time aware signing keys
create table time_aware_issuer(
    id uuid primary key default generate_uuidv4(),
    issuer_type text not null,
    created_at datetime with time zone,
    expires_at datetime with time zone,
    last_rotated_at datetime with time zone,
    max_tokens integer,
    buffer integer,
    duration text
);

-- time_aware_keys will represent the v3 issuer keys which are time aware
create table time_aware_keys (
    id uuid primary key default generate_uuidv4(),
    time_aware_issuer_id uuid references time_aware_issuer(id),
    created_at datetime with time zone,
    start_at datetime with time zone,
    end_at datetime with time zone,
    signing_key text not null,
    public_key text not null,
    cohort text not null
);
```

## API changes required

The following new API endpoint will need to be created:

```bash
curl "https://challenge-bypass-server/v3/issuer" -d'
{
    "name": <issuer_type>::string,
    "max_tokens": <max_tokens>::integer,
    "valid_from": <issuance_start>::rfc3339,
    "duration": <duration>::iso8601,
    "buffer": <number_of_durations>::integer
    "overlap": <number_of_overlap_duration>::integer
}
'
```

Upon calling this endpoint the handler should perform the following steps:

1. Insertion of `time_aware_issuer` in database
2. Creation of `buffer` number of `time_aware_keys` in database
3. Queuing of time aware key rotation at `duration` periods off of `valid_from` datetime

## Alterations to "Rotation" Logic

Each day rotator will identify issuers that satisfy greatest( keys[].end_at ) - ( issuer.buffer * ( issuer.days_out - issuer.overlap ) ) < now() and creates a key with key.start_at = greatest(keys[].end_at) - issuer.overlap and key.end_at = key.start_at + issuer.days_out for each cohort

## Batch Job changes required

At `duration` periods from `valid_from` for time aware issuers a batch job should run
to verify that `buffer` number of keys are created and available for said issuer to sign
requests with.  I.E. every day a job will run that will look at the number of keys for a given
time aware issuer, and validate that there are `buffer` keys from `now` created.

If keys need to be created then the job runner will create new a new signing key and insert said
key into the `time_aware_key` table, and start handling signing requests.

## Signing Requests

This implementation of challenge bypass already handles signing requests from a kafka topic.  This service
will ingest a batch (`buffer` + `overlap`) of blinded credentials in base64 standard encoding.  If
`len(blinded_credentials)` % (`buffer`+`overlap`) != 0 the service shall return an error back to the caller.

Otherwise the service shall take (`len(blinded_credentials)`/(`buffer`+`overlap`)) of the blinded tokens
and perform signing iteratively across all `buffer`+`overlap` keys in the `time_aware_keys` for the
given `issuer_type` within the signing request message.

## Signing Results

After the service performs signing across each issuer, the iterative batches of signed tokens are
returned to the caller in a single signing result payload through kafka.  There will be one Signing
Result record in the `data` array for each signing key for `buffer`+`overlap`.

