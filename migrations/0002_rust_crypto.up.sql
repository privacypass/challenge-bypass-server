drop table issuers;

create table issuers (
  "issuerType" text not null primary key,
  "signingKey" text not null,
  "maxTokens" integer not null
);
