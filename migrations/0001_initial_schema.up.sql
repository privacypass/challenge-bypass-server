create table issuers (
  "issuerType" text not null primary key,
  G text not null,
  H text not null,
  "privateKey" text not null,
  "maxTokens" integer not null
);


create table redemptions (
  id text not null primary key,
  "issuerType" text not null,
  ts timestamp not null,
  payload text
);

create index redemptions_type on redemptions using hash ("issuerType");
