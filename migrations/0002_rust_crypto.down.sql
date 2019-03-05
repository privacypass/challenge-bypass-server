drop table issuers;

create table issuers (
  "issuerType" text not null primary key,
  G text not null,
  H text not null,
  "privateKey" text not null,
  "maxTokens" integer not null
);
