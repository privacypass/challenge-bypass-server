insert into migrations (id, description) values ('0001', 'initial_schema');

create table issuers (
  issuerType text not null primary key,
  G text not null,
  H text not null,
  privateKey text not null,
  maxTokens integer not null
);


create table redemptions (
  id text not null primary key,
  payload text
);
