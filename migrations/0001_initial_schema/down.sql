drop table issuers;
drop table redemption;
drop index redemptions_type;

delete from migrations where id = '0001';
