-- Fictional custom evaluation case cc_1: replication drift.
-- The primary no longer holds account_7001 but the read replica still does (old email).
BEGIN TRANSACTION;
CREATE TABLE customer_profiles_primary (resource_id TEXT PRIMARY KEY, user_id TEXT, full_name TEXT, email TEXT, phone TEXT, account_status TEXT);
CREATE TABLE customer_profiles_read_replica (resource_id TEXT PRIMARY KEY, user_id TEXT, full_name TEXT, email TEXT, phone TEXT, account_status TEXT);
INSERT INTO customer_profiles_primary VALUES ('account_7999','user_999','Unrelated Person','unrelated@example.org','+1 202 555 0199','ACTIVE');
INSERT INTO customer_profiles_read_replica VALUES ('account_7999','user_999','Unrelated Person','unrelated@example.org','+1 202 555 0199','ACTIVE');
INSERT INTO customer_profiles_read_replica VALUES ('account_7001','user_901','Ines Moreau','ines.m.old@example.org','+33 6 11 22 33 44','ACTIVE');
COMMIT;
