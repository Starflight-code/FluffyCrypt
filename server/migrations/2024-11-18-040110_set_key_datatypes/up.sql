-- Your SQL goes here
ALTER TABLE `asymmetric_key` DROP COLUMN `public_key`;
ALTER TABLE `asymmetric_key` DROP COLUMN `private_key`;
ALTER TABLE `asymmetric_key` ADD COLUMN `public_key` BINARY NOT NULL;
ALTER TABLE `asymmetric_key` ADD COLUMN `private_key` BINARY NOT NULL;


