-- Your SQL goes here

ALTER TABLE `client_key` DROP COLUMN `encryption_key`;
ALTER TABLE `client_key` ADD COLUMN `encryption_key` BINARY NOT NULL;

