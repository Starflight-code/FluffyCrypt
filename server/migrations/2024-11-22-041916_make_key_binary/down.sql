-- This file should undo anything in `up.sql`

ALTER TABLE `client_key` DROP COLUMN `encryption_key`;
ALTER TABLE `client_key` ADD COLUMN `encryption_key` TEXT NOT NULL;

