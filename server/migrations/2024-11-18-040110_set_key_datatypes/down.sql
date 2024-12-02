-- This file should undo anything in `up.sql`
ALTER TABLE `asymmetric_key` DROP COLUMN `public_key`;
ALTER TABLE `asymmetric_key` DROP COLUMN `private_key`;
ALTER TABLE `asymmetric_key` ADD COLUMN `public_key` TEXT NOT NULL;
ALTER TABLE `asymmetric_key` ADD COLUMN `private_key` TEXT NOT NULL;


