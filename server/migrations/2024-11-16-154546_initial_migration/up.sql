-- Your SQL goes here
CREATE TABLE `client_key`(
	`id` INTEGER NOT NULL PRIMARY KEY,
	`asymmetric_key_id` INTEGER NOT NULL REFERENCES `asymmetric_key`(`id`),
	`ucid` BIGINT NOT NULL,
	`encryption_key` TEXT NOT NULL
);

CREATE TABLE `asymmetric_key`(
	`id` INTEGER NOT NULL PRIMARY KEY,
	`public_key` TEXT NOT NULL,
	`private_key` TEXT NOT NULL,
	`algo_metadata` TEXT NOT NULL
);

