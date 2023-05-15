INSERT INTO `events_catcheds` (`created_at`,`updated_at`,`deleted_at`,`tx_hash`,`token_address`) VALUES ("2022-05-12 02:03:12.331","2022-05-12 02:03:12.331",NULL,"0xa4f6b8949d2fc1ddb2d5424d4e0a872c53c70febee4d2dc7c055b6f3aca9f006","<binary>")


CREATE TABLE events_catcheds (
	id INTEGER PRIMARY KEY,
	tx_hash TEXT NOT NULL,
	token_address TEXT NOT NULL,
	created_at TIMESTAMP
  DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NULL,
	deleted_at TIMESTAMP NULL
);

CREATE TABLE lp_pairs (
	id INTEGER PRIMARY KEY,
	lp_address TEXT NOT NULL,
	lp_pair_a TEXT NOT NULL,
	lp_pair_b TEXT NOT NULL,
	has_liquidity TEXT NOT NULL,
	events_catched_id INTEGER NOT NULL,
	created_at TIMESTAMP
  DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NULL,
	deleted_at TIMESTAMP NULL
);

ALTER TABLE lp_pairs
RENAME COLUMN events_catcheds_id TO events_catched_id;