CREATE TABLE IF NOT EXISTS rules (
	id 		TEXT 		PRIMARY KEY,
	hash 		TEXT 		NOT NULL UNIQUE,

	-- behavior
	action 		TEXT 		NOT NULL,
	terminate 	BOOLEAN 	NOT NULL,
	expires         DATETIME,

	-- metadata
	source          TEXT		NOT NULL,
	comment 	TEXT,
	created_at 	DATETIME 	NOT NULL,
	updated_at 	DATETIME,

	-- conditions
	addr TEXT,
	cidr TEXT,
	user_agent TEXT,
	host TEXT,
	path TEXT,
	method TEXT,
	country_code TEXT,
	asn TEXT,
	org TEXT
) WITHOUT ROWID;
