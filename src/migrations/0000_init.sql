CREATE TABLE IF NOT EXISTS rules (
	id 		TEXT 		PRIMARY KEY,
	hash 		TEXT 		NOT NULL UNIQUE,

	-- actions
	action 		TEXT 		NOT NULL,
	deny_action 	TEXT,
	terminate 	BOOLEAN 	NOT NULL,
	expires         DATETIME,

	-- metadata
	source          TEXT		NOT NULL,
	comment 	TEXT,
	created_at 	DATETIME 	NOT NULL,
	updated_at 	DATETIME,

	-- conditions
	addr 		TEXT,
	user_agent 	TEXT,
	network 	TEXT,
	host 		TEXT,
	method 		TEXT,
	path 		TEXT,
	country_code    TEXT,
	asn             INTEGER,
	org             TEXT
) WITHOUT ROWID;
