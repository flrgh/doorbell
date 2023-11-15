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

	conditions      TEXT
) WITHOUT ROWID;
