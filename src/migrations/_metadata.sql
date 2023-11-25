CREATE TABLE IF NOT EXISTS meta (
	key 	TEXT PRIMARY KEY,
	value   TEXT NOT NULL
) WITHOUT ROWID;

INSERT INTO meta(key, value) VALUES ("db_version", "0")
ON CONFLICT(key) DO NOTHING;