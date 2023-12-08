CREATE TABLE IF NOT EXISTS "rules" (
	"id" 		TEXT 		NOT NULL UNIQUE,
	"hash" 		TEXT 		NOT NULL UNIQUE,

	-- behavior
	"action"        TEXT 		NOT NULL,
	"terminate" 	BOOLEAN 	NOT NULL,
	"expires"       DATETIME,

	-- metadata
	"source"        TEXT		NOT NULL,
	"comment" 	TEXT,
	"created_at" 	DATETIME 	NOT NULL,
	"updated_at" 	DATETIME,

	-- conditions
	"addr"          TEXT,
	"cidr"          TEXT,
	"user_agent"    TEXT,
	"host"          TEXT,
	"path"          TEXT,
	"method"        TEXT,
	"country_code"  TEXT,
	"asn"           TEXT,
	"org"           TEXT,

	PRIMARY KEY("id")
) WITHOUT ROWID;

CREATE UNIQUE INDEX "rules_idx_id" ON "rules" (
	"id"
);

CREATE UNIQUE INDEX "rules_idx_hash" ON "rules" (
	"hash"
);

CREATE TABLE "access_requests" (
	"token"		TEXT 		NOT NULL UNIQUE,
	"addr"		TEXT 		NOT NULL UNIQUE,
	"request"	TEXT 		NOT NULL,
	"timestamp"	DATETIME 	NOT NULL,

	PRIMARY KEY("token")
) WITHOUT ROWID;

CREATE UNIQUE INDEX "access_requests_idx_addr" ON "access_requests" (
	"addr"
);

CREATE UNIQUE INDEX "access_requests_idx_token" ON "access_requests" (
	"token"
);
