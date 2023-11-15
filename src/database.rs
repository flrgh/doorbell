use actix_web::{error, web, Error};
use anyhow::Result;

use crate::rules::Rule;
use r2d2_sqlite::rusqlite;
use r2d2_sqlite::rusqlite::Statement;
use serde::{Deserialize, Serialize};
use std::{thread::sleep, time::Duration};

pub type Pool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;
pub type Connection = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;

const NO_PARAMS: &[&dyn rusqlite::ToSql] = &[];

const INIT_METADATA: &str = include_str!("migrations/_metadata.sql");

const MIGRATIONS: &[&str] = &[include_str!("migrations/0000_init.sql")];

fn get_meta<T>(conn: &rusqlite::Connection, key: &str) -> Option<T>
where
    T: std::str::FromStr,
{
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
        row.get(0)
    })
    .unwrap_or(None)
    .and_then(|s: String| s.parse::<T>().ok())
}

fn set_meta<T>(conn: &rusqlite::Connection, key: &str, value: T)
where
    T: std::string::ToString,
{
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [key, &value.to_string()],
    )
    .unwrap();
}

fn init(db: &std::path::PathBuf) {
    let conn = rusqlite::Connection::open(db).unwrap();
    dbg!(&conn);
    conn.execute_batch(INIT_METADATA).unwrap();

    let version: usize = get_meta(&conn, "db_version").unwrap_or(0);
    assert!(version <= MIGRATIONS.len());

    for (i, m) in MIGRATIONS.iter().skip(version).enumerate() {
        eprintln!("Running migration {i}");
        conn.execute_batch(m).unwrap();
        set_meta(&conn, "db_version", i + 1);
    }
}

pub(crate) fn connect(db: &std::path::PathBuf) {
    init(db);

    let manager = r2d2_sqlite::SqliteConnectionManager::file(db);
    let pool = Pool::new(manager).unwrap();
    let conn = pool.get().unwrap();
    dbg!(pool);
}

pub(crate) fn list_rules(conn: &Connection) {
    let mut s = conn
        .prepare(
            "SELECT
                id,
                hash,
                action,
                deny_action,
                terminate,
                expires,
                source,
                comment,
                created_at,
                updated_at,
                conditions
            FROM rules",
        )
        .unwrap();

    s.query_map([], |row| {
        dbg!(&row);
        Ok(Rule {
            id: row.get(0)?,
            hash: row.get(1)?,
            action: row.get(2)?,
            deny_action: row.get(3)?,
            terminate: row.get(4)?,
            expires: row.get(5)?,
            source: row.get(6)?,
            comment: row.get(7)?,
            created_at: row.get(8)?,
            updated_at: row.get(9)?,
            conditions: row.get(10)?,
        })
    })
    .unwrap();
}
