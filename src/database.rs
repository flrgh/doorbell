use actix_web::{error, web, Error};
use anyhow::Result;
use r2d2;
use r2d2_sqlite;
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
    let mut stmt = conn.prepare("INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value").unwrap();

    stmt.execute(&[key, &value.to_string()]).unwrap();
}

fn init(db: &str) {
    let conn = rusqlite::Connection::open(db).unwrap();
    dbg!(&conn);
    conn.execute_batch(INIT_METADATA).unwrap();

    let version: usize = get_meta(&conn, "db_version").unwrap_or(0);
    assert!(version <= MIGRATIONS.len());

    for i in version..MIGRATIONS.len() {
        println!("Running migration {}", i);
        conn.execute_batch(MIGRATIONS[i]).unwrap();
        set_meta(&conn, "db_version", i + 1);
    }

    dbg!(version);
    todo!()
}

pub(crate) fn connect(db: &str) {
    init(db);

    let manager = r2d2_sqlite::SqliteConnectionManager::file(db);
    let pool = Pool::new(manager).unwrap();
    dbg!(pool);
}
