use actix_web::{error, web, Error};
use anyhow::Result;

use crate::rules::Rule;
use sqlx::{SqliteConnection, SqlitePool, Connection, prelude::*, Acquire};
use serde::{Deserialize, Serialize};
use std::{thread::sleep, time::Duration};

const INIT_METADATA: &str = include_str!("migrations/_metadata.sql");
const MIGRATIONS: &[&str] = &[include_str!("migrations/0000_init.sql")];

async fn get_meta<T>(conn: &SqliteConnection, key: &str) -> Option<T>
where
    T: std::str::FromStr,
{
    let res = conn.fetch_one(
        sqlx::query("SELECT value FROM meta WHERE key = ?")
            .bind(key)
    ).await.unwrap();

    res.get("value")
}

async fn set_meta<T>(conn: &SqliteConnection, key: &str, value: T)
where
    T: std::string::ToString,
{
    conn.execute(
        sqlx::query(
            "INSERT INTO meta (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value",

        ).bind([key, &value.to_string().as_ref()]),
    ).await.unwrap();
}

async fn init(db: &std::path::PathBuf) {
    let db = db.to_string_lossy();
    let mut conn = SqliteConnection::connect(db.as_ref()).await.unwrap();

    dbg!(&conn);
    conn.begin().await.unwrap();

    conn.execute(INIT_METADATA).await.unwrap();

    let version: usize = get_meta(&conn, "db_version").await.unwrap_or(0);
    assert!(version <= MIGRATIONS.len());

    for (i, m) in MIGRATIONS.iter().skip(version).enumerate() {
        eprintln!("Running migration {i}");
        conn.execute(m).await.unwrap();
        set_meta(&conn, "db_version", i + 1);
    }
}

pub(crate) async fn connect(db: &std::path::PathBuf) {
    init(db);

    let pool = sqlx::SqlitePool::connect(db).await.unwrap();
    dbg!(pool);
    list_rules(&pool);
}

pub(crate) async fn list_rules(pool: &SqlitePool) {
    let q = sqlx::query(
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
        );

    pool.fetch_all(q).await.unwrap().iter().map(|row| {
        row.try_into::<Rule>()
    })
    .for_each(|r| {
        dbg!(&r);
    });
}
