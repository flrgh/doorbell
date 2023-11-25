use actix_web::{error, web, Error};
use anyhow::Result;
use std::sync::Arc;

use crate::rules::repo::Repository as RulesRepository;
use crate::rules::Rule;
use crate::types::Repository;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use sqlx::{prelude::*, Acquire, Connection, SqliteConnection, SqlitePool};
use std::{thread::sleep, time::Duration};

const INIT_METADATA: &str = include_str!("migrations/_metadata.sql");
const MIGRATIONS: &[&str] = &[include_str!("migrations/0000_init.sql")];

async fn get_meta<T>(conn: &mut SqliteConnection, key: &str) -> Option<T>
where
    T: std::str::FromStr,
{
    let res = conn
        .fetch_one(sqlx::query("SELECT value FROM meta WHERE key = ?").bind(key))
        .await
        .unwrap();

    let elem: Option<&str> = res.get("value");
    if let Some(value) = elem {
        T::from_str(value).ok()
    } else {
        None
    }
}

async fn set_meta<T>(conn: &mut SqliteConnection, key: &str, value: T)
where
    T: std::string::ToString + Send + Sync,
{
    conn.execute(
        sqlx::query(
            "INSERT INTO meta (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value.to_string()),
    )
    .await
    .unwrap();
}

async fn init(db: &std::path::Path) -> SqlitePool {
    let mut conn = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(db)
        .create_if_missing(true)
        .connect()
        .await
        .unwrap();

    dbg!(&conn);
    //conn.begin().await.unwrap();

    conn.execute(INIT_METADATA).await.unwrap();

    let version: usize = get_meta(&mut conn, "db_version").await.unwrap_or(0);
    assert!(version <= MIGRATIONS.len());

    for (i, m) in MIGRATIONS.iter().skip(version).enumerate() {
        eprintln!("Running migration {i}");
        sqlx::query(m).execute(&mut conn).await.unwrap();
        set_meta(&mut conn, "db_version", i + 1);
    }

    sqlx::sqlite::SqlitePoolOptions::new()
        .connect(db.to_str().unwrap())
        .await
        .unwrap()
}

pub(crate) async fn connect(db: &std::path::Path) -> SqlitePool {
    let pool = init(db).await;

    dbg!(&pool);
    pool
}