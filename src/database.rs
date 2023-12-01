use sqlx::{prelude::*, SqliteConnection, SqlitePool};

const INIT_METADATA: &str = include_str!("migrations/_metadata.sql");
const MIGRATIONS: &[&str] = &[include_str!("migrations/0000_init.sql")];

async fn get_meta<T>(conn: &mut SqliteConnection, key: &str) -> anyhow::Result<Option<T>>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: Into<anyhow::Error>,
{
    let res = conn
        .fetch_one(sqlx::query("SELECT value FROM meta WHERE key = ?").bind(key))
        .await?;

    let elem: Option<&str> = res.get("value");
    if let Some(value) = elem {
        match T::from_str(value) {
            Ok(s) => Ok(Some(s)),
            Err(e) => Err(anyhow::anyhow!(e.into())),
        }
    } else {
        Ok(None)
    }
}

async fn set_meta<T>(conn: &mut SqliteConnection, key: &str, value: T) -> Result<(), sqlx::Error>
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
    .map(|_| ())
}

async fn init(db: &std::path::Path) -> Result<SqlitePool, anyhow::Error> {
    let mut conn = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(db)
        .create_if_missing(true)
        .connect()
        .await?;

    dbg!(&conn);

    conn.execute(INIT_METADATA).await?;

    let version: usize = get_meta(&mut conn, "db_version").await?.unwrap_or(0);
    assert!(version <= MIGRATIONS.len());

    for (i, m) in MIGRATIONS.iter().skip(version).enumerate() {
        eprintln!("Running migration {i}");
        sqlx::query(m).execute(&mut conn).await.unwrap();
        set_meta(&mut conn, "db_version", i + 1).await?;
    }

    sqlx::sqlite::SqlitePoolOptions::new()
        .connect(db.to_str().unwrap())
        .await
        .map_err(|e| anyhow::anyhow!(e))
}

pub async fn connect(db: &std::path::Path) -> Result<SqlitePool, anyhow::Error> {
    let pool = init(db).await?;
    Ok(pool)
}
