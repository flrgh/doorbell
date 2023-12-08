use crate::types::{ForwardedRequest, IpAddr};
use actix_web::web::Data;
use anyhow;
use chrono::prelude::*;
use hex;
use serde_derive::Serialize;
use sqlx::SqlitePool;
use sqlx::{FromRow, Type};
use sqlx_sqlite::Sqlite;

#[derive(Debug, Eq, PartialEq, Type, Clone, Serialize, FromRow)]
pub struct Request {
    token: String,
    addr: IpAddr,

    #[sqlx(json)]
    request: ForwardedRequest,
    timestamp: DateTime<Utc>,
}

impl Request {
    pub fn from_forwarded(fr: &ForwardedRequest) -> Self {
        let token: [u8; 24] = rand::random();

        Self {
            token: hex::encode(token),
            addr: fr.addr,
            request: fr.clone(),
            timestamp: fr.timestamp,
        }
    }
}

pub struct Repository {
    pool: Data<SqlitePool>,
}

impl Repository {
    pub fn new(pool: Data<SqlitePool>) -> Self {
        Self { pool }
    }
}

impl Repository {
    async fn insert(&self, req: &Request) -> anyhow::Result<()> {
        let Request {
            token,
            addr,
            request,
            timestamp,
        } = req.clone();

        sqlx::query_as::<Sqlite, Request>(
            "INSERT INTO access_requests (
                token,
                addr,
                request,
                timestamp
            ) VALUES (
                ?, ?, ?, ?
            )
        ",
        )
        .bind(token)
        .bind(&addr)
        .bind(&request)
        .bind(timestamp)
        .fetch_all(self.pool.as_ref())
        .await
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!(e))
    }

    async fn get(&self, token: &str) -> Result<Option<Request>, anyhow::Error> {
        let rule = sqlx::query_as::<_, Request>("SELECT * FROM access_requests WHERE token = ?")
            .bind(token)
            .fetch_one(self.pool.as_ref())
            .await;

        match rule {
            Ok(row) => Ok(Some(row)),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(anyhow::anyhow!(e)),
        }
    }

    async fn get_by_addr(&self, addr: &IpAddr) -> Result<Option<Request>, anyhow::Error> {
        let rule = sqlx::query_as::<_, Request>("SELECT * FROM access_requests WHERE addr = ?")
            .bind(addr)
            .fetch_one(self.pool.as_ref())
            .await;

        match rule {
            Ok(row) => Ok(Some(row)),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(anyhow::anyhow!(e)),
        }
    }

    async fn get_all(&self) -> Result<Vec<Request>, anyhow::Error> {
        Ok(
            sqlx::query_as::<_, Request>("SELECT * FROM access_requests")
                .fetch_all(self.pool.as_ref())
                .await?,
        )
    }

    async fn delete(&self, token: &str) -> Result<Option<Request>, anyhow::Error> {
        let old = self.get(token).await?;

        sqlx::query("DELETE FROM access_requests WHERE token = ?")
            .bind(token)
            .execute(self.pool.as_ref())
            .await?;

        Ok(old)
    }

    async fn truncate(&self) -> Result<(), anyhow::Error> {
        sqlx::query("DELETE FROM access_requests")
            .execute(self.pool.as_ref())
            .await
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!(e))
    }

    pub async fn delete_where<T>(&self, column: &str, value: T) -> anyhow::Result<()>
    where
        T: Send,
        T: sqlx::Type<sqlx::Sqlite>,
        T: for<'a> sqlx::Encode<'a, sqlx::Sqlite>,
    {
        sqlx::query("DELETE FROM access_requests WHERE ? = ?")
            .bind(column)
            .bind(value)
            .execute(self.pool.as_ref())
            .await
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!(e))
    }

    pub async fn incoming(&self, forwarded: &ForwardedRequest) {
        if let Ok(Some(current)) = self.get_by_addr(&forwarded.addr).await {
            log::info!(
                "there's already a pending request for this client: {:#?}",
                current
            );
            return;
        }

        let req = Request::from_forwarded(&forwarded);
        let res = self.insert(&req).await;
        dbg!(res);
    }
}
