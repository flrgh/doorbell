use crate::rules::*;
use crate::types;
use crate::types::Repository as RepoTrait;
use anyhow;
use async_trait::async_trait;
use sqlx::Type;
use sqlx::{prelude::*, Acquire, Connection, SqliteConnection, SqlitePool};
use std::sync::Arc;
use tokio;

use super::DenyAction;

pub struct Repository {
    pool: Arc<SqlitePool>,
}

impl Repository {
    pub fn new(pool: Arc<SqlitePool>) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Eq, PartialEq, sqlx::Type)]
struct RuleRow {
    id: String,
    action: String,
    deny_action: Option<String>,
    hash: String,
    created_at: chrono::NaiveDateTime,
    updated_at: Option<chrono::NaiveDateTime>,
    terminate: Option<bool>,
    comment: Option<String>,
    source: String,
    expires: Option<chrono::NaiveDateTime>,

    addr: Option<String>,
    cidr: Option<String>,
    user_agent: Option<String>,
    host: Option<String>,
    path: Option<String>,
    country_code: Option<String>,
    method: Option<String>,
    asn: Option<String>,
    org: Option<String>,
}

impl TryInto<Rule> for RuleRow {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Rule, Self::Error> {
        Ok(Rule {
            id: self.id.parse()?,
            action: self.action.parse()?,
            deny_action: match self.deny_action {
                None => None,
                Some(da) => match da.parse() {
                    Ok(da) => Some(da),
                    Err(e) => {
                        return Err(anyhow::anyhow!(e));
                    }
                },
            },
            hash: self.hash,
            created_at: self.created_at.and_utc(),
            updated_at: self.updated_at.map(|t| t.and_utc()),
            terminate: self.terminate.unwrap_or(false),
            comment: self.comment,
            source: self.source.parse()?,
            expires: self.expires.map(|expires| expires.and_utc()),
            addr: match self.addr {
                Some(addr) => Some(addr.parse()?),
                None => None,
            },
            cidr: match self.cidr {
                Some(cidr) => Some(cidr.parse()?),
                None => None,
            },
            user_agent: match self.user_agent {
                Some(user_agent) => Some(user_agent.parse()?),
                None => None,
            },
            host: match self.host {
                Some(host) => Some(host.parse()?),
                None => None,
            },
            path: match self.path {
                Some(path) => Some(path.parse()?),
                None => None,
            },
            country_code: match self.country_code {
                Some(country_code) => Some(country_code.parse()?),
                None => None,
            },
            method: match self.method {
                Some(method) => Some(method.parse()?),
                None => None,
            },
            asn: match self.asn {
                Some(asn) => Some(asn.parse()?),
                None => None,
            },
            org: match self.org {
                Some(org) => Some(org.parse()?),
                None => None,
            },
        })
    }
}

impl From<Rule> for RuleRow {
    fn from(val: Rule) -> Self {
        Self {
            id: val.id.into(),
            action: val.action.to_string(),
            deny_action: val.deny_action.map(|da| da.to_string()),
            hash: val.hash,
            created_at: val.created_at.naive_utc(),
            updated_at: val.updated_at.map(|ua| ua.naive_utc()),
            terminate: Some(val.terminate),
            comment: val.comment,
            source: val.source.to_string(),
            expires: val.expires.map(|exp| exp.naive_utc()),
            addr: val.addr.map(|addr| addr.to_string()),
            cidr: val.cidr.map(|cidr| cidr.to_string()),
            user_agent: val.user_agent.map(|user_agent| user_agent.into()),
            host: val.host.map(|host| host.into()),
            path: val.path.map(|path| path.into()),
            country_code: val
                .country_code
                .map(|country_code| country_code.to_string()),
            method: val.method.map(|method| method.to_string()),
            asn: val.asn.map(|asn| asn.to_string()),
            org: val.org.map(|org| org.into()),
        }
    }
}

impl Repository {
    async fn do_insert(&self, item: Rule, upsert: bool) -> anyhow::Result<()> {
        let item: RuleRow = item.into();
        if upsert {
            sqlx::query_as!(
                Rule,
                "
                INSERT or REPLACE INTO rules (
                    id,
                    hash,
                    action,
                    deny_action,
                    created_at,
                    terminate,
                    comment,
                    source,
                    expires,
                    addr,
                    cidr,
                    user_agent,
                    host,
                    path,
                    country_code,
                    method,
                    asn,
                    org
                ) VALUES (
                    ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?
                )
            ",
                item.id,
                item.hash,
                item.action,
                item.deny_action,
                item.created_at,
                item.terminate,
                item.comment,
                item.source,
                item.expires,
                item.addr,
                item.cidr,
                item.user_agent,
                item.host,
                item.path,
                item.country_code,
                item.method,
                item.asn,
                item.org
            )
        } else {
            sqlx::query_as!(
                Rule,
                "
                INSERT INTO rules (
                    id,
                    hash,
                    action,
                    deny_action,
                    created_at,
                    terminate,
                    comment,
                    source,
                    expires,
                    addr,
                    cidr,
                    user_agent,
                    host,
                    path,
                    country_code,
                    method,
                    asn,
                    org
                ) VALUES (
                    ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?
                )
            ",
                item.id,
                item.hash,
                item.action,
                item.deny_action,
                item.created_at,
                item.terminate,
                item.comment,
                item.source,
                item.expires,
                item.addr,
                item.cidr,
                item.user_agent,
                item.host,
                item.path,
                item.country_code,
                item.method,
                item.asn,
                item.org
            )
        }
        .execute(self.pool.as_ref())
        .await
        .map(|r| ())
        .map_err(|e| anyhow::anyhow!(e))
    }
}

#[async_trait]
impl RepoTrait<Rule> for Repository {
    type Err = anyhow::Error;

    async fn get(&self, id: <Rule as types::PrimaryKey>::Key) -> Result<Option<Rule>, Self::Err> {
        let id = id.to_string();
        let row = sqlx::query_as!(RuleRow, "SELECT * FROM rules WHERE id = ?", id)
            .fetch_one(self.pool.as_ref())
            .await;

        match row {
            Ok(row) => Ok(Some(row.try_into()?)),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(anyhow::anyhow!(e)),
        }
    }

    async fn get_all(&self) -> Result<Vec<Rule>, Self::Err> {
        let rows = sqlx::query_as!(RuleRow, "SELECT * FROM rules")
            .fetch_all(self.pool.as_ref())
            .await?;

        let mut rules = Vec::with_capacity(rows.len());
        for row in rows {
            rules.push(row.try_into()?);
        }
        Ok(rules)
    }

    async fn insert(&self, item: Rule) -> Result<(), Self::Err> {
        self.do_insert(item, false).await
    }

    async fn upsert(&self, item: Rule) -> Result<(), Self::Err> {
        self.do_insert(item, true).await
    }

    async fn update(
        &self,
        id: <Rule as types::PrimaryKey>::Key,
        updates: <Rule as types::Update>::Updates,
    ) -> Result<(), Self::Err> {
        let Some(mut rule) = self.get(id).await? else {
            return Err(anyhow::anyhow!("rule {id} not found"));
        };

        updates.update(&mut rule);

        self.do_insert(rule, true).await
    }

    async fn delete(
        &self,
        id: <Rule as types::PrimaryKey>::Key,
    ) -> Result<Option<Rule>, Self::Err> {
        let old = self.get(id).await?;

        let id = id.to_string();
        sqlx::query!("DELETE FROM rules WHERE id = ?", id)
            .execute(self.pool.as_ref())
            .await?;

        Ok(old)
    }

    async fn truncate(&self) -> Result<(), Self::Err> {
        sqlx::query!("DELETE FROM rules")
            .execute(self.pool.as_ref())
            .await
            .map(|r| ())
            .map_err(|e| anyhow::anyhow!(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Repository as RepoTrait;

    struct Ctx {
        pool: Arc<SqlitePool>,
        repo: Repository,
    }

    impl Ctx {
        async fn init() -> Self {
            let path = std::path::Path::new("./test/doorbell-test.db");
            let pool = Arc::new(crate::database::connect(path).await);
            let repo = Repository::new(pool.clone());

            repo.truncate().await.unwrap();

            Self { pool, repo }
        }
    }

    #[tokio::test]
    async fn test_repo() {
        let ctx = Ctx::init().await;
        let repo = &ctx.repo;

        {
            let rule = Rule {
                hash: String::from("my hash"),
                ..Rule::default()
            };
            repo.insert(rule).await.unwrap();
        }

        assert_eq!(1, repo.get_all().await.unwrap().len());

        let rule = Rule {
            id: uuid::Uuid::new_v4(),
            hash: String::from("my other hash"),
            ..Rule::default()
        };

        repo.insert(rule.clone()).await.unwrap();

        assert_eq!(2, repo.get_all().await.unwrap().len());
        println!("{:#?}", repo.get_all().await);

        let got = repo.get(rule.id).await.unwrap();
        assert_eq!(Some(rule), got);
    }
}
