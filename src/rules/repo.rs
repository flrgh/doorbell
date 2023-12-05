use crate::rules::*;
use crate::types;
use crate::types::Repository as RepoTrait;
use anyhow;
use async_trait::async_trait;
use chrono::NaiveDateTime;
use sqlx::SqlitePool;
use sqlx_sqlite::Sqlite;
use std::sync::Arc;

pub struct Repository {
    pool: Arc<SqlitePool>,
}

impl Repository {
    pub fn new(pool: Arc<SqlitePool>) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Eq, PartialEq, sqlx::Type, sqlx::FromRow)]
struct RuleRow {
    id: String,
    action: String,
    deny_action: Option<String>,
    hash: String,
    created_at: NaiveDateTime,
    updated_at: Option<NaiveDateTime>,
    terminate: Option<bool>,
    comment: Option<String>,
    source: String,
    expires: Option<NaiveDateTime>,

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
        fn parse<T>(v: Option<String>) -> Result<Option<T>, <T as std::str::FromStr>::Err>
        where
            T: std::str::FromStr,
        {
            match v {
                None => Ok(None),
                Some(s) => Ok(Some(s.parse()?)),
            }
        }

        let rule = Rule {
            id: self.id.parse()?,
            action: self.action.parse()?,
            deny_action: parse(self.deny_action)?,
            hash: self.hash,
            created_at: self.created_at.and_utc(),
            updated_at: self.updated_at.map(|t| t.and_utc()),
            terminate: self.terminate.unwrap_or(false),
            comment: self.comment,
            source: self.source.parse()?,
            expires: self.expires.map(|expires| expires.and_utc()),
            addr: parse(self.addr)?,
            cidr: parse(self.cidr)?,
            user_agent: parse(self.user_agent)?,
            host: parse(self.host)?,
            path: parse(self.path)?,
            country_code: parse(self.country_code)?,
            method: parse(self.method)?,
            asn: parse(self.asn)?,
            org: parse(self.org)?,
        };

        anyhow::ensure!(
            rule.hash == Rule::calculate_hash(&rule),
            "rule's database hash doesn't match the calculated one"
        );

        Ok(rule)
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
        let Rule {
            id,
            action,
            deny_action,
            terminate,
            hash,
            created_at,
            updated_at,
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
            org,
        } = item;

        sqlx::query_as::<Sqlite, Rule>(if upsert {
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
                "
        } else {
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
                "
        })
        .bind(id.to_string())
        .bind(hash)
        .bind(action)
        .bind(deny_action)
        .bind(created_at)
        .bind(terminate)
        .bind(comment)
        .bind(source)
        .bind(expires)
        .bind(addr.as_ref())
        .bind(cidr.as_ref())
        .bind(user_agent.map(String::from))
        .bind(host.map(String::from))
        .bind(path.map(String::from))
        .bind(country_code)
        .bind(method)
        .bind(asn)
        .bind(org.map(String::from))
        .fetch_all(self.pool.as_ref())
        .await
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!(e))
    }
}

#[async_trait]
impl RepoTrait<Rule> for Repository {
    type Err = anyhow::Error;

    async fn get(&self, id: <Rule as types::PrimaryKey>::Key) -> Result<Option<Rule>, Self::Err> {
        let id = id.to_string();
        let rule = sqlx::query_as::<_, Rule>("SELECT * FROM rules WHERE id = ?")
            .bind(id)
            .fetch_one(self.pool.as_ref())
            .await;

        match rule {
            Ok(row) => Ok(Some(row)),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(anyhow::anyhow!(e)),
        }
    }

    async fn get_all(&self) -> Result<Vec<Rule>, Self::Err> {
        Ok(sqlx::query_as::<_, Rule>("SELECT * FROM rules")
            .fetch_all(self.pool.as_ref())
            .await?)
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
        sqlx::query("DELETE FROM rules WHERE id = ?")
            .bind(id)
            .execute(self.pool.as_ref())
            .await?;

        Ok(old)
    }

    async fn truncate(&self) -> Result<(), Self::Err> {
        sqlx::query("DELETE FROM rules")
            .execute(self.pool.as_ref())
            .await
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!(e))
    }
}

impl Repository {
    pub async fn delete_where<T>(&self, column: &str, value: T) -> anyhow::Result<()>
    where
        T: Send,
        T: sqlx::Type<sqlx::Sqlite>,
        T: for<'a> sqlx::Encode<'a, sqlx::Sqlite>,
    {
        sqlx::query("DELETE FROM rules WHERE ? = ?")
            .bind(column)
            .bind(value)
            .execute(self.pool.as_ref())
            .await
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Pattern;
    use crate::types::Repository as RepoTrait;

    struct Ctx {
        pool: Arc<SqlitePool>,
        repo: Repository,
    }

    impl Ctx {
        async fn init() -> Self {
            let path = std::path::Path::new("./test/doorbell-test.db");
            let pool = Arc::new(crate::database::connect(path).await.unwrap());
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
            let mut rule = Rule {
                id: Uuid::new(),
                user_agent: Some(Pattern::try_from("test").unwrap()),
                ..Rule::default()
            };
            rule.hash = Rule::calculate_hash(&rule);
            repo.insert(rule).await.unwrap();
        }

        assert_eq!(1, repo.get_all().await.unwrap().len());

        let mut rule = Rule {
            id: Uuid::new(),
            user_agent: Some(Pattern::try_from("test other").unwrap()),
            ..Rule::default()
        };
        rule.hash = Rule::calculate_hash(&rule);

        repo.insert(rule.clone()).await.unwrap();

        assert_eq!(2, repo.get_all().await.unwrap().len());
        println!("{:#?}", repo.get_all().await);

        let got = repo.get(rule.id).await.unwrap();
        assert_eq!(Some(rule), got);
    }
}
