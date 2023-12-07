use crate::rules::*;
use crate::types;
use crate::types::Repository as RepoTrait;
use actix_web::web::Data;
use anyhow;
use async_trait::async_trait;
use sqlx::SqlitePool;
use sqlx_sqlite::Sqlite;

pub struct Repository {
    pool: Data<SqlitePool>,
}

impl Repository {
    pub fn new(pool: Data<SqlitePool>) -> Self {
        Self { pool }
    }
}

impl Repository {
    async fn do_insert(&self, item: Rule, upsert: bool) -> anyhow::Result<()> {
        let query = format!(
            "
            {action} INTO rules (
                id,
                hash,
                action,
                created_at,
                updated_at,
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
            action = if upsert {
                "INSERT or REPLACE"
            } else {
                "INSERT"
            }
        );

        let Rule {
            id,
            action,
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

        sqlx::query_as::<Sqlite, Rule>(&query)
            .bind(id.to_string())
            .bind(hash)
            .bind(action)
            .bind(created_at)
            .bind(updated_at)
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
    ) -> Result<Option<Rule>, Self::Err> {
        let Some(mut rule) = self.get(id).await? else {
            return Ok(None);
        };

        updates.update(&mut rule)?;

        self.do_insert(rule.clone(), true).await?;
        Ok(Some(rule))
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
