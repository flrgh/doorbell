use crate::rules::Rule;
use crate::types;
use anyhow;
use async_trait::async_trait;
use sqlx::{prelude::*, Acquire, Connection, SqliteConnection, SqlitePool};

pub struct Repository<'a> {
    pool: &'a SqlitePool,
}

impl<'a> Repository<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl<'a> types::Repository<Rule> for Repository<'a> {
    type Err = anyhow::Error;

    async fn get(
        &self,
        id: <Rule as crate::types::PrimaryKey>::Key,
    ) -> Result<Option<Rule>, Self::Err> {
        let rows = sqlx::query("SELECT * FROM rules WHERE id = ?")
            .bind(id)
            .fetch_all(self.pool)
            .await?;

        Ok(match rows.get(0) {
            Some(row) => Some(Rule::try_from_row(row)?),
            None => None,
        })
    }

    async fn get_all(&self) -> Result<Vec<Rule>, Self::Err> {
        let rows = sqlx::query("SELECT * FROM rules")
            .fetch_all(self.pool)
            .await?;

        let mut rules = Vec::with_capacity(rows.len());
        for row in rows {
            rules.push(Rule::try_from_row(&row)?);
        }
        Ok(rules)
    }

    async fn insert(&self, item: &Rule) -> Result<(), Self::Err> {
        todo!()
    }

    async fn upsert(&self, item: &Rule) -> Result<(), Self::Err> {
        todo!()
    }

    async fn update(
        &self,
        id: <Rule as crate::types::PrimaryKey>::Key,
        item: &Rule,
    ) -> Result<(), Self::Err> {
        todo!()
    }

    async fn delete(
        &self,
        id: <Rule as crate::types::PrimaryKey>::Key,
    ) -> Result<Option<Rule>, Self::Err> {
        todo!()
    }
}
