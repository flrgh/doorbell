use crate::config::Conf;
use crate::rules::repo::Repository;
use crate::rules::{Collection, Source};
use crate::types::Repository as RepoTrait;
use actix_web::web;
use tokio::sync::RwLock;

pub struct Manager {
    repo: web::Data<Repository>,
    config: web::Data<Conf>,
    collection: web::Data<RwLock<Collection>>,
}

impl Manager {
    pub fn new(
        config: web::Data<Conf>,
        repo: web::Data<Repository>,
        collection: web::Data<RwLock<Collection>>,
    ) -> Self {
        Self {
            repo,
            config,
            collection,
        }
    }

    pub async fn init(&mut self) -> anyhow::Result<()> {
        self.repo.delete_where("source", Source::Config).await?;

        for rule in self.config.rules() {
            self.repo.insert(rule).await?;
        }

        self.update_matcher().await?;

        Ok(())
    }

    pub async fn update_matcher(&self) -> anyhow::Result<()> {
        let rules = self.repo.get_all().await?;

        let version = { self.collection.read().await.version() };
        log::debug!("Got version: {}", version);

        let new_collection = Collection::new(rules, version + 1);
        log::debug!("Built new collection: {:?}", new_collection);

        {
            let mut collection = self.collection.write().await;
            *collection = new_collection;
        }

        log::debug!("Updated collection");

        Ok(())
    }
}
