use crate::config::Config;
use crate::rules::repo::Repository;
use crate::rules::{Collection, Source};
use crate::types::Repository as RepoTrait;
use actix_web::web;
use tokio::sync::{Mutex, RwLock};

pub struct Manager {
    repo: web::Data<Repository>,
    config: web::Data<Config>,
    collection: web::Data<RwLock<Collection>>,
    version: tokio::sync::Mutex<u64>,
}

impl Manager {
    pub fn new(
        config: web::Data<Config>,
        repo: web::Data<Repository>,
        collection: web::Data<RwLock<Collection>>,
    ) -> Self {
        let version = Mutex::new(0);
        Self {
            repo,
            config,
            collection,
            version,
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
        let mut my_version = self.version.lock().await;

        let rules = self.repo.get_all().await?;

        let version = { self.collection.read().await.version() };
        anyhow::ensure!(*my_version == version);

        let new_version = version + 1;
        let new_collection = Collection::new(rules, new_version);
        log::debug!("Built new collection: {:?}", new_collection);

        {
            let mut collection = self.collection.write().await;
            if collection.version() != version {
                return Err(anyhow::anyhow!(
                        "The global collection was modified while building a new one (expected: {}, actual: {})",
                        version,
                        collection.version()));
            }

            *collection = new_collection;
        }

        log::debug!("Updated collection");

        *my_version = new_version;

        Ok(())
    }
}
