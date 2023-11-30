use crate::config::Conf;
use crate::rules::repo::Repository;
use crate::rules::{Collection, Rule, Source};
use crate::types::Repository as RepoTrait;
use std::sync::{Arc, RwLock};

pub struct Manager {
    repo: Arc<Repository>,
    config: Arc<Conf>,
    collection: Arc<RwLock<Collection>>,
}

impl Manager {
    pub fn new(
        config: Arc<Conf>,
        repo: Arc<Repository>,
        collection: Arc<RwLock<Collection>>,
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

    pub async fn update_matcher(&mut self) -> anyhow::Result<()> {
        let rules = self.repo.get_all().await?;

        let version = self
            .collection
            .read()
            .map_err(|e| anyhow::anyhow!(e.to_string()))?
            .version();

        let new_collection = Collection::new(rules, version);

        {
            let mut collection = self
                .collection
                .write()
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;

            *collection = new_collection;
        }

        Ok(())
    }
}
