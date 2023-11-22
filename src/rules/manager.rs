use crate::config::Conf;
use crate::rules::repo::Repository;
use crate::rules::{Rule, Source};
use crate::types::Repository as RepoTrait;
use std::sync::Arc;

pub struct Manager {
    repo: Arc<Repository>,
    config: Arc<Conf>,
}

impl Manager {
    pub fn new(config: Arc<Conf>, repo: Arc<Repository>) -> Self {
        Self { repo, config }
    }

    pub async fn init(&self) -> anyhow::Result<()> {
        self.repo.delete_where("source", Source::Config).await?;

        for rule in self.config.rules() {
            self.repo.insert(rule).await?;
        }

        Ok(())
    }
}
