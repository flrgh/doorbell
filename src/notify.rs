pub mod pushover;
use pushover::Pushover;

use async_trait::async_trait;
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(tag = "strategy", content = "config")]
pub enum Config {
    #[default]
    Disabled,
    Pushover {
        config: pushover::Config,
    },
}

//#[derive(Debug, Default, Clone, Deserialize, Serialize)]
//pub struct Config {
//    strategy: Strategy,
//    //quiet_hours: Vec<Period>,
//}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub title: String,
    pub body: String,
    pub uri: Option<String>,
    pub uri_title: Option<String>,
}

#[derive(Debug)]
pub struct Disabled;

#[async_trait]
impl Notify for Disabled {
    async fn send(&self, msg: Message) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

#[async_trait]
trait Notify {
    async fn send(&self, msg: Message) -> Result<(), anyhow::Error>;
}

pub struct Service {
    strategy: Box<dyn Notify + Send + Sync>,
}

impl Service {
    pub fn try_from_config(config: &crate::config::Config) -> anyhow::Result<Self> {
        let strategy: Box<dyn Notify + Send + Sync> = match &config.notify {
            Config::Disabled => Box::new(Disabled),
            Config::Pushover { config } => Box::new(Pushover::try_from_config(&config)?),
        };
        Ok(Self { strategy })
    }

    pub async fn send(&self, msg: Message) -> Result<(), anyhow::Error> {
        self.strategy.send(msg).await
    }
}
