pub mod pushover;

use async_trait::async_trait;
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Default)]
pub enum Notifier {
    #[default]
    Disabled,
    Pushover(pushover::Pushover),
}

#[derive(Debug)]
pub struct Config {
    strategy: Notifier,
}

#[derive(Debug, Clone, Serialize)]
pub struct Access {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub title: String,
    pub body: String,
    pub uri: Option<String>,
    pub uri_title: Option<String>,
}

#[async_trait]
trait Notify {
    type Err;

    async fn send(&self, msg: Message) -> Result<(), Self::Err>;
}
