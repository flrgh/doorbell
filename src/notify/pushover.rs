use super::{Message, Notify};
use async_trait::async_trait;
use reqwest;
use serde_derive::{Deserialize, Serialize};

const URI: &str = "https://api.pushover.net/1/messages.json";
const USER_AGENT: &str = "Doorbell Forward Auth Server";

#[derive(Debug, Serialize, Clone)]
struct Request {
    token: String,
    user: String,
    message: String,
    title: String,
    url: Option<String>,
    url_title: Option<String>,
    priority: Priority,
    monospace: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub enum Priority {
    Lowest = -2,
    Low = -1,
    #[default]
    Normal = 0,
    High = 1,
    Emergency = 2,
}

#[derive(Debug, Clone)]
struct Pushover {
    config: Config,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    token: String,
    user_key: String,
    priority: Priority,
}

#[async_trait]
impl Notify for Pushover {
    type Err = anyhow::Error;

    async fn send(&self, msg: Message) -> Result<(), Self::Err> {
        let body = Request {
            token: self.config.token.clone(),
            user: self.config.user_key.clone(),
            url: msg.uri.clone(),
            url_title: msg.uri_title.clone(),
            priority: self.config.priority.clone(),
            message: msg.body.clone(),
            title: msg.title.clone(),
            monospace: true,
        };

        let body = serde_json::to_vec(&body)?;

        let client = reqwest::Client::new();
        let res = client
            .post(URI)
            .body(reqwest::Body::from(body))
            .header("User-Agent", USER_AGENT)
            .header("Content-Type", "application/json")
            .send()
            .await?;

        let res = res.error_for_status()?;

        let bytes = res.bytes().await?;

        let json = serde_json::from_slice(&bytes[..])?;

        dbg!(json);

        Ok(())
    }
}
