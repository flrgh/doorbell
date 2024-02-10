use super::{Message, Notify};
use async_trait::async_trait;
use reqwest;
use serde_derive::{Deserialize, Serialize};
use serde_repr::*;
use std::env;
use tokio::sync::Mutex;
use tokio::time::*;

const URI: &str = "https://api.pushover.net/1/messages.json";
const USER_AGENT: &str = "Doorbell Forward Auth Server";
const RATE: Duration = Duration::from_millis(500);
const ENV_TOKEN: &str = "PUSHOVER_TOKEN";
const ENV_USER_KEY: &str = "PUSHOVER_USER_KEY";
const ENV_PRIORITY: &str = "PUSHOVER_PRIORITY";

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

#[derive(Debug, Deserialize_repr, Serialize_repr, Clone, Default, strum_macros::EnumString)]
#[repr(i8)]
pub enum Priority {
    Lowest = -2,
    Low = -1,
    #[default]
    Normal = 0,
    High = 1,
    Emergency = 2,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Config {
    token: Option<String>,
    user_key: Option<String>,
}

#[derive(Debug)]
pub struct Pushover {
    token: String,
    user_key: String,
    priority: Priority,
    rate: Mutex<Interval>,
}

fn get_env(name: &str) -> Option<String> {
    env::var(name).ok()
}

impl Pushover {
    pub fn try_from_config(config: &Config) -> anyhow::Result<Self> {
        let token = get_env(ENV_TOKEN)
            .or(config.token.clone())
            .ok_or(anyhow::anyhow!("Missing Pushover API token"))?;

        let user_key = get_env(ENV_USER_KEY)
            .or(config.token.clone())
            .ok_or(anyhow::anyhow!("Missing Pushover API user key"))?;

        let priority = get_env(ENV_PRIORITY)
            .and_then(|var| var.parse().ok())
            .unwrap_or_default();

        let rate = Mutex::new(interval(RATE));

        Ok(Self {
            token,
            user_key,
            priority,
            rate,
        })
    }

    fn try_from_env() -> Result<Self, anyhow::Error> {
        Ok(Pushover {
            token: env::var("PUSHOVER_TOKEN")?,
            user_key: env::var("PUSHOVER_USER_KEY")?,
            priority: match env::var("PUSHOVER_PRIORITY") {
                Ok(v) => v.parse().unwrap_or_default(),
                Err(_) => Default::default(),
            },
            rate: Mutex::new(interval(RATE)),
        })
    }
}

#[async_trait]
impl Notify for Pushover {
    async fn send(&self, msg: Message) -> Result<(), anyhow::Error> {
        // rate-limit ourselves and also require an exclusive lock
        // for sending
        let mut rate = self.rate.lock().await;
        rate.tick().await;

        let req = Request {
            token: self.token.clone(),
            user: self.user_key.clone(),
            url: msg.uri.clone(),
            url_title: msg.uri_title.clone(),
            priority: self.priority.clone(),
            message: msg.body.clone(),
            title: msg.title.clone(),
            monospace: true,
        };

        let client = reqwest::Client::new();
        let res = client
            .post(URI)
            .json(&req)
            .header("User-Agent", USER_AGENT)
            .header("Content-Type", "application/json")
            .send()
            .await?;

        dbg!(&res);

        let status = res.status();

        let json: serde_json::Value = res.json().await?;

        if !status.is_success() {
            log::error!(
                "pushover returned non-OK status: {}\nbody:\n{}",
                status,
                json
            );
            return Err(anyhow::anyhow!("oops"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pushover_notify() {
        let po = Pushover::try_from_env().unwrap();
        dbg!(&po);

        let res = po
            .send(Message {
                title: "test".to_string(),
                body: "test body".to_string(),
                uri: None,
                uri_title: None,
            })
            .await;

        dbg!(&res);
        res.unwrap();
    }
}
