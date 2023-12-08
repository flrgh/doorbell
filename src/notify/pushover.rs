use super::{Message, Notify};
use async_trait::async_trait;
use reqwest;
use serde_derive::{Deserialize, Serialize};
use serde_repr::*;
use std::env;
use tokio::sync::Mutex;

const URI: &str = "https://api.pushover.net/1/messages.json";
const USER_AGENT: &str = "Doorbell Forward Auth Server";
const RATE: std::time::Duration = std::time::Duration::from_millis(500);

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

#[derive(Debug)]
pub struct Pushover {
    token: String,
    user_key: String,
    priority: Priority,
    last_sent: Mutex<std::time::Instant>,
}

impl Pushover {
    fn try_from_env() -> Result<Self, anyhow::Error> {
        Ok(Pushover {
            token: env::var("PUSHOVER_TOKEN")?,
            user_key: env::var("PUSHOVER_USER_KEY")?,
            priority: match env::var("PUSHOVER_PRIORITY") {
                Ok(v) => v.parse().unwrap_or_default(),
                Err(_) => Default::default(),
            },
            last_sent: Mutex::new(std::time::Instant::now() - RATE),
        })
    }

    async fn delay_for_rate_limit(&self) {
        let mut last_sent = self.last_sent.lock().await;
        if last_sent.elapsed() < RATE {
            let delay = RATE - last_sent.elapsed();
            log::trace!(
                "sleeping for {}ms until next Pushover request",
                delay.as_millis()
            );
            tokio::time::sleep(delay).await;
        }

        *last_sent = std::time::Instant::now();
    }
}

#[async_trait]
impl Notify for Pushover {
    type Err = anyhow::Error;

    async fn send(&self, msg: Message) -> Result<(), Self::Err> {
        self.delay_for_rate_limit().await;

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
