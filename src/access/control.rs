use crate::rules::condition::ForwardedRequest;
use actix_web::web::Data;

use super::request::{Repository, Request};

#[derive(Debug)]
pub struct Control {
    repo: Repository,
    notifier: Data<crate::notify::Service>,
    config: Data<crate::config::Config>,
}

impl Control {
    pub fn new(
        repo: Repository,
        notifier: Data<crate::notify::Service>,
        config: Data<crate::config::Config>,
    ) -> Self {
        Self {
            repo,
            notifier,
            config,
        }
    }

    pub async fn get_by_token(&self, token: &str) -> Option<Request> {
        self.repo
            .get_all()
            .await
            .ok()?
            .into_iter()
            .find(|r| r.token == token)
    }

    pub async fn delete_by_token(&self, token: &str) {
        if self.get_by_token(token).await.is_none() {
            log::warn!("access request with token '{}' not found", token);
            return;
        };

        self.repo
            .delete(token)
            .await
            .expect("failed to delete access request");
    }

    pub async fn incoming(&self, forwarded: &ForwardedRequest) {
        if let Ok(Some(current)) = self.repo.get_by_addr(&forwarded.addr).await {
            log::info!(
                "there's already a pending request for this client: {:#?}",
                current
            );
            return;
        }

        let req = {
            let req = Request::from_forwarded(&forwarded);
            match self.repo.insert(&req).await {
                Ok(req) => req,
                Err(e) => {
                    log::error!("{}", e);
                    return;
                }
            }
        };

        dbg!(&req);

        self.notify_incoming(&req).await;
    }

    async fn notify_incoming(&self, req: &Request) {
        let fwd = &req.request;
        let mut body = String::new();
        body.push_str(&format!("IP Address: {}\n", fwd.addr));

        if let Some(ref cc) = fwd.country_code {
            body.push_str(&format!("Country: {}\n", cc));
        }

        if let Some(ref org) = fwd.org {
            body.push_str(&format!("Network: {}\n", org));
        }

        body.push_str(&format!("User-Agent: {}\n", fwd.user_agent));

        body.push_str(&format!(
            "Request: {} {}://{}{}\n",
            fwd.method, fwd.scheme, fwd.host, fwd.uri
        ));

        // pushover puts the action link/url immediately below the rest of the
        // content, so this adds a little extra padding to make it more clickable
        body.push_str("---\n");

        let title = format!("Access requested for {}", fwd.addr);

        let uri = Some(format!(
            "{}/answer.html?t={}",
            &self.config.public_url, req.token
        ));
        let uri_title = Some("Approve/Deny access".to_string());

        let msg = crate::notify::Message {
            title,
            body,
            uri,
            uri_title,
        };

        dbg!(&msg);

        if let Err(e) = self.notifier.send(msg).await {
            log::error!("{}", e);
        }
    }
}
