#![allow(dead_code, unused)]

mod cli;
mod config;
mod database;
mod geo;
mod net;
mod rules;
mod types;
use database as db;

use actix_web::{get, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use std::sync::Arc;
use types::Repository;

struct State<'a> {
    matcher: rules::Matcher<'a>,
    config: Arc<config::Conf>,
    manager: Arc<rules::Manager>,
    trusted_proxies: Arc<net::TrustedProxies>,
}

#[get("/")]
async fn index(req: HttpRequest) -> impl Responder {
    println!("REQ: {:?}", req);
    "Hello world!"
}

#[get("/ring")]
async fn ring(req: HttpRequest, state: web::Data<State<'_>>) -> impl Responder {
    let Some(addr) = req.peer_addr() else {
        return HttpResponse::new(http::StatusCode::INTERNAL_SERVER_ERROR);
    };

    let addr = addr.ip();
    if !state.trusted_proxies.is_trusted(&addr) {
        return HttpResponse::new(http::StatusCode::FORBIDDEN);
    }

    let headers = req.headers();

    let xff = {
        let mut iter = headers.get_all("x-forwarded-for");
        match (iter.next(), iter.next()) {
            (None, _) | (Some(_), Some(_)) => {
                return HttpResponse::new(http::StatusCode::BAD_REQUEST);
            }
            (Some(value), None) => value,
        }
    };

    let forwarded_addr = {
        let Ok(xff) = xff.to_str() else {
            return HttpResponse::new(http::StatusCode::BAD_REQUEST);
        };

        let Some(forwarded) = state.trusted_proxies.get_forwarded_ip(xff) else {
            return HttpResponse::new(http::StatusCode::BAD_REQUEST);
        };

        forwarded
    };

    let scheme = {
        let mut iter = headers.get_all("x-forwarded-proto");
        match (iter.next(), iter.next()) {
            (None, _) | (Some(_), Some(_)) => {
                return HttpResponse::new(http::StatusCode::BAD_REQUEST);
            }
            (Some(value), None) => match value.to_str() {
                Ok(s) => s.to_owned(),
                Err(_) => {
                    return HttpResponse::new(http::StatusCode::BAD_REQUEST);
                }
            },
        }
    };

    let host = {
        let mut iter = headers.get_all("x-forwarded-host");
        match (iter.next(), iter.next()) {
            (None, _) | (Some(_), Some(_)) => {
                return HttpResponse::new(http::StatusCode::BAD_REQUEST);
            }
            (Some(value), None) => match value.to_str() {
                Ok(s) => s.to_owned(),
                Err(_) => {
                    return HttpResponse::new(http::StatusCode::BAD_REQUEST);
                }
            },
        }
    };

    let uri = {
        let mut iter = headers.get_all("x-forwarded-uri");
        match (iter.next(), iter.next()) {
            (None, _) | (Some(_), Some(_)) => {
                return HttpResponse::new(http::StatusCode::BAD_REQUEST);
            }
            (Some(value), None) => match value.to_str() {
                Ok(s) => s.to_owned(),
                Err(_) => {
                    return HttpResponse::new(http::StatusCode::BAD_REQUEST);
                }
            },
        }
    };

    let method = {
        let mut iter = headers.get_all("x-forwarded-method");
        match (iter.next(), iter.next()) {
            (None, _) | (Some(_), Some(_)) => {
                return HttpResponse::new(http::StatusCode::BAD_REQUEST);
            }
            (Some(value), None) => match value.to_str() {
                Ok(s) => s.to_owned(),
                Err(_) => {
                    return HttpResponse::new(http::StatusCode::BAD_REQUEST);
                }
            },
        }
    };

    let Ok(method) = method.parse() else {
        return HttpResponse::new(http::StatusCode::BAD_REQUEST);
    };

    let user_agent = match headers.get("user-agent") {
        Some(value) => match value.to_str() {
            Ok(s) => s.to_owned(),
            Err(_) => {
                return HttpResponse::new(http::StatusCode::BAD_REQUEST);
            }
        },
        None => String::from(""),
    };

    let path = uri
        .split_once('?')
        .unwrap_or((uri.as_ref(), ""))
        .0
        .to_owned();

    let ar = types::AccessRequest {
        addr: forwarded_addr,
        user_agent,
        host,
        method,
        uri,
        path,
        country_code: None,
        asn: None,
        org: None,
        timestamp: chrono::Utc::now(),
    };

    dbg!(&ar);

    let status = {
        match state.matcher.get_match(&ar) {
            Some(rule) => {
                use crate::rules::{Action, DenyAction};
                match rule.action {
                    Action::Allow => http::StatusCode::OK,
                    Action::Deny => {
                        if let Some(DenyAction::Tarpit) = rule.deny_action {
                            tokio::time::sleep(std::time::Duration::from_secs(30));
                        }

                        http::StatusCode::FORBIDDEN
                    }
                }
            }
            None => http::StatusCode::UNAUTHORIZED,
        }
    };

    HttpResponse::new(status)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let conf = config::Conf::new().unwrap();
    dbg!(&conf);
    let pool = db::connect(&conf.db).await;

    let conf = Arc::new(conf);
    let listen = conf.listen;
    let pool = Arc::new(pool);
    let repo = Arc::new(crate::rules::repo::Repository::new(pool.clone()));
    repo.truncate().await.unwrap();

    let manager = rules::Manager::new(conf.clone(), repo.clone());
    manager.init().await.expect("failed to initialize things");
    let manager = Arc::new(manager);
    let trusted_proxies = Arc::new(net::TrustedProxies::new(&conf.trusted_proxies));

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(State {
                matcher: Default::default(),
                config: conf.clone(),
                manager: manager.clone(),
                trusted_proxies: trusted_proxies.clone(),
            }))
            .service(index)
            .service(ring)
    })
    .bind(listen)?
    .run()
    .await
}
