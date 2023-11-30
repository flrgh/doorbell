#![allow(dead_code, unused)]

mod cli;
mod config;
mod database;
mod geo;
mod net;
mod rules;
mod types;
use database as db;

use actix_web::{
    get, middleware::Logger, web, App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use std::sync::Arc;
use std::sync::RwLock;
use types::Repository;

struct State {
    rules: Arc<RwLock<rules::Collection>>,
    repo: Arc<rules::repo::Repository>,
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
async fn ring(req: HttpRequest, state: web::Data<State>) -> impl Responder {
    let Some(addr) = req.peer_addr() else {
        log::error!("failed to get peer IP address");
        return HttpResponse::new(http::StatusCode::INTERNAL_SERVER_ERROR);
    };

    let addr = addr.ip();
    if !state.trusted_proxies.is_trusted(&addr) {
        log::info!("got a request from an untrusted proxy IP: {}", addr);
        return HttpResponse::new(http::StatusCode::FORBIDDEN);
    }

    let headers = req.headers();

    use crate::types::{
        USER_AGENT, X_FORWARDED_FOR, X_FORWARDED_HOST, X_FORWARDED_METHOD, X_FORWARDED_PROTO,
        X_FORWARDED_URI,
    };
    use actix_web::http::header::{HeaderMap, HeaderValue};

    fn require_single_header(name: &str, headers: &HeaderMap) -> Option<String> {
        let mut iter = headers.get_all(name);
        match (iter.next(), iter.next()) {
            (None, _) => {
                log::debug!("peer did not send a {} header", name);
                None
            }
            (Some(_), Some(_)) => {
                log::debug!("peer sent more than one {} header", name);
                None
            }
            (Some(value), None) => match value.to_str() {
                Ok(s) => Some(s.to_owned()),
                Err(e) => {
                    log::debug!("peer sent invalid {} header: {}", name, e);
                    None
                }
            },
        }
    }

    let Some(xff) = require_single_header(X_FORWARDED_FOR, headers) else {
        return HttpResponse::BadRequest().finish();
    };

    let Some(forwarded_addr) = state.trusted_proxies.get_forwarded_ip(&xff) else {
        return HttpResponse::BadRequest().finish();
    };

    let Some(scheme) = require_single_header(X_FORWARDED_PROTO, headers) else {
        return HttpResponse::BadRequest().finish();
    };

    let Some(host) = require_single_header(X_FORWARDED_HOST, headers) else {
        return HttpResponse::BadRequest().finish();
    };

    let Some(uri) = require_single_header(X_FORWARDED_URI, headers) else {
        return HttpResponse::BadRequest().finish();
    };

    let Some(method) = require_single_header(X_FORWARDED_METHOD, headers) else {
        return HttpResponse::BadRequest().finish();
    };

    let Ok(method) = method.parse() else {
        return HttpResponse::BadRequest().finish();
    };

    let user_agent = match headers.get(USER_AGENT) {
        Some(value) => match value.to_str() {
            Ok(s) => s.to_owned(),
            Err(e) => {
                log::debug!("peer sent invalid {} header", USER_AGENT);
                return HttpResponse::BadRequest().finish();
            }
        },
        None => String::from(""),
    };

    fn get_path(uri: &str) -> String {
        uri.split_once('?').get_or_insert((uri, "")).0.to_owned()
    }

    let path = get_path(&uri);

    let req = types::ForwardedRequest {
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

    let status = {
        let matched = match state.rules.read() {
            Ok(rules) => rules.get_match(&req).cloned(),
            Err(e) => {
                log::error!("{}", e);
                return HttpResponse::InternalServerError().finish();
            }
        };

        if let Some(rule) = matched {
            use crate::rules::{Action, DenyAction};
            log::trace!("request {:?} matched rule {:?}", req, rule);

            match rule.action {
                Action::Allow => {
                    log::debug!("/ring => ALLOW");
                    http::StatusCode::OK
                }
                Action::Deny => {
                    log::debug!("/ring => DENY");
                    if let Some(DenyAction::Tarpit) = rule.deny_action {
                        log::debug!("Tarpitting request");
                        tokio::time::sleep(std::time::Duration::from_secs(30));
                    }

                    http::StatusCode::FORBIDDEN
                }
            }
        } else {
            log::trace!("request {:?} did not match any rule", req);
            log::debug!("/ring => UNKNOWN");
            http::StatusCode::UNAUTHORIZED
        }
    };

    HttpResponse::new(status)
}

#[get("/rules")]
async fn list_rules(_: HttpRequest, state: web::Data<State>) -> impl Responder {
    let rules = match state.repo.get_all().await {
        Ok(rules) => rules,
        Err(e) => {
            dbg!(e);
            return HttpResponse::new(http::StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let json = serde_json::json!({
        "data": rules,
    });

    HttpResponse::Ok().json(json)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let conf = config::Conf::new().unwrap();
    dbg!(&conf);
    let pool = db::connect(&conf.db).await;

    let conf = Arc::new(conf);
    let listen = conf.listen;
    let pool = Arc::new(pool);
    let repo = Arc::new(crate::rules::repo::Repository::new(pool.clone()));
    repo.truncate().await.unwrap();

    let collection = Arc::new(RwLock::new(crate::rules::Collection::default()));

    let mut manager = rules::Manager::new(conf.clone(), repo.clone(), collection.clone());
    manager.init().await.expect("failed to initialize things");
    let manager = Arc::new(manager);
    let trusted_proxies = Arc::new(net::TrustedProxies::new(&conf.trusted_proxies));

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(web::Data::new(State {
                rules: collection.clone(),
                config: conf.clone(),
                manager: manager.clone(),
                trusted_proxies: trusted_proxies.clone(),
                repo: repo.clone(),
            }))
            .service(index)
            .service(ring)
            .service(list_rules)
    })
    .bind(listen)?
    .run()
    .await
}
