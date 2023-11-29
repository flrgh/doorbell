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
        return HttpResponse::new(http::StatusCode::INTERNAL_SERVER_ERROR);
    };

    let addr = addr.ip();
    if !state.trusted_proxies.is_trusted(&addr) {
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
            (None, _) | (Some(_), Some(_)) => None,
            (Some(value), None) => match value.to_str() {
                Ok(s) => Some(s.to_owned()),
                Err(_) => None,
            },
        }
    }

    let Some(xff) = require_single_header(X_FORWARDED_FOR, headers) else {
        return HttpResponse::new(http::StatusCode::BAD_REQUEST);
    };

    let Some(forwarded_addr) = state.trusted_proxies.get_forwarded_ip(&xff) else {
        return HttpResponse::new(http::StatusCode::BAD_REQUEST);
    };

    let Some(scheme) = require_single_header(X_FORWARDED_PROTO, headers) else {
        return HttpResponse::new(http::StatusCode::BAD_REQUEST);
    };

    let Some(host) = require_single_header(X_FORWARDED_HOST, headers) else {
        return HttpResponse::new(http::StatusCode::BAD_REQUEST);
    };

    let Some(uri) = require_single_header(X_FORWARDED_URI, headers) else {
        return HttpResponse::new(http::StatusCode::BAD_REQUEST);
    };

    let Some(method) = require_single_header(X_FORWARDED_METHOD, headers) else {
        return HttpResponse::new(http::StatusCode::BAD_REQUEST);
    };

    let Ok(method) = method.parse() else {
        return HttpResponse::new(http::StatusCode::BAD_REQUEST);
    };

    let user_agent = match headers.get(USER_AGENT) {
        Some(value) => match value.to_str() {
            Ok(s) => s.to_owned(),
            Err(_) => {
                return HttpResponse::new(http::StatusCode::BAD_REQUEST);
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

    dbg!(&req);

    dbg!(&state.rules);

    let status = {
        match state.rules.read().unwrap().get_match(&req) {
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
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

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
            }))
            .service(index)
            .service(ring)
    })
    .bind(listen)?
    .run()
    .await
}
