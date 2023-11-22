#![allow(dead_code, unused)]

mod cli;
mod config;
mod database;
mod geo;
mod rules;
mod types;
mod net;
use database as db;

use actix_web::{get, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use std::sync::Arc;

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

    let Some(xff) = headers.get("x-forwarded-for") else {
        return HttpResponse::new(http::StatusCode::BAD_REQUEST);
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


    let Some(xfp) = headers.get("x-forwarded-proto") else {
        return HttpResponse::new(http::StatusCode::BAD_REQUEST);
    };

    let Some(xfh) = headers.get("x-forwarded-host") else {
        return HttpResponse::new(http::StatusCode::BAD_REQUEST);
    };

    let Some(xfu) = headers.get("x-forwarded-uri") else {
        return HttpResponse::new(http::StatusCode::BAD_REQUEST);
    };

    let Some(xfm) = headers.get("x-forwarded-method") else {
        return HttpResponse::new(http::StatusCode::BAD_REQUEST);
    };

    let user_agent = headers.get("user-agent")
        .map(|h| h.as_bytes())
        .unwrap_or(b"");

    use types::AccessRequest;
    HttpResponse::new(http::StatusCode::OK)
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
