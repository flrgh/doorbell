mod cli;
mod config;
mod database;
mod geo;
mod net;
mod routes;
mod rules;
mod types;

use actix_web::{error, get, middleware::Logger, web, App, HttpResponse, HttpServer, Responder};
use std::io::{Error as IoError, ErrorKind};
use std::sync::Arc;
use std::sync::RwLock;
use tokio::sync::Mutex;
use types::Repository as RepoTrait;

pub(crate) struct State {
    rules: Arc<RwLock<rules::Collection>>,
    repo: Arc<rules::Repository>,
    config: Arc<config::Conf>,
    manager: Arc<Mutex<rules::Manager>>,
    trusted_proxies: Arc<net::TrustedProxies>,
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::MethodNotAllowed().body("Go away!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let conf = match config::Conf::new() {
        Ok(conf) => {
            dbg!(&conf);
            conf
        }
        Err(e) => {
            log::error!("{}", e);
            return Err(IoError::new(ErrorKind::InvalidInput, e));
        }
    };

    let pool = match database::connect(&conf.db).await {
        Ok(pool) => pool,
        Err(e) => {
            log::error!("{}", e);
            return Err(IoError::new(ErrorKind::InvalidInput, e));
        }
    };

    let conf = Arc::new(conf);
    let listen = conf.listen;
    let pool = Arc::new(pool);
    let repo = Arc::new(rules::Repository::new(pool.clone()));

    if let Err(e) = repo.truncate().await {
        log::error!("{}", e);
        return Err(IoError::new(ErrorKind::InvalidInput, e));
    }

    let collection = Arc::new(RwLock::new(rules::Collection::default()));

    let mut manager = rules::Manager::new(conf.clone(), repo.clone(), collection.clone());
    if let Err(e) = manager.init().await {
        log::error!("{}", e);
        return Err(IoError::new(ErrorKind::InvalidInput, e));
    }

    let manager = Arc::new(Mutex::new(manager));
    let trusted_proxies = Arc::new(net::TrustedProxies::new(&conf.trusted_proxies));

    {
        let manager = manager.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = manager.lock().await.update_matcher().await {
                    log::error!("error {}", e);
                } else {
                    log::info!("rebuilt matcher");
                }

                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        });
    }

    HttpServer::new(move || {
        let json_config = web::JsonConfig::default()
            .limit(4096)
            .error_handler(|err, _req| {
                // create custom error response
                let json = serde_json::json!({
                    "error": err.to_string(),
                });
                error::InternalError::from_response(err, HttpResponse::BadRequest().json(json))
                    .into()
            });

        App::new()
            .wrap(Logger::default())
            .app_data(json_config)
            .app_data(web::Data::new(State {
                rules: collection.clone(),
                config: conf.clone(),
                manager: manager.clone(),
                trusted_proxies: trusted_proxies.clone(),
                repo: repo.clone(),
            }))
            .service(index)
            .service(routes::ring::handler)
            .service(routes::rules::list)
            .service(routes::rules::create)
    })
    .bind(listen)
    .map_err(|e| IoError::new(ErrorKind::InvalidInput, e))?
    .run()
    .await
}
