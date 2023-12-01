mod app;
mod cli;
mod config;
mod database;
mod geo;
mod net;
mod routes;
mod rules;
mod types;

use actix_web::{error, middleware::Logger, web, App, HttpResponse, HttpServer};
use std::io::{Error as IoError, ErrorKind};
use std::sync::Arc;
use std::sync::RwLock;
use tokio::sync::Mutex;
use types::Repository as RepoTrait;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let conf = match config::Conf::new() {
        Ok(conf) => {
            dbg!(&conf);
            Arc::new(conf)
        }
        Err(e) => {
            log::error!("{}", e);
            return Err(IoError::new(ErrorKind::Other, e));
        }
    };

    let listen = conf.listen;

    let geoip = match geo::GeoIp::try_from_config(&conf) {
        Ok(geoip) => Arc::new(geoip),
        Err(e) => {
            log::error!("{}", e);
            return Err(IoError::new(ErrorKind::Other, e));
        }
    };

    let pool = match database::connect(&conf.db).await {
        Ok(pool) => Arc::new(pool),
        Err(e) => {
            log::error!("{}", e);
            return Err(IoError::new(ErrorKind::Other, e));
        }
    };

    let repo = Arc::new(rules::Repository::new(pool.clone()));

    if let Err(e) = repo.truncate().await {
        log::error!("{}", e);
        return Err(IoError::new(ErrorKind::Other, e));
    }

    let trusted_proxies = Arc::new(net::TrustedProxies::new(&conf.trusted_proxies));
    let collection = Arc::new(RwLock::new(rules::Collection::default()));

    let manager = {
        let mut manager = rules::Manager::new(conf.clone(), repo.clone(), collection.clone());

        if let Err(e) = manager.init().await {
            log::error!("{}", e);
            return Err(IoError::new(ErrorKind::Other, e));
        }

        Arc::new(Mutex::new(manager))
    };

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
            .app_data(web::Data::new(app::State {
                rules: collection.clone(),
                config: conf.clone(),
                manager: manager.clone(),
                trusted_proxies: trusted_proxies.clone(),
                repo: repo.clone(),
                geoip: geoip.clone(),
            }))
            .service(routes::root::handler)
            .service(routes::ring::handler)
            .service(routes::rules::list)
            .service(routes::rules::create)
    })
    .bind(listen)
    .map_err(|e| IoError::new(ErrorKind::Other, e))?
    .run()
    .await
}
