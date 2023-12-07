use actix_web::{
    error, middleware::DefaultHeaders, middleware::Logger, web, App, HttpResponse, HttpServer,
};
use std::io::{Error as IoError, ErrorKind};
use tokio::sync::RwLock;

use crate::config;
use crate::database;
use crate::geo;
use crate::net;
use crate::routes;
use crate::rules;
use crate::types::Repository as RepoTrait;

pub(super) async fn run() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let conf = match config::Conf::new() {
        Ok(conf) => {
            dbg!(&conf);
            web::Data::new(conf)
        }
        Err(e) => {
            log::error!("{}", e);
            return Err(IoError::new(ErrorKind::Other, e));
        }
    };

    let listen = conf.listen;

    let geoip = match geo::GeoIp::try_from_config(&conf) {
        Ok(geoip) => web::Data::new(geoip),
        Err(e) => {
            log::error!("{}", e);
            return Err(IoError::new(ErrorKind::Other, e));
        }
    };

    let pool = match database::connect(&conf.db).await {
        Ok(pool) => web::Data::new(pool),
        Err(e) => {
            log::error!("{}", e);
            return Err(IoError::new(ErrorKind::Other, e));
        }
    };

    let repo = { web::Data::new(rules::Repository::new(pool.clone())) };

    if let Err(e) = repo.truncate().await {
        log::error!("{}", e);
        return Err(IoError::new(ErrorKind::Other, e));
    }

    let trusted_proxies = web::Data::new(net::TrustedProxies::new(&conf.trusted_proxies));
    let collection = web::Data::new(RwLock::new(rules::Collection::default()));

    let manager = {
        let mut manager = rules::Manager::new(conf.clone(), repo.clone(), collection.clone());

        if let Err(e) = manager.init().await {
            log::error!("{}", e);
            return Err(IoError::new(ErrorKind::Other, e));
        }

        web::Data::new(manager)
    };

    {
        let manager = manager.clone();
        let collection = collection.clone();
        let repo = repo.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                let rules = collection.read().await;
                let now = chrono::Utc::now();

                if !rules.next_expiration().is_some_and(|time| time <= now) {
                    log::trace!("no expired rules to delete");
                    continue;
                }

                drop(rules);

                let Ok(rules) = repo.get_all().await else {
                    log::error!("failed listing rules for expiration handling");
                    continue;
                };

                let mut deleted = 0;
                for rule in rules.iter().filter(|rule| rule.is_expired_at(&now)) {
                    deleted += 1;
                    if let Err(e) = repo.delete(rule.id).await {
                        log::error!("failed to delete expired rule: {}", e);
                    };
                }

                if deleted == 0 {
                    log::warn!("no expired rules were deleted, but some should have been");
                    continue;
                }

                if let Err(e) = manager.update_matcher().await {
                    log::error!("error {}", e);
                } else {
                    log::info!("rebuilt matcher");
                }
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
            .wrap(DefaultHeaders::new().add(("Server", "Doorbell")))
            .app_data(json_config)
            .app_data(repo.clone())
            .app_data(conf.clone())
            .app_data(manager.clone())
            .app_data(trusted_proxies.clone())
            .app_data(geoip.clone())
            .app_data(collection.clone())
            .service(routes::root::handler)
            .service(routes::ring::handler)
            .service(routes::rules::list)
            .service(routes::rules::create)
            .service(routes::rules::get)
            .service(routes::rules::delete)
            .service(routes::rules::patch)
    })
    .workers(4)
    .bind(listen)
    .map_err(|e| IoError::new(ErrorKind::Other, e))?
    .run()
    .await
}
