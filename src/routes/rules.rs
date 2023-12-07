use actix_web::{delete, get, patch, post, web, HttpRequest, HttpResponse, Responder};

use crate::rules::{Manager, RuleBuilder, RuleCreate, RuleUpdates, Source};
use crate::types::Repository;

async fn update_matcher(event: &str, manager: web::Data<Manager>) {
    if let Err(e) = manager.update_matcher().await {
        log::error!("failed rebuilding matcher after rule {}: {}", event, e);
    } else {
        log::info!("rebuilt matcher after rule {}", event);
    }
}

#[get("/rules")]
pub async fn list(_: HttpRequest, repo: web::Data<crate::rules::Repository>) -> impl Responder {
    let rules = match repo.get_all().await {
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

#[post("/rules")]
pub async fn create(
    web::Json(input): web::Json<RuleCreate>,
    repo: web::Data<crate::rules::Repository>,
    manager: web::Data<Manager>,
) -> impl Responder {
    let built = RuleBuilder::from(input).source(Source::Api).build();

    let rule = match built {
        Ok(rule) => rule,
        Err(e) => {
            log::info!("invalid POST /rules input: {}", e);

            let json = serde_json::json!({
                "error": e,
            });

            return HttpResponse::BadRequest().json(json);
        }
    };

    match repo.insert(rule.clone()).await {
        Ok(_) => {
            log::debug!("Created a new rule: {:?}", &rule);
            update_matcher("creation", manager).await;
            HttpResponse::Created().json(rule)
        }
        Err(e) => {
            dbg!(e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[get("/rules/{id}")]
pub async fn get(
    id: web::Path<uuid::Uuid>,
    repo: web::Data<crate::rules::Repository>,
) -> impl Responder {
    let id = id.into_inner();
    match repo.get(id.into()).await {
        Ok(Some(rule)) => HttpResponse::Ok().json(rule),
        Ok(None) => HttpResponse::NotFound().finish(),
        Err(err) => {
            log::error!("{}", err);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[delete("/rules/{id}")]
pub async fn delete(
    id: web::Path<uuid::Uuid>,
    repo: web::Data<crate::rules::Repository>,
    manager: web::Data<Manager>,
) -> impl Responder {
    let id = id.into_inner();
    let rule = match repo.get(id.into()).await {
        Ok(Some(rule)) => rule,
        Ok(None) => {
            return HttpResponse::NotFound().finish();
        }
        Err(err) => {
            log::error!("{}", err);
            return HttpResponse::InternalServerError().finish();
        }
    };

    if rule.is_read_only() {
        let msg = format!("Cannot delete {} rule", rule.source);
        let json = serde_json::json!({
            "error": msg
        });
        return HttpResponse::BadRequest().json(json);
    }

    match repo.delete(id.into()).await {
        Ok(Some(_)) => {
            update_matcher("deletion", manager).await;
            HttpResponse::NoContent().finish()
        }
        Ok(None) => HttpResponse::NotFound().finish(),
        Err(err) => {
            log::error!("{}", err);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[patch("/rules/{id}")]
pub async fn patch(
    id: web::Path<uuid::Uuid>,
    web::Json(updates): web::Json<RuleUpdates>,
    repo: web::Data<crate::rules::Repository>,
    manager: web::Data<Manager>,
) -> impl Responder {
    let id = id.into_inner();
    let mut rule = match repo.get(id.into()).await {
        Ok(Some(rule)) => rule,
        Ok(None) => {
            return HttpResponse::NotFound().finish();
        }
        Err(err) => {
            log::error!("{}", err);
            return HttpResponse::InternalServerError().finish();
        }
    };

    if rule.is_read_only() {
        let msg = format!("Cannot update {} rule", rule.source);
        let json = serde_json::json!({
            "error": msg
        });
        return HttpResponse::BadRequest().json(json);
    }

    match updates.update(&mut rule) {
        Ok(true) => match repo.upsert(rule.clone()).await {
            Ok(_) => {
                update_matcher("update", manager).await;
                HttpResponse::Ok().json(rule)
            }
            Err(err) => {
                log::error!("{}", err);
                HttpResponse::InternalServerError().finish()
            }
        },
        Ok(false) => {
            log::warn!("got a patch request but without any changes");
            HttpResponse::Ok().json(rule)
        }
        Err(err) => {
            log::error!("{}", err);
            HttpResponse::InternalServerError().finish()
        }
    }
}
