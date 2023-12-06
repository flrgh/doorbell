use actix_web::{delete, get, patch, post, web, HttpRequest, HttpResponse, Responder};

use crate::app::State;
use crate::rules::{RuleBuilder, RuleCreate, RuleUpdates, Source};
use crate::types::Repository;

#[get("/rules")]
pub async fn list(_: HttpRequest, state: web::Data<State>) -> impl Responder {
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

#[post("/rules")]
pub async fn create(
    web::Json(input): web::Json<RuleCreate>,
    state: web::Data<State>,
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

    match state.repo.insert(rule.clone()).await {
        Ok(_) => {
            log::debug!("Created a new rule: {:?}", &rule);
            if let Err(e) = state.manager.lock().await.update_matcher().await {
                log::error!("failed rebuilding matcher after rule creation: {}", e);
            } else {
                log::info!("rebuilt matcher");
            }

            HttpResponse::Created().json(rule)
        }
        Err(e) => {
            dbg!(e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[get("/rules/{id}")]
pub async fn get(id: web::Path<uuid::Uuid>, state: web::Data<State>) -> impl Responder {
    let id = id.into_inner();
    match state.repo.get(id.into()).await {
        Ok(Some(rule)) => HttpResponse::Ok().json(rule),
        Ok(None) => HttpResponse::NotFound().finish(),
        Err(err) => {
            log::error!("{}", err);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[delete("/rules/{id}")]
pub async fn delete(id: web::Path<uuid::Uuid>, state: web::Data<State>) -> impl Responder {
    let id = id.into_inner();
    let rule = match state.repo.get(id.into()).await {
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

    match state.repo.delete(id.into()).await {
        Ok(Some(_)) => HttpResponse::NoContent().finish(),
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
    state: web::Data<State>,
) -> impl Responder {
    let id = id.into_inner();
    let mut rule = match state.repo.get(id.into()).await {
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
        Ok(true) => match state.repo.upsert(rule.clone()).await {
            Ok(_) => HttpResponse::Ok().json(rule),
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
