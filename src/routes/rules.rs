use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};

use crate::app::State;
use crate::rules::RuleBuilder;
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
    web::Json(input): web::Json<RuleBuilder>,
    state: web::Data<State>,
) -> impl Responder {
    let rule = match input.build() {
        Ok(rule) => rule,
        Err(e) => {
            log::info!("{e}");

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

            let json = serde_json::json!(rule);
            HttpResponse::Created().json(json)
        }
        Err(e) => {
            dbg!(e);
            HttpResponse::InternalServerError().finish()
        }
    }
}
