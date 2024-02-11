use crate::access;
use crate::geo::GeoIp;
use crate::net::TrustedProxies;
use crate::rules::Collection;
use actix_web::{get, http::header::HeaderMap, web, HttpRequest, HttpResponse, Responder};
use serde::Deserialize;
use tokio::sync::RwLock;

#[inline]
fn bad_request() -> HttpResponse {
    HttpResponse::BadRequest().finish()
}

#[inline]
fn internal_error() -> HttpResponse {
    HttpResponse::InternalServerError().finish()
}

#[inline]
fn not_found() -> HttpResponse {
    HttpResponse::NotFound().finish()
}

#[derive(Deserialize)]
struct Answer {
    #[serde(alias = "t")]
    token: String,
}

#[get("/answer")]
pub async fn get(
    req: HttpRequest,
    query: web::Query<Answer>,
    tp: web::Data<TrustedProxies>,
    access_control: web::Data<access::Control>,
) -> impl Responder {
    let Answer { token } = query.into_inner();

    let forwarded = if token == "TEST" {
        access::Request::dummy()
    } else {
        let Some(forwarded) = access_control.get_by_token(&token).await else {
            return not_found();
        };

        forwarded
    };

    let is_current_ip = &tp.get_client_ip(&req) == forwarded.addr.as_ref();

    dbg!(forwarded, is_current_ip);

    HttpResponse::Ok().finish()
}
