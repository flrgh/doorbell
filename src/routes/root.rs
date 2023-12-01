use actix_web::{get, HttpResponse, Responder};

#[get("/")]
pub async fn handler() -> impl Responder {
    HttpResponse::MethodNotAllowed().body("Go away!")
}
