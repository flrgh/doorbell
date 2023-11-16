#![allow(dead_code, unused)]

mod cli;
mod config;
mod database;
mod geo;
mod rules;
mod types;
use database as db;

use actix_web::{get, web, App, HttpRequest, HttpResponse, HttpServer, Responder};

struct State<'a> {
    rules: crate::rules::RuleCollection<'a>,
}

#[get("/")]
async fn index(req: HttpRequest) -> impl Responder {
    println!("REQ: {:?}", req);
    "Hello world!"
}

#[get("/ring")]
async fn ring(req: HttpRequest, state: web::Data<State<'_>>) -> impl Responder {
    let headers = req.headers();
    let addr = headers.get("x-forwarded-for").unwrap();
    let proto = headers.get("x-forwarded-proto").unwrap();
    let host = headers.get("x-forwarded-host").unwrap();
    let uri = headers.get("x-forwarded-uri").unwrap();
    let method = headers.get("x-forwarded-method").unwrap();
    let user_agent = headers.get("user-agent").unwrap();

    "later"
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let conf = config::Conf::new().unwrap();
    dbg!(&conf);
    db::connect(&conf.db).await;

    HttpServer::new(|| {
        App::new()
            .app_data(web::Data::new(State {
                rules: Default::default(),
            }))
            .service(index)
            .service(ring)
    })
    .bind(&conf.listen)?
    .run()
    .await
}
