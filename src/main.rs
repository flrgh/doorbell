#![allow(dead_code, unused)]

pub mod cli;
mod config;
mod database;
pub mod geo;
pub mod rules;
pub mod types;
use database as db;

use actix_web::{web, App, HttpRequest, HttpServer, Responder};

async fn index(req: HttpRequest) -> impl Responder {
    println!("REQ: {:?}", req);
    "Hello world!"
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let conf = config::Conf::new().unwrap();
    dbg!(&conf);
    db::connect(&conf.db);

    HttpServer::new(|| App::new().route("/", web::get().to(index)))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
