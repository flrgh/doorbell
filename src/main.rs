mod access;
mod app;
mod cli;
mod config;
mod database;
mod geo;
mod net;
mod notify;
mod routes;
mod rules;
mod types;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    app::run().await
}
