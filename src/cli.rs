use clap::Parser;
use log::Level as LogLevel;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    db: String,
    config: Option<String>,
}
