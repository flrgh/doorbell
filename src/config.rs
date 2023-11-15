use config::{Config, ConfigError, Environment, File};
use serde_derive::Deserialize;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct Conf {
    pub db: PathBuf,
    pub listen: SocketAddr,
}

impl Conf {
    pub fn new() -> Result<Self, ConfigError> {
        Config::builder()
            .add_source(File::with_name("config.default"))
            .add_source(File::with_name("config").required(false))
            .add_source(Environment::with_prefix("DOORBELL"))
            .build()?
            .try_deserialize()
    }
}
