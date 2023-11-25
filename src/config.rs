use crate::rules::condition::*;
use crate::rules::{Action, DenyAction, IpCidr, Rule, Source};
use config::{Config, ConfigError, Environment, File};
use serde_derive::Deserialize;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct Conf {
    pub db: PathBuf,
    pub listen: SocketAddr,
    pub allow: Vec<ConfRule>,
    pub deny: Vec<ConfRule>,
    pub geoip_asn_db: Option<PathBuf>,
    pub geoip_city_db: Option<PathBuf>,
    pub geoip_country_db: Option<PathBuf>,
    pub trusted_proxies: Vec<IpCidr>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ConfRule {
    pub deny_action: Option<DenyAction>,
    pub terminate: bool,
    pub comment: Option<String>,

    pub addr: Option<IpAddr>,
    pub cidr: Option<IpCidr>,
    pub user_agent: Option<Pattern>,
    pub host: Option<Pattern>,
    pub path: Option<Pattern>,
    pub country_code: Option<CountryCode>,
    pub method: Option<HttpMethod>,
    pub asn: Option<u32>,
    pub org: Option<Pattern>,
}

impl ConfRule {
    fn as_rule(&self, action: Action) -> Rule {
        let ConfRule {
            deny_action,
            terminate,
            comment,
            addr,
            cidr,
            user_agent,
            host,
            path,
            country_code,
            method,
            asn,
            org,
        } = self.clone();

        Rule {
            id: uuid::Uuid::new_v4(),
            source: Source::Config,
            action,
            terminate,
            comment,
            addr,
            cidr,
            user_agent,
            host,
            path,
            country_code,
            method,
            asn,
            org,
            ..Default::default()
        }
    }
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

    pub fn rules(&self) -> Vec<crate::rules::Rule> {
        let mut rules = Vec::with_capacity(self.allow.len() + self.deny.len());
        for deny in &self.deny {
            rules.push(deny.as_rule(Action::Deny));
        }

        for allow in &self.allow {
            rules.push(allow.as_rule(Action::Allow));
        }

        rules
    }
}
