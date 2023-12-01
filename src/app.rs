use std::sync::Arc;
use std::sync::RwLock;
use tokio::sync::Mutex;

use crate::config;
use crate::net;
use crate::rules;

pub struct State {
    pub rules: Arc<RwLock<rules::Collection>>,
    pub repo: Arc<rules::Repository>,
    pub config: Arc<config::Conf>,
    pub manager: Arc<Mutex<rules::Manager>>,
    pub trusted_proxies: Arc<net::TrustedProxies>,
}
