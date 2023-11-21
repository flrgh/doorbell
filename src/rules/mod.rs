use std::net::IpAddr;
//use std::collections::HashMap;
use chrono::prelude::*;
use cidr::IpCidr;
//use uuid::Uuid;
use sqlx::sqlite::SqliteRow;
use sqlx::Row;
use sqlx::Type;
use std::cmp::Ordering;
use strum_macros::Display as EnumDisplay;
use strum_macros::EnumIs;
use strum_macros::EnumString;

use self::condition::*;
use crate::geo::*;
use crate::types::*;
use anyhow::{anyhow, Context, Result};
use sqlx::sqlite::SqliteColumn;
use sqlx::Column;


pub mod condition;
pub mod repo;
pub mod matcher;

#[derive(
    PartialEq, Eq, Clone, Debug, PartialOrd, Ord, EnumDisplay, EnumString, Type, Default, EnumIs,
)]
#[strum(serialize_all = "lowercase")]
#[sqlx(rename_all = "lowercase")]
pub(crate) enum Action {
    #[default]
    Deny,
    Allow,
}

#[derive(PartialEq, Eq, Clone, Debug, Default, EnumDisplay, EnumString, Type, EnumIs)]
#[strum(serialize_all = "lowercase")]
#[sqlx(rename_all = "lowercase")]
pub(crate) enum DenyAction {
    #[default]
    Exit,
    Tarpit,
}

#[derive(
    PartialEq, Eq, Clone, Debug, PartialOrd, Ord, EnumDisplay, EnumString, Type, Default, EnumIs,
)]
#[strum(serialize_all = "lowercase")]
#[sqlx(rename_all = "lowercase")]
pub(crate) enum Source {
    #[default]
    Api,
    User,
    Config,
    Ota,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Uuid {
    inner: uuid::Uuid,
}

impl std::ops::Deref for Uuid {
    type Target = uuid::Uuid;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl TryFrom<&str> for Uuid {
    type Error = uuid::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            inner: uuid::Uuid::try_parse(value)?,
        })
    }
}

#[derive(Debug, Eq, PartialEq, Type, Clone, Default)]
pub(crate) struct Rule {
    pub id: uuid::Uuid,
    pub action: Action,
    pub deny_action: Option<DenyAction>,
    pub hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
    pub terminate: bool,
    pub comment: Option<String>,
    pub source: Source,
    pub expires: Option<DateTime<Utc>>,

    pub addr: Option<IpAddr>,
    pub cidr: Option<IpCidr>,
    pub user_agent: Option<Pattern>,
    pub host: Option<Pattern>,
    pub path: Option<Pattern>,
    pub country_code: Option<CountryCode>,

    pub method: Option<http::Method>,
    pub asn: Option<u32>,
    pub org: Option<Pattern>,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct RuleBuilder {
    pub id: Option<uuid::Uuid>,
    pub action: Option<Action>,
    pub deny_action: Option<DenyAction>,
    pub terminate: Option<bool>,
    pub comment: Option<String>,
    pub source: Option<Source>,
    pub expires: Option<DateTime<Utc>>,
    pub addr: Option<IpAddr>,
    pub cidr: Option<IpCidr>,
    pub user_agent: Option<Pattern>,
    pub host: Option<Pattern>,
    pub path: Option<Pattern>,
    pub country_code: Option<CountryCode>,
    pub method: Option<http::Method>,
    pub asn: Option<u32>,
    pub org: Option<Pattern>,
}

impl RuleBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_id(mut self, id: uuid::Uuid) -> Self {
        self.id = Some(id);
        self
    }

    pub fn with_action(mut self, action: Action) -> Self {
        self.action = Some(action);
        self
    }

    pub fn with_deny_action(mut self, da: DenyAction) -> Self {
        self.deny_action = Some(da);
        self
    }
}

impl Rule {
    pub fn calculate_hash(rule: &Rule) -> String {
        let mut ctx = md5::Context::new();

        if let Some(ref addr) = rule.addr {
            let addr = addr.to_string().as_bytes().to_owned();
            ctx.consume(addr);
        } else {
            ctx.consume([0]);
        }

        if let Some(ref cidr) = rule.cidr {
            let cidr = cidr.to_string().as_bytes().to_owned();
            ctx.consume(cidr);
        } else {
            ctx.consume([0]);
        }

        if let Some(ref user_agent) = rule.user_agent {
            let user_agent: String = user_agent.into();
            ctx.consume(user_agent)
        } else {
            ctx.consume([0]);
        }

        if let Some(ref host) = rule.host {
            let host: String = host.into();
            ctx.consume(host)
        } else {
            ctx.consume([0]);
        }

        if let Some(ref path) = rule.path {
            let path: String = path.into();
            ctx.consume(path)
        } else {
            ctx.consume([0]);
        }

        if let Some(ref org) = rule.org {
            let org: String = org.into();
            ctx.consume(org);
        } else {
            ctx.consume([0]);
        }

        if let Some(ref method) = rule.method {
            let method = method.to_string();
            ctx.consume(method);
        } else {
            ctx.consume([0]);
        }

        if let Some(ref country_code) = rule.country_code {
            let country_code = country_code.to_string();
            ctx.consume(country_code);
        } else {
            ctx.consume([0]);
        }

        if let Some(ref asn) = rule.asn {
            let asn = asn.to_string();
            ctx.consume(asn);
        } else {
            ctx.consume([0]);
        }

        let digest = ctx.compute();
        format!("{:x}", digest)
    }
}

impl Update for Rule {
    type Updates = RuleUpdates;

    fn update(&mut self, updates: Self::Updates) {
        updates.update(self);
    }
}

#[derive(Debug, Eq, PartialEq, Type)]
pub(crate) struct RuleUpdates {
    pub action: Option<Action>,
    pub deny_action: Option<Option<DenyAction>>,
    pub updated_at: Option<Option<DateTime<Utc>>>,
    pub terminate: Option<bool>,
    pub comment: Option<Option<String>>,
    pub expires: Option<Option<DateTime<Utc>>>,

    pub addr: Option<Option<IpAddr>>,
    pub cidr: Option<Option<IpCidr>>,
    pub user_agent: Option<Option<Pattern>>,
    pub host: Option<Option<Pattern>>,
    pub path: Option<Option<Pattern>>,
    pub country_code: Option<Option<CountryCode>>,
    pub method: Option<Option<http::Method>>,
    pub asn: Option<Option<u32>>,
    pub org: Option<Option<Pattern>>,
}

impl RuleUpdates {
    fn update(self, rule: &mut Rule) {
        let RuleUpdates {
            action,
            deny_action,
            updated_at,
            terminate,
            comment,
            expires,
            addr,
            cidr,
            user_agent,
            host,
            path,
            country_code,
            method,
            asn,
            org,
        } = self;

        if let Some(action) = action {
            rule.action = action;
        }

        if let Some(deny_action) = deny_action {
            rule.deny_action = deny_action;
        }

        if let Some(terminate) = terminate {
            rule.terminate = terminate;
        }

        if let Some(comment) = comment {
            rule.comment = comment;
        }

        if let Some(expires) = expires {
            rule.expires = expires;
        }

        if let Some(addr) = addr {
            rule.addr = addr;
        }

        if let Some(cidr) = cidr {
            rule.cidr = cidr;
        }

        if let Some(user_agent) = user_agent {
            rule.user_agent = user_agent;
        }

        if let Some(host) = host {
            rule.host = host;
        }

        if let Some(path) = path {
            rule.path = path;
        }

        if let Some(method) = method {
            rule.method = method;
        }

        if let Some(asn) = asn {
            rule.asn = asn;
        }

        if let Some(country_code) = country_code {
            rule.country_code = country_code;
        }

        if let Some(org) = org {
            rule.org = org;
        }

        rule.updated_at = Some(chrono::Utc::now());
        rule.hash = Rule::calculate_hash(rule);
    }
}


pub struct RuleConditions<'a> {
    count: usize,
    offset: usize,
    conditions: [Option<&'a Condition>; 9],
}

impl<'a> Iterator for RuleConditions<'a> {
    type Item = &'a Condition;

    fn next(&mut self) -> Option<Self::Item> {
        todo!()
    }
}

impl<'a> ExactSizeIterator for RuleConditions<'a> {
    fn len(&self) -> usize {
        self.count
    }
}

impl Rule {
    pub fn conditions(&self) -> RuleConditions {
        todo!()
        //let conditions = [
        //    self.addr.and_then(|addr| Some(Condition::Addr(addr))),
        //    self.cidr.and_then(|cidr| Some(Condition::Network(cidr))),
        //    self.user_agent.and_then(|user_agent| Some(Condition::UserAgent(user_agent))),
        //    self.host.and_then(|host| Some(Condition::Host(host))),
        //    self.path.and_then(|path| Some(Condition::Path(path))),
        //    self.path.and_then(|path| Some(Condition::Path(path))),
        //];

        //RuleConditions {
        //    count: conditions.len(),
        //    offset: 0,
        //    conditions,
        //}
    }

    pub fn matches(&self, req: &AccessRequest) -> bool {
        self.conditions().all(|cond| cond.matches(req))
    }

    pub fn is_expired(&self) -> bool {
        if self.expires.is_some() {
            self.is_expired_at(&Utc::now())
        } else {
            false
        }
    }

    pub fn is_expired_at(&self, now: &DateTime<Utc>) -> bool {
        if let Some(exp) = self.expires {
            *now >= exp
        } else {
            false
        }
    }
}

impl PartialOrd for Rule {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Rule {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.terminate && !other.terminate {
            return Ordering::Less;
        }

        if self.conditions().len() != other.conditions().len() {
            return other.conditions().len().cmp(&self.conditions().len());
        }

        if self.action != other.action {
            return self.action.cmp(&other.action);
        }

        if self.updated_at != other.updated_at {
            return self.updated_at.cmp(&other.updated_at);
        }

        if self.created_at != other.created_at {
            return self.created_at.cmp(&other.created_at);
        }

        self.hash.cmp(&other.hash)
    }
}

impl PrimaryKey for Rule {
    type Key = uuid::Uuid;

    fn primary_key(&self) -> Self::Key {
        self.id
    }

    fn primary_key_column() -> &'static str {
        "id"
    }
}

impl Validate for Rule {
    type Err = anyhow::Error;

    fn validate(&self) -> std::result::Result<(), Self::Err> {
        if self.addr.is_none()
            && self.asn.is_none()
            && self.cidr.is_none()
            && self.country_code.is_none()
            && self.host.is_none()
            && self.method.is_none()
            && self.org.is_none()
            && self.path.is_none()
            && self.user_agent.is_none()
        {
            return Err(anyhow::anyhow!("rule must have at least one condition"));
        }

        if self.source.is_config() && self.expires.is_some() {
            return Err(anyhow::anyhow!("config rules cannot expire"));
        }

        Ok(())
    }
}

impl Entity for Rule {
    fn table_name() -> &'static str {
        "rules"
    }
}
