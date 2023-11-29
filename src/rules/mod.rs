use chrono::prelude::*;
use derive_builder::Builder;
use serde_derive::Deserialize;
use sqlx::sqlite::SqliteRow;
use sqlx::Row;
use sqlx::Type;
use std::cmp::Ordering;
use std::net::IpAddr;
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
pub mod manager;
pub mod matcher;
pub mod repo;

pub use cidr_utils::cidr::IpCidr;
pub use manager::Manager;
pub use matcher::Matcher;

#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    PartialOrd,
    Ord,
    EnumDisplay,
    EnumString,
    Type,
    Default,
    EnumIs,
    Deserialize,
)]
#[strum(serialize_all = "lowercase")]
#[sqlx(rename_all = "lowercase")]
pub(crate) enum Action {
    #[default]
    Deny,
    Allow,
}

#[derive(
    PartialEq, Eq, Clone, Debug, Default, EnumDisplay, EnumString, Type, EnumIs, Deserialize,
)]
#[strum(serialize_all = "lowercase")]
#[sqlx(rename_all = "lowercase")]
pub(crate) enum DenyAction {
    #[default]
    Exit,
    Tarpit,
}

#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    PartialOrd,
    Ord,
    EnumDisplay,
    EnumString,
    Type,
    Default,
    EnumIs,
    Deserialize,
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

/*
  1. private, set/get all fields indiscriminantly
  2. crate, set/get:
    * conditions
    * action
    * deny_action
    * terminate
    * id????
    * source
    * expires
  3. end-user API, similar to crate
*/

#[derive(Debug, Eq, PartialEq, Type, Clone, Default, Builder)]
#[builder(build_fn(skip, validate = "Self::validate"))]
pub(crate) struct Rule {
    #[builder(setter(skip))]
    pub id: uuid::Uuid,
    pub action: Action,
    pub deny_action: Option<DenyAction>,
    #[builder(setter(skip))]
    pub hash: String,
    #[builder(setter(skip))]
    pub created_at: DateTime<Utc>,
    #[builder(setter(skip))]
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
    pub method: Option<HttpMethod>,
    pub asn: Option<u32>,
    pub org: Option<Pattern>,
}

trait ConditionHash {
    fn hash(&self, ctx: &mut md5::Context);
}

impl<T> ConditionHash for Option<T>
where
    T: ConditionHash,
{
    fn hash(&self, ctx: &mut md5::Context) {
        if let Some(t) = self {
            t.hash(ctx);
        } else {
            ctx.consume([0]);
        }
    }
}

impl<T> ConditionHash for &Option<T>
where
    T: ConditionHash,
{
    fn hash(&self, ctx: &mut md5::Context) {
        if let Some(t) = self {
            t.hash(ctx);
        } else {
            ctx.consume([0]);
        }
    }
}


impl ConditionHash for IpAddr {
    fn hash(&self, ctx: &mut md5::Context) {
        match self {
            IpAddr::V6(addr) => ctx.consume(addr.octets()),
            IpAddr::V4(addr) => ctx.consume(addr.octets()),
        }
    }
}

impl ConditionHash for IpCidr {
    fn hash(&self, ctx: &mut md5::Context) {
        match self {
            IpCidr::V4(cidr) => {
                ctx.consume(cidr.get_prefix_as_u8_array());
                ctx.consume(cidr.get_mask_as_u8_array());
            }
            IpCidr::V6(cidr) => {
                ctx.consume(cidr.get_prefix_as_u8_array());
                ctx.consume(cidr.get_mask_as_u8_array());
            }
        }
    }
}

impl ConditionHash for Pattern {
    fn hash(&self, ctx: &mut md5::Context) {
        ctx.consume(self.as_ref());
    }
}

impl ConditionHash for HttpMethod {
    fn hash(&self, ctx: &mut md5::Context) {
        ctx.consume(self.as_ref());
    }
}

impl ConditionHash for CountryCode {
    fn hash(&self, ctx: &mut md5::Context) {
        ctx.consume::<&[u8]>(self.as_ref());
    }
}

impl ConditionHash for u32 {
    fn hash(&self, ctx: &mut md5::Context) {
        ctx.consume(self.to_be_bytes());
    }
}

fn hash_conditions(addr: impl ConditionHash, cidr: impl ConditionHash, org: impl ConditionHash, asn: impl ConditionHash, country_code: impl ConditionHash, host: impl ConditionHash, path: impl ConditionHash, method: impl ConditionHash, user_agent: impl ConditionHash) -> String {
    let mut ctx = md5::Context::new();

    addr.hash(&mut ctx);
    cidr.hash(&mut ctx);
    org.hash(&mut ctx);
    asn.hash(&mut ctx);
    country_code.hash(&mut ctx);
    host.hash(&mut ctx);
    path.hash(&mut ctx);
    method.hash(&mut ctx);
    user_agent.hash(&mut ctx);

    let digest = ctx.compute();
    format!("{:x}", digest)

}

impl Rule {
    pub fn calculate_hash(rule: &Rule) -> String {
        hash_conditions(&rule.addr, &rule.cidr, &rule.org, &rule.asn, &rule.country_code, &rule.host, &rule.path, &rule.method, &rule.user_agent)
    }
}

impl RuleBuilder {
    fn validate(&self) -> std::result::Result<(), String> {
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
            return Err("rule must have at least one condition".to_string());
        }

        if self.source.as_ref().is_some_and(|src| src.is_config()) && self.expires.is_some() {
            return Err("config rules cannot expire".to_string());
        }

        Ok(())
    }

    pub fn ttl(&mut self, ttl: std::time::Duration) -> &mut Self {
        self.expires(Some(chrono::Utc::now() + ttl))
    }

    pub fn build(&self) -> Result<Rule, String> {
        self.validate()?;
        let RuleBuilder {
            action,
            deny_action,
            terminate,
            comment,
            source,
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
            id,
            hash,
            created_at,
            updated_at,
        } = self.clone();

        fn get<T>(t: Option<T>, name: &str) -> Result<T, String> {
            if let Some(t) = t {
                Ok(t)
            } else {
                Err(format!("missing required field: {}", name))
            }
        }

        fn get_inner<T>(t: Option<Option<T>>) -> Option<T> {
            if let Some(Some(t)) = t {
                Some(t)
            } else {
                None
            }
        }

        let addr = get_inner(addr);
        let cidr = get_inner(cidr);
        let org = get_inner(org);
        let asn = get_inner(asn);
        let country_code = get_inner(country_code);
        let host = get_inner(host);
        let path = get_inner(path);
        let method = get_inner(method);
        let user_agent = get_inner(user_agent);

        Ok(Rule {
            id: uuid::Uuid::new_v4(),
            source: get(source, "source")?,
            action: get(action, "action")?,
            deny_action: get_inner(deny_action),
            terminate: terminate.unwrap_or(false),
            comment: get_inner(comment),
            expires: get_inner(expires),
            created_at: chrono::Utc::now(),
            updated_at: None,

            hash: hash_conditions(&addr,
                                  &cidr,
                                  &org,
                                  &asn,
                                  &country_code,
                                  &host,
                                  &path,
                                  &method,
                                  &user_agent),

            addr,
            cidr,
            user_agent,
            host,
            path,
            country_code,
            method,
            asn,
            org,
        })
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
    pub method: Option<Option<HttpMethod>>,
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

        fn update<T>(field: &mut T, value: Option<T>) {
            if let Some(t) = value {
                *field = t;
            }
        }

        update(&mut rule.action, action);
        update(&mut rule.deny_action, deny_action);
        update(&mut rule.terminate, terminate);
        update(&mut rule.comment, comment);
        update(&mut rule.expires, expires);
        update(&mut rule.addr, addr);
        update(&mut rule.cidr, cidr);
        update(&mut rule.user_agent, user_agent);
        update(&mut rule.host, host);
        update(&mut rule.path, path);
        update(&mut rule.method, method);
        update(&mut rule.asn, asn);
        update(&mut rule.org, org);
        update(&mut rule.country_code, country_code);

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

    pub fn matches(&self, req: &ForwardedRequest) -> bool {
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
