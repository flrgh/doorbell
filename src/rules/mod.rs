use chrono::prelude::*;
use derive_builder::Builder;
use serde::Deserializer;
use serde_derive::{Deserialize, Serialize};
use sqlx::{FromRow, Type};
use std::{cmp::Ordering, time::Duration};
//use std::net::IpAddr;

use self::condition::*;
use crate::geo::*;
pub(crate) use crate::types::{IpAddr, IpCidr, Pattern, Uuid, Validate};
use anyhow::{anyhow, Result};

pub mod action;
pub mod collection;
pub mod condition;
pub mod manager;
pub mod repo;
pub mod source;

pub use action::*;
pub use collection::*;
pub use manager::*;
pub use repo::*;
pub use source::*;

#[serde_with::skip_serializing_none]
#[derive(Debug, Eq, PartialEq, Type, Clone, Default, Builder, Serialize, FromRow)]
#[builder(
    setter(into),
    build_fn(private, name = "build_super", validate = "Self::validate"),
    derive(serde::Deserialize, Debug)
)]
#[builder_struct_attr(serde(deny_unknown_fields))]
pub struct Rule {
    #[builder(setter(skip = true))]
    #[builder_field_attr(serde(skip))]
    pub id: Uuid,

    pub action: Action,

    #[sqlx(default)]
    pub terminate: bool,

    #[builder(setter(skip = true))]
    #[builder_field_attr(serde(skip))]
    pub hash: String,

    #[builder(setter(skip = true))]
    #[builder_field_attr(serde(skip))]
    pub created_at: DateTime<Utc>,

    #[builder(setter(skip = true))]
    #[builder_field_attr(serde(skip))]
    pub updated_at: Option<DateTime<Utc>>,

    pub comment: Option<String>,
    pub source: Source,
    pub expires: Option<DateTime<Utc>>,

    pub addr: Option<IpAddr>,
    pub cidr: Option<IpCidr>,
    pub user_agent: Option<Pattern>,
    pub host: Option<Pattern>,
    pub path: Option<Pattern>,
    pub country_code: Option<CountryCode>,
    pub method: Option<Method>,
    pub asn: Option<u32>,
    pub org: Option<Pattern>,
}

#[derive(Debug, Eq, PartialEq, Type, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleCreate {
    pub comment: Option<String>,

    pub action: Action,
    pub terminate: Option<bool>,
    pub expires: Option<DateTime<Utc>>,
    pub ttl: Option<u64>,

    pub addr: Option<IpAddr>,
    pub cidr: Option<IpCidr>,
    pub user_agent: Option<Pattern>,
    pub host: Option<Pattern>,
    pub path: Option<Pattern>,
    pub country_code: Option<CountryCode>,
    pub method: Option<Method>,
    pub asn: Option<u32>,
    pub org: Option<Pattern>,
}

impl From<RuleCreate> for RuleBuilder {
    fn from(value: RuleCreate) -> Self {
        let RuleCreate {
            comment,
            action,
            terminate,
            expires,
            ttl,
            addr,
            cidr,
            user_agent,
            host,
            path,
            country_code,
            method,
            asn,
            org,
        } = value;

        let expires = match (expires, ttl) {
            (Some(expires), Some(_)) => {
                log::warn!("Trying to create a rule with both `expires` and `ttl` inputs");
                Some(expires)
            }
            (None, Some(ttl)) => {
                let ttl = Duration::from_secs(ttl);
                Some(chrono::Utc::now() + ttl)
            }
            _ => expires,
        };

        Self::default()
            .comment(comment)
            .action(action)
            .terminate(terminate.unwrap_or(false))
            .expires(expires)
            .addr(addr)
            .cidr(cidr)
            .user_agent(user_agent)
            .host(host)
            .path(path)
            .country_code(country_code)
            .method(method)
            .asn(asn)
            .org(org)
            .to_owned()
    }
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
        match self.0 {
            std::net::IpAddr::V4(addr) => {
                ctx.consume(addr.octets());
            }
            std::net::IpAddr::V6(addr) => {
                ctx.consume(addr.octets());
            }
        }
    }
}

impl ConditionHash for IpCidr {
    fn hash(&self, ctx: &mut md5::Context) {
        match self.0 {
            cidr_utils::cidr::IpCidr::V4(cidr) => {
                ctx.consume(cidr.get_prefix_as_u8_array());
                ctx.consume(cidr.get_mask_as_u8_array());
            }
            cidr_utils::cidr::IpCidr::V6(cidr) => {
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

impl ConditionHash for Method {
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

fn hash_conditions(
    addr: impl ConditionHash,
    cidr: impl ConditionHash,
    org: impl ConditionHash,
    asn: impl ConditionHash,
    country_code: impl ConditionHash,
    host: impl ConditionHash,
    path: impl ConditionHash,
    method: impl ConditionHash,
    user_agent: impl ConditionHash,
) -> String {
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
        hash_conditions(
            rule.addr,
            rule.cidr,
            &rule.org,
            rule.asn,
            rule.country_code,
            &rule.host,
            &rule.path,
            &rule.method,
            &rule.user_agent,
        )
    }

    pub fn is_read_only(&self) -> bool {
        self.source.is_config() || self.source.is_ota()
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

    pub fn ttl(&mut self, ttl: Duration) -> &mut Self {
        self.expires(Some(chrono::Utc::now() + ttl))
    }

    pub fn build(&self) -> Result<Rule, String> {
        self.validate()?;
        let RuleBuilder {
            action,
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
            id: _,
            hash: _,
            created_at: _,
            updated_at: _,
        } = self.to_owned();

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
            id: Uuid::new(),
            source: get(source, "source")?,
            action: get(action, "action")?,
            terminate: terminate.unwrap_or(false),
            comment: get_inner(comment),
            expires: get_inner(expires),
            created_at: chrono::Utc::now(),
            updated_at: None,

            hash: hash_conditions(
                addr,
                cidr,
                &org,
                asn,
                country_code,
                &host,
                &path,
                &method,
                &user_agent,
            ),

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

impl crate::types::Update for Rule {
    type Updates = RuleUpdates;
    type Err = anyhow::Error;

    fn update(&mut self, updates: Self::Updates) -> Result<bool, Self::Err> {
        updates.update(self)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub enum FieldAction<T> {
    Delete,
    Update(T),
}

pub type FieldUpdate<T> = Option<FieldAction<T>>;

// #[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
// pub enum FieldUpdate<T> {
//     NoChange,
//     Change(FieldAction<T>),
// }

#[derive(Debug, Eq, PartialEq, Default)]
pub(crate) enum Patch<T> {
    #[default]
    Unchanged,
    Remove,
    Value(T),
}

impl<T> From<Option<T>> for Patch<T> {
    fn from(opt: Option<T>) -> Patch<T> {
        match opt {
            Some(v) => Patch::Value(v),
            None => Patch::Remove,
        }
    }
}

impl<'de, T> serde::Deserialize<'de> for Patch<T>
where
    T: serde::Deserialize<'de>,
    T: std::fmt::Debug,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::deserialize(deserializer).map(Into::into)
    }
}

#[derive(Debug, Eq, PartialEq, Type, Deserialize, Default)]
pub struct RuleUpdates {
    #[serde(default)]
    pub action: Option<Action>,
    #[serde(default)]
    pub terminate: Option<bool>,
    #[serde(default)]
    pub comment: Patch<String>,
    #[serde(default)]
    pub expires: Patch<DateTime<Utc>>,
    #[serde(default)]
    pub ttl: Option<u64>,

    #[serde(default)]
    pub addr: Patch<IpAddr>,
    #[serde(default)]
    pub cidr: Patch<IpCidr>,
    #[serde(default)]
    pub user_agent: Patch<Pattern>,
    #[serde(default)]
    pub host: Patch<Pattern>,
    #[serde(default)]
    pub path: Patch<Pattern>,
    #[serde(default)]
    pub country_code: Patch<CountryCode>,
    #[serde(default)]
    pub method: Patch<Method>,
    #[serde(default)]
    pub asn: Patch<u32>,
    #[serde(default)]
    pub org: Patch<Pattern>,
}

trait UpdateChanged<T> {
    fn update(&mut self, t: T) -> bool;
}

impl<T: PartialEq> UpdateChanged<T> for Option<T> {
    fn update(&mut self, t: T) -> bool {
        let old = self.take();
        let changed = old.is_none() || old.is_some_and(|old| old != t);
        let _ = self.insert(t);
        changed
    }
}

impl<T> Patch<T> {
    pub fn update(self, field: &mut Option<T>) -> bool
    where
        T: PartialEq,
    {
        match self {
            Self::Unchanged => false,
            Self::Value(new) => UpdateChanged::update(field, new),
            Self::Remove => field.take().is_some(),
        }
    }
}

impl RuleUpdates {
    pub fn update(self, rule: &mut Rule) -> Result<bool, anyhow::Error>
    where
        Rule: Validate,
    {
        dbg!(&self);

        if rule.is_read_only() {
            return Err(anyhow::anyhow!(
                "Cannot update a rule of source = {}",
                rule.source
            ));
        }

        let RuleUpdates {
            action,
            terminate,
            comment,
            expires,
            ttl,
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

        let expires = match (expires, ttl) {
            (Patch::Remove | Patch::Unchanged, Some(ttl)) => {
                let ttl = Duration::from_secs(ttl);
                Patch::Value(chrono::Utc::now() + ttl)
            }
            (Patch::Value(expires), Some(_)) => {
                log::warn!("Trying to update a rule with both `expires` and `ttl` inputs");
                Patch::Value(expires)
            }
            (patch, None) => patch,
        };

        fn update<T: Eq>(field: &mut T, new: Option<T>) -> bool {
            if let Some(value) = new {
                let changed = *field != value;
                *field = value;
                changed
            } else {
                false
            }
        }

        let mut changed = false;
        changed |= update(&mut rule.action, action);
        changed |= update(&mut rule.terminate, terminate);

        changed |= expires.update(&mut rule.expires);
        changed |= comment.update(&mut rule.comment);
        changed |= addr.update(&mut rule.addr);
        changed |= cidr.update(&mut rule.cidr);
        changed |= user_agent.update(&mut rule.user_agent);
        changed |= host.update(&mut rule.host);
        changed |= path.update(&mut rule.path);
        changed |= method.update(&mut rule.method);
        changed |= asn.update(&mut rule.asn);
        changed |= org.update(&mut rule.org);
        changed |= country_code.update(&mut rule.country_code);

        if changed {
            rule.updated_at = Some(chrono::Utc::now());
            rule.hash = Rule::calculate_hash(rule);
        }

        rule.validate()?;

        Ok(changed)
    }
}

pub struct RuleConditions {
    count: usize,
    offset: usize,
    conditions: [Condition; 9],
}

impl Iterator for RuleConditions {
    type Item = Condition;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.conditions.get(self.offset);
        self.offset += 1;
        next.cloned()
    }
}

impl ExactSizeIterator for RuleConditions {
    fn len(&self) -> usize {
        self.conditions.len()
    }
}

impl Rule {
    pub fn conditions(&self) -> RuleConditions {
        let conditions = [
            self.addr.map(Condition::Addr).unwrap_or_default(),
            self.cidr.map(Condition::Network).unwrap_or_default(),
            self.user_agent
                .clone()
                .map(Condition::UserAgent)
                .unwrap_or_default(),
            self.host.clone().map(Condition::Host).unwrap_or_default(),
            self.path.clone().map(Condition::Path).unwrap_or_default(),
            self.asn.map(Condition::Asn).unwrap_or_default(),
            self.org.clone().map(Condition::Org).unwrap_or_default(),
            self.country_code
                .map(Condition::CountryCode)
                .unwrap_or_default(),
            self.method
                .clone()
                .map(Condition::Method)
                .unwrap_or_default(),
        ];

        RuleConditions {
            count: conditions.len(),
            offset: 0,
            conditions,
        }
    }

    pub fn matches(&self, req: &ForwardedRequest) -> bool {
        self.conditions().all(|cond| cond.matches(req))
    }

    pub fn is_expired(&self) -> bool {
        self.expires
            .is_some_and(|_| self.is_expired_at(&Utc::now()))
    }

    pub fn is_expired_at(&self, time: &DateTime<Utc>) -> bool {
        self.expires.is_some_and(|expires| *time >= expires)
    }

    pub fn equivalent(&self, other: &Rule) -> bool {
        self.action == other.action
            && self.terminate == other.terminate
            && self.comment == other.comment
            && self.expires == other.expires
            && self.addr == other.addr
            && self.cidr == other.cidr
            && self.host == other.host
            && self.user_agent == other.user_agent
            && self.path == other.path
            && self.method == other.method
            && self.org == other.org
            && self.country_code == other.country_code
            && self.asn == other.asn
    }

    pub fn diff(old: &Self, new: &Self) -> Option<RuleUpdates> {
        if old.equivalent(new) {
            return None;
        }

        let mut updates = RuleUpdates::default();

        fn patch<T: Eq + Clone>(old: &T, new: &T) -> Option<T> {
            if old == new {
                None
            } else {
                Some(new.clone())
            }
        }

        fn patch_opt<T: Eq + Clone>(old: &Option<T>, new: &Option<T>) -> Patch<T> {
            match (old, new) {
                (Some(_), None) => Patch::Remove,
                (None, None) => Patch::Unchanged,
                (Some(old), Some(new)) if old == new => Patch::Unchanged,
                (_, Some(new)) => Patch::Value(new.to_owned()),
            }
        }

        updates.action = patch(&old.action, &new.action);
        updates.terminate = patch(&old.terminate, &new.terminate);

        updates.comment = patch_opt(&old.comment, &new.comment);
        updates.expires = patch_opt(&old.expires, &new.expires);

        updates.addr = patch_opt(&old.addr, &new.addr);
        updates.cidr = patch_opt(&old.cidr, &new.cidr);
        updates.user_agent = patch_opt(&old.user_agent, &new.user_agent);
        updates.host = patch_opt(&old.host, &new.host);
        updates.method = patch_opt(&old.method, &new.method);
        updates.path = patch_opt(&old.path, &new.path);
        updates.asn = patch_opt(&old.asn, &new.asn);
        updates.org = patch_opt(&old.org, &new.org);
        updates.country_code = patch_opt(&old.country_code, &new.country_code);

        Some(updates)
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

impl crate::types::PrimaryKey for Rule {
    type Key = Uuid;

    fn primary_key(&self) -> Self::Key {
        self.id
    }

    fn primary_key_column() -> &'static str {
        "id"
    }
}

impl crate::types::Validate for Rule {
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

impl crate::types::Entity for Rule {
    fn table_name() -> &'static str {
        "rules"
    }
}

//impl<'a, R: ::sqlx::Row> ::sqlx::FromRow<'a, R> for Rule
//where
//    &'a ::std::primitive::str: ::sqlx::ColumnIndex<R>,
//
//    String: ::sqlx::decode::Decode<'a, R::Database>,
//    String: ::sqlx::types::Type<R::Database>,
//
//    uuid::Uuid: ::sqlx::decode::Decode<'a, R::Database>,
//    uuid::Uuid: ::sqlx::types::Type<R::Database>,
//
//    DateTime<Utc>: ::sqlx::decode::Decode<'a, R::Database>,
//    DateTime<Utc>: ::sqlx::types::Type<R::Database>,
//
//    Action: ::sqlx::decode::Decode<'a, R::Database>,
//    Action: ::sqlx::types::Type<R::Database>,
//
//    Source: ::sqlx::decode::Decode<'a, R::Database>,
//    Source: ::sqlx::types::Type<R::Database>,
//
//    Pattern: ::sqlx::decode::Decode<'a, R::Database>,
//    Pattern: ::sqlx::types::Type<R::Database>,
//
//    CountryCode: ::sqlx::decode::Decode<'a, R::Database>,
//    CountryCode: ::sqlx::types::Type<R::Database>,
//
//    IpAddr: ::sqlx::decode::Decode<'a, R::Database>,
//    IpAddr: ::sqlx::types::Type<R::Database>,
//
//    IpCidr: ::sqlx::decode::Decode<'a, R::Database>,
//    IpCidr: ::sqlx::types::Type<R::Database>,
//
//    bool: ::sqlx::decode::Decode<'a, R::Database>,
//    bool: ::sqlx::types::Type<R::Database>,
//
//    u32: ::sqlx::decode::Decode<'a, R::Database>,
//    u32: ::sqlx::types::Type<R::Database>,
//
//    Method: ::sqlx::decode::Decode<'a, R::Database>,
//    Method: ::sqlx::types::Type<R::Database>,
//
//{
//    fn from_row(row: &'a R) -> ::sqlx::Result<Self> {
//        Ok(Rule {
//            id: row.try_get("id")?,
//            action: row.try_get("action")?,
//            hash: row.try_get("hash")?,
//            created_at: row.try_get("created_at")?,
//            updated_at: row.try_get("updated_at")?,
//            terminate: row.try_get("terminate")?,
//            comment: row.try_get("comment")?,
//            source: row.try_get("source")?,
//            expires: row.try_get("expires")?,
//            addr: row.try_get("addr")?,
//            cidr: row.try_get("cidr")?,
//            user_agent: row.try_get("user_agent")?,
//            host: row.try_get("host")?,
//            path: row.try_get("path")?,
//            country_code: row.try_get("country_code")?,
//            method: row.try_get("method")?,
//            asn: row.try_get("asn")?,
//            org: row.try_get("org")?,
//        })
//    }
//}
