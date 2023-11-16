use std::net::IpAddr;
//use std::collections::HashMap;
use chrono::prelude::*;
use cidr::IpCidr;
//use uuid::Uuid;
use std::cmp::Ordering;
use sqlx::FromRow;
use strum_macros::Display as EnumDisplay;
use strum_macros::EnumString;

use crate::geo::*;
use crate::types::*;

#[derive(Debug, Eq, PartialEq)]
pub enum Condition {
    Addr(IpAddr),
    Network(IpCidr),
    UserAgent(Pattern),
    Host(Pattern),
    Path(Pattern),
    CountryCode(CountryCode),
    Method(http::Method),
    Asn(u32),
    Org(Pattern),
}

impl Condition {
    fn matches(&self, req: &AccessRequest) -> bool {
        match self {
            Condition::Addr(addr) => req.addr.eq(addr),
            Condition::Network(cidr) => cidr.contains(&req.addr),
            Condition::UserAgent(pattern) => pattern.matches(&req.user_agent),
            Condition::Host(pattern) => pattern.matches(&req.host),
            Condition::Path(pattern) => pattern.matches(&req.path),
            Condition::CountryCode(code) => req.country_code == Some(*code),
            Condition::Method(method) => req.method.eq(method),
            Condition::Asn(asn) => req.asn == Some(*asn),
            Condition::Org(pattern) => {
                if let Some(org) = &req.org {
                    return pattern.matches(org);
                }
                false
            }
        }
    }
}

#[derive(
    PartialEq, Eq, Clone, Debug, PartialOrd, Ord, EnumDisplay, EnumString, sqlx::Type,
)]
#[strum(serialize_all = "lowercase")]
#[sqlx(rename_all = "lowercase")]
pub(crate) enum Action {
    Deny,
    Allow,
}


#[derive(PartialEq, Eq, Clone, Debug, Default, EnumDisplay, EnumString, sqlx::Type)]
#[strum(serialize_all = "lowercase")]
#[sqlx(rename_all = "lowercase")]
pub(crate) enum DenyAction {
    #[default]
    Exit,
    Tarpit,
}

#[derive(
    PartialEq, Eq, Clone, Debug, PartialOrd, Ord, EnumDisplay, EnumString, sqlx::Type,
)]
#[strum(serialize_all = "lowercase")]
#[sqlx(rename_all = "lowercase")]
pub(crate) enum Source {
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


#[derive(Debug, Eq, PartialEq, sqlx::Type, sqlx::FromRow)]
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
    pub user_agent: Option<String>,
    pub host: Option<Pattern>,
    pub path: Option<Pattern>,
    pub country_code: Option<CountryCode>,
    pub method: Option<http::Method>,
    pub asn: Option<u32>,
    pub org: Option<Pattern>,
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

#[derive(Default, Debug)]
pub(crate) struct RuleCollection<'a> {
    pub(crate) rules: Vec<Rule>,
    //pub(crate) by_id: HashMap<String, &'a Rule>,
    //pub(crate) by_hash: HashMap<String, &'a Rule>,
    pd: std::marker::PhantomData<&'a ()>,
}

impl<'a> RuleCollection<'a> {
    pub fn get_match(&'a self, req: &AccessRequest) -> Option<&'a Rule> {
        let mut matched: Option<&'a Rule> = None;

        let iter = self
            .rules
            .iter()
            .filter(|r| !r.is_expired_at(&req.timestamp));

        for rule in iter {
            if rule.matches(req) {
                if rule.terminate {
                    matched = Some(rule);
                    break;
                }

                if let Some(last) = matched {
                    if last.conditions().len() < rule.conditions().len() {
                        matched = Some(rule);
                    }
                }
            }
        }

        matched
    }

    pub fn drop_expired(&mut self) -> usize {
        let before = self.rules.len();
        self.rules.retain(|r| !r.is_expired());

        let dropped = before - self.rules.len();
        if dropped > 0 {
            self.rules.sort();
        }

        dropped
    }
}
