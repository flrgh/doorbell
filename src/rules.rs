use std::net::IpAddr;
//use std::collections::HashMap;
use chrono::prelude::*;
use cidr::IpCidr;
use uuid::Uuid;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use rusqlite::Result as RusqliteResult;

use std::cmp::Ordering;

use crate::geo::*;
use crate::types::*;

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Condition {
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

#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, strum_macros::Display, strum_macros::EnumString)]
#[strum(serialize_all = "lowercase")]
pub(crate) enum Action {
    Deny,
    Allow,
}

impl FromSql for Action {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        Self::try_from(value.as_str()?).map_err(|_| FromSqlError::InvalidType)
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Default, strum_macros::Display, strum_macros::EnumString)]
#[strum(serialize_all = "lowercase")]
pub(crate) enum DenyAction {
    #[default]
    Exit,
    Tarpit,
}

impl FromSql for DenyAction {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        Self::try_from(value.as_str()?).map_err(|_| FromSqlError::InvalidType)
    }
}

#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, strum_macros::Display, strum_macros::EnumString)]
#[strum(serialize_all = "lowercase")]
pub(crate) enum Source {
    Api,
    User,
    Config,
    Ota,
}

impl FromSql for Source {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        Self::try_from(value.as_str()?).map_err(|_| FromSqlError::InvalidType)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Rule {
    pub(crate) id: Uuid,
    pub(crate) action: Action,
    pub(crate) deny_action: Option<DenyAction>,
    pub(crate) hash: String,
    pub(crate) conditions: Vec<Condition>,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: Option<DateTime<Utc>>,
    pub(crate) terminate: bool,
    pub(crate) comment: Option<String>,
    pub(crate) source: Source,
    pub(crate) expires: Option<DateTime<Utc>>,
}

impl Rule {
    pub fn matches(&self, req: &AccessRequest) -> bool {
        self.conditions.iter().all(|cond| cond.matches(req))
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

        if self.conditions.len() != other.conditions.len() {
            return other.conditions.len().cmp(&self.conditions.len());
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
                    if last.conditions.len() < rule.conditions.len() {
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
