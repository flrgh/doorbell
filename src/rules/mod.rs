use std::net::IpAddr;
//use std::collections::HashMap;
use chrono::prelude::*;
use cidr::IpCidr;
//use uuid::Uuid;
use sqlx::sqlite::SqliteRow;
use sqlx::Row;
use std::cmp::Ordering;
use strum_macros::Display as EnumDisplay;
use strum_macros::EnumString;

use self::condition::*;
use crate::geo::*;
use crate::types::*;

pub mod condition;
pub mod repo;

#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, EnumDisplay, EnumString)]
#[strum(serialize_all = "lowercase")]
pub(crate) enum Action {
    Deny,
    Allow,
}

#[derive(PartialEq, Eq, Clone, Debug, Default, EnumDisplay, EnumString)]
#[strum(serialize_all = "lowercase")]
pub(crate) enum DenyAction {
    #[default]
    Exit,
    Tarpit,
}

#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, EnumDisplay, EnumString)]
#[strum(serialize_all = "lowercase")]
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

#[derive(Debug, Eq, PartialEq)]
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

use anyhow::{anyhow, Context, Result};
use sqlx::sqlite::SqliteColumn;
use sqlx::Column;

fn get_column<T>(row: &SqliteRow, name: &str) -> anyhow::Result<T>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    match row.get::<Option<&str>, _>(&name) {
        Some(value) => match value.parse::<T>() {
            Ok(value) => Ok(value),
            Err(e) => Err(anyhow!("Could not parse {name} from `{value}`: {e}")),
        },
        None => Err(anyhow!("Missing required value for {name}")),
    }
}

fn try_get_column<T>(row: &SqliteRow, name: &str) -> anyhow::Result<Option<T>>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    match row.get::<Option<&str>, _>(&name) {
        Some(value) => match value.parse::<T>() {
            Ok(value) => Ok(Some(value)),
            Err(e) => Err(anyhow!("Could not parse {name} from `{value}`: {e}")),
        },
        None => Ok(None),
    }
}
impl Rule {
    pub fn try_from_row(row: &SqliteRow) -> anyhow::Result<Self> {
        use anyhow::Context;
        use sqlx::sqlite::SqliteColumn;
        use sqlx::Column;

        row.columns().iter().for_each(|c| {
            let name = c.name();
            let value: Option<String> = row.try_get(c.name()).ok();
            dbg!((name, value));
        });

        Ok(Self {
            id: get_column(row, "id")?,
            hash: get_column(row, "hash")?,

            created_at: NaiveDateTime::parse_from_str(
                &get_column::<String>(row, "created_at")?,
                "%Y-%m-%d %H:%M:%S",
            )?
            .and_utc(),

            updated_at: try_get_column::<String>(row, "updated_at")?.and_then(|t| {
                NaiveDateTime::parse_from_str(&t, "%Y-%m-%d %H:%M:%S")
                    .ok()
                    .map(|dt| dt.and_utc())
            }),

            comment: try_get_column(row, "comment")?,
            source: get_column(row, "source")?,

            action: get_column(row, "action")?,
            deny_action: try_get_column(row, "deny_action")?,

            terminate: try_get_column(row, "terminate")?.unwrap_or(false),

            expires: try_get_column(row, "expires")?,

            addr: try_get_column(row, "addr")?,
            cidr: try_get_column(row, "cidr")?,
            user_agent: try_get_column(row, "user_agent")?,
            host: try_get_column(row, "host")?,
            path: try_get_column(row, "path")?,
            method: try_get_column(row, "method")?,
            country_code: try_get_column(row, "country_code")?,
            org: try_get_column(row, "org")?,
            asn: try_get_column(row, "asn")?,
        })
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

impl crate::types::PrimaryKey for Rule {
    type Key = uuid::Uuid;

    fn primary_key(&self) -> Self::Key {
        self.id
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
