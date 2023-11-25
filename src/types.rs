use crate::geo::*;

use crate::types::Repository as RepoTrait;
use chrono::{DateTime, Utc};
use regex::Regex;
use serde_derive::{Deserialize, Serialize};
use sqlx::Type;
use std::cmp::Ordering;
use std::fmt::Display;
use std::net::IpAddr;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged, try_from = "&str", into = "String")]
pub enum Pattern {
    Plain(String),
    Regex(Regex),
}

fn serialize_regex<S>(regex: &Regex, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    todo!()
}

impl Eq for Pattern {}

impl From<Pattern> for String {
    fn from(value: Pattern) -> Self {
        match value {
            Pattern::Plain(s) => s,
            Pattern::Regex(s) => format!("~{}", s.as_str()),
        }
    }
}

impl From<&Pattern> for String {
    fn from(value: &Pattern) -> Self {
        value.clone().into()
    }
}

impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        use Pattern::*;
        match (self, other) {
            (Plain(s), Plain(o)) => s == o,
            (Regex(s), Regex(o)) => s.as_str() == o.as_str(),
            _ => false,
        }
    }
}

impl PartialOrd for Pattern {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        use Pattern::*;

        if self != other {
            match (self, other) {
                (Plain(s), Plain(o)) => s.partial_cmp(o),
                (Regex(s), Regex(o)) => s.as_str().partial_cmp(o.as_str()),
                (Plain(_), Regex(_)) => Some(Ordering::Less),
                (Regex(_), Plain(_)) => Some(Ordering::Greater),
            }
        } else {
            None
        }
    }
}

impl Pattern {
    pub fn matches(&self, s: &str) -> bool {
        match self {
            Pattern::Plain(p) => s == p,
            Pattern::Regex(r) => r.is_match(s),
        }
    }
}

impl TryFrom<&str> for Pattern {
    type Error = regex::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.strip_prefix('~') {
            Some(re) => Ok(Self::Regex(Regex::new(re)?)),
            None => Ok(Self::Plain(value.to_string())),
        }
    }
}

impl std::str::FromStr for Pattern {
    type Err = regex::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AccessRequest {
    pub addr: IpAddr,
    pub user_agent: String,
    pub host: String,
    pub method: http::Method,
    pub uri: String,
    pub path: String,
    pub country_code: Option<CountryCode>,
    pub asn: Option<u32>,
    pub org: Option<String>,
    pub timestamp: DateTime<Utc>,
}

pub trait PrimaryKey {
    type Key;

    fn primary_key(&self) -> Self::Key;
    fn primary_key_column() -> &'static str;
}

pub trait Update {
    type Updates;

    fn update(&mut self, updates: Self::Updates);
}

use async_trait::async_trait;

#[async_trait]
pub trait Repository<T: Entity> {
    type Err;

    async fn get(&self, id: T::Key) -> Result<Option<T>, Self::Err>;

    async fn get_all(&self) -> Result<Vec<T>, Self::Err>;

    async fn insert(&self, item: T) -> Result<(), Self::Err>;

    async fn upsert(&self, item: T) -> Result<(), Self::Err>;

    async fn update(&self, id: T::Key, updates: T::Updates) -> Result<(), Self::Err>;

    async fn delete(&self, id: T::Key) -> Result<Option<T>, Self::Err>;

    async fn truncate(&self) -> Result<(), Self::Err>;
}

pub trait Validate {
    type Err;

    fn validate(&self) -> Result<(), Self::Err>;
}

pub trait Entity: Validate + PrimaryKey + Update {
    fn table_name() -> &'static str;
}