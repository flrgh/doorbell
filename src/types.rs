use crate::geo::*;

use chrono::{DateTime, Utc};
use regex::Regex;
use std::cmp::Ordering;
use std::net::IpAddr;
use std::fmt::Display;
use sqlx::Type;

#[derive(Debug, Clone)]
pub enum Pattern {
    Plain(String),
    Regex(Regex),
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
