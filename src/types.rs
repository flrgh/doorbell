use crate::geo::*;

use chrono::{DateTime, Utc};
use regex::Regex;
use std::cmp::Ordering;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub(crate) enum Pattern {
    Plain(String),
    Regex(Regex),
}

impl Eq for Pattern {}

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
    pub(crate) fn matches(&self, s: &str) -> bool {
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
pub(crate) struct AccessRequest {
    pub(crate) addr: IpAddr,
    pub(crate) user_agent: String,
    pub(crate) host: String,
    pub(crate) method: http::Method,
    pub(crate) uri: String,
    pub(crate) path: String,
    pub(crate) country_code: Option<CountryCode>,
    pub(crate) asn: Option<u32>,
    pub(crate) org: Option<String>,
    pub(crate) timestamp: DateTime<Utc>,
}
