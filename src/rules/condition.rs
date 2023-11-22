use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqliteRow;
use sqlx::FromRow;
use sqlx::Row;
use sqlx::Type;
use std::cmp::Ordering;
use strum_macros::Display as EnumDisplay;
use strum_macros::EnumIs;
use strum_macros::EnumString;

use crate::geo::*;
use crate::types::*;

pub use crate::geo::CountryCode;
pub use crate::types::Pattern;
pub use cidr::IpCidr;
pub use std::net::IpAddr;
//pub use http::Method as HttpMethod;

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
    EnumIs,
    Serialize,
    Deserialize,
)]
#[strum(serialize_all = "UPPERCASE")]
#[sqlx(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    GET,
    PUT,
    POST,
    DELETE,
    PATCH,
    OPTIONS,
    HEAD,
    TRACE,
    CONNECT,
}

impl From<http::Method> for HttpMethod {
    fn from(val: http::Method) -> Self {
        match val {
            http::Method::GET => HttpMethod::GET,
            http::Method::PUT => HttpMethod::PUT,
            http::Method::POST => HttpMethod::POST,
            http::Method::DELETE => HttpMethod::DELETE,
            http::Method::PATCH => HttpMethod::PATCH,
            http::Method::OPTIONS => HttpMethod::OPTIONS,
            http::Method::HEAD => HttpMethod::HEAD,
            http::Method::TRACE => HttpMethod::TRACE,
            http::Method::CONNECT => HttpMethod::CONNECT,
            _ => unreachable!(),
        }
    }
}

impl From<HttpMethod> for http::Method {
    fn from(value: HttpMethod) -> Self {
        match value {
            HttpMethod::GET => http::Method::GET,
            HttpMethod::PUT => http::Method::PUT,
            HttpMethod::POST => http::Method::POST,
            HttpMethod::DELETE => http::Method::DELETE,
            HttpMethod::PATCH => http::Method::PATCH,
            HttpMethod::OPTIONS => http::Method::OPTIONS,
            HttpMethod::HEAD => http::Method::HEAD,
            HttpMethod::TRACE => http::Method::TRACE,
            HttpMethod::CONNECT => http::Method::CONNECT,
        }
    }
}

impl HttpMethod {
    pub fn is(&self, method: &http::Method) -> bool {
        match *method {
            http::Method::GET => self.is_get(),
            http::Method::PUT => self.is_put(),
            http::Method::POST => self.is_post(),
            http::Method::DELETE => self.is_delete(),
            http::Method::PATCH => self.is_patch(),
            http::Method::OPTIONS => self.is_options(),
            http::Method::HEAD => self.is_head(),
            http::Method::TRACE => self.is_trace(),
            http::Method::CONNECT => self.is_connect(),
            _ => false,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Condition {
    Addr(IpAddr),
    Network(IpCidr),
    UserAgent(Pattern),
    Host(Pattern),
    Path(Pattern),
    CountryCode(CountryCode),
    Method(HttpMethod),
    Asn(u32),
    Org(Pattern),
}

impl Condition {
    pub fn matches(&self, req: &AccessRequest) -> bool {
        match self {
            Condition::Addr(addr) => req.addr.eq(addr),
            Condition::Network(cidr) => cidr.contains(&req.addr),
            Condition::UserAgent(pattern) => pattern.matches(&req.user_agent),
            Condition::Host(pattern) => pattern.matches(&req.host),
            Condition::Path(pattern) => pattern.matches(&req.path),
            Condition::CountryCode(code) => req.country_code == Some(*code),
            Condition::Method(method) => method.is(&req.method),
            Condition::Asn(asn) => req.asn == Some(*asn),
            Condition::Org(pattern) => req.org.as_ref().is_some_and(|org| pattern.matches(org)),
        }
    }
}
