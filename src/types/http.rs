use crate::geo::CountryCode;
use chrono::prelude::*;
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqliteRow;
use sqlx::FromRow;
use sqlx::Row;
use sqlx::Type;
use std::cmp::Ordering;
use std::fmt::Display;
use std::net::IpAddr;
use strum_macros::Display as EnumDisplay;
use strum_macros::EnumIs;
use strum_macros::EnumString;

#[derive(Debug, PartialEq, Eq)]
pub struct ForwardedRequest {
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

#[derive(
    Clone,
    PartialOrd,
    Ord,
    EnumDisplay,
    EnumString,
    Type,
    EnumIs,
    Serialize,
    Deserialize,
    Debug,
    Eq,
    PartialEq,
)]
#[strum(serialize_all = "UPPERCASE")]
#[sqlx(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Put,
    Post,
    Delete,
    Patch,
    Options,
    Head,
    Trace,
    Connect,
}

impl From<::http::Method> for HttpMethod {
    fn from(val: ::http::Method) -> Self {
        match val {
            ::http::Method::GET => HttpMethod::Get,
            ::http::Method::PUT => HttpMethod::Put,
            ::http::Method::POST => HttpMethod::Post,
            ::http::Method::DELETE => HttpMethod::Delete,
            ::http::Method::PATCH => HttpMethod::Patch,
            ::http::Method::OPTIONS => HttpMethod::Options,
            ::http::Method::HEAD => HttpMethod::Head,
            ::http::Method::TRACE => HttpMethod::Trace,
            ::http::Method::CONNECT => HttpMethod::Connect,
            _ => unreachable!(),
        }
    }
}

impl From<HttpMethod> for ::http::Method {
    fn from(value: HttpMethod) -> Self {
        match value {
            HttpMethod::Get => ::http::Method::GET,
            HttpMethod::Put => ::http::Method::PUT,
            HttpMethod::Post => ::http::Method::POST,
            HttpMethod::Delete => ::http::Method::DELETE,
            HttpMethod::Patch => ::http::Method::PATCH,
            HttpMethod::Options => ::http::Method::OPTIONS,
            HttpMethod::Head => ::http::Method::HEAD,
            HttpMethod::Trace => ::http::Method::TRACE,
            HttpMethod::Connect => ::http::Method::CONNECT,
        }
    }
}

impl HttpMethod {
    pub fn is(&self, method: &::http::Method) -> bool {
        match *method {
            ::http::Method::GET => self.is_get(),
            ::http::Method::PUT => self.is_put(),
            ::http::Method::POST => self.is_post(),
            ::http::Method::DELETE => self.is_delete(),
            ::http::Method::PATCH => self.is_patch(),
            ::http::Method::OPTIONS => self.is_options(),
            ::http::Method::HEAD => self.is_head(),
            ::http::Method::TRACE => self.is_trace(),
            ::http::Method::CONNECT => self.is_connect(),
            _ => false,
        }
    }
}
