use crate::geo::CountryCode;
use chrono::DateTime;
use chrono::Utc;
use derive_builder::Builder;

use super::net::IpAddr;

// XXX: should I use actix_web::http::header::HeaderName::from_static()?
pub const X_FORWARDED_FOR: &str = "X-Forwarded-For";
pub const X_FORWARDED_PROTO: &str = "X-Forwarded-Proto";
pub const X_FORWARDED_HOST: &str = "X-Forwarded-Host";
pub const X_FORWARDED_METHOD: &str = "X-Forwarded-Method";
pub const X_FORWARDED_URI: &str = "X-Forwarded-Uri";
pub const USER_AGENT: &str = "User-Agent";

#[derive(Debug, PartialEq, Eq, Builder, serde_derive::Serialize)]
#[builder(setter(into), build_fn(private, name = "build_super"))]
pub struct ForwardedRequest {
    pub addr: IpAddr,
    pub user_agent: String,
    pub host: String,
    pub method: Method,
    pub uri: String,
    pub path: String,
    pub country_code: Option<CountryCode>,
    pub asn: Option<u32>,
    pub org: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub scheme: Scheme,
}

impl ForwardedRequest {
    pub fn builder() -> ForwardedRequestBuilder {
        ForwardedRequestBuilder::default()
    }
}

impl ForwardedRequestBuilder {
    pub fn build(&mut self) -> Result<ForwardedRequest, ForwardedRequestBuilderError> {
        if self.timestamp.is_none() {
            self.timestamp(chrono::Utc::now());
        }

        self.build_super()
    }
}

#[derive(
    Clone,
    Debug,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::EnumIs,
    sqlx::Type,
    serde_derive::Deserialize,
    serde_derive::Serialize,
)]
#[strum(serialize_all = "UPPERCASE")]
#[sqlx(rename_all = "UPPERCASE")]
pub enum Method {
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

impl From<::http::Method> for Method {
    fn from(val: ::http::Method) -> Self {
        match val {
            ::http::Method::GET => Method::Get,
            ::http::Method::PUT => Method::Put,
            ::http::Method::POST => Method::Post,
            ::http::Method::DELETE => Method::Delete,
            ::http::Method::PATCH => Method::Patch,
            ::http::Method::OPTIONS => Method::Options,
            ::http::Method::HEAD => Method::Head,
            ::http::Method::TRACE => Method::Trace,
            ::http::Method::CONNECT => Method::Connect,
            _ => unreachable!(),
        }
    }
}

impl From<Method> for ::http::Method {
    fn from(value: Method) -> Self {
        match value {
            Method::Get => ::http::Method::GET,
            Method::Put => ::http::Method::PUT,
            Method::Post => ::http::Method::POST,
            Method::Delete => ::http::Method::DELETE,
            Method::Patch => ::http::Method::PATCH,
            Method::Options => ::http::Method::OPTIONS,
            Method::Head => ::http::Method::HEAD,
            Method::Trace => ::http::Method::TRACE,
            Method::Connect => ::http::Method::CONNECT,
        }
    }
}

impl Method {
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

impl AsRef<[u8]> for Method {
    fn as_ref(&self) -> &[u8] {
        match self {
            Method::Get => b"GET",
            Method::Put => b"PUT",
            Method::Post => b"POST",
            Method::Delete => b"DELETE",
            Method::Patch => b"PATCH",
            Method::Options => b"OPTIONS",
            Method::Head => b"HEAD",
            Method::Trace => b"TRACE",
            Method::Connect => b"CONNECT",
        }
    }
}

#[derive(
    Clone,
    Debug,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::EnumIs,
    sqlx::Type,
    serde_derive::Deserialize,
    serde_derive::Serialize,
)]
#[strum(serialize_all = "lowercase")]
#[sqlx(rename_all = "lowercase")]
pub enum Scheme {
    Http,
    Https,
}
