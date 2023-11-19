use std::net::IpAddr;
//use std::collections::HashMap;
use chrono::prelude::*;
use cidr::IpCidr;
//use uuid::Uuid;
use sqlx::FromRow;
use std::cmp::Ordering;
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
    pub fn matches(&self, req: &AccessRequest) -> bool {
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
