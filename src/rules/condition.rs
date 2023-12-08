pub use crate::geo::CountryCode;
pub use crate::types::{ForwardedRequest, IpAddr, IpCidr, Method, Pattern};

#[derive(Debug, Eq, PartialEq, Default, Clone)]
pub enum Condition {
    Addr(IpAddr),
    Network(IpCidr),
    UserAgent(Pattern),
    Host(Pattern),
    Path(Pattern),
    CountryCode(CountryCode),
    Method(Method),
    Asn(u32),
    Org(Pattern),
    #[default]
    Any,
}

impl Condition {
    pub fn matches(&self, req: &ForwardedRequest) -> bool {
        match self {
            Condition::Addr(addr) => addr.eq(&req.addr),
            Condition::Network(cidr) => cidr.contains(&req.addr),
            Condition::UserAgent(pattern) => pattern.matches(&req.user_agent),
            Condition::Host(pattern) => pattern.matches(&req.host),
            Condition::Path(pattern) => pattern.matches(&req.path),
            Condition::CountryCode(code) => code.matches(&req.country_code),
            Condition::Method(method) => method == &req.method,
            Condition::Asn(asn) => req.asn == Some(*asn),
            Condition::Org(pattern) => req.org.as_ref().is_some_and(|org| pattern.matches(org)),
            Condition::Any => true,
        }
    }
}

trait Match {
    fn matches(&self, req: &ForwardedRequest) -> bool;
}

impl<T> Match for Option<T>
where
    T: Match,
{
    fn matches(&self, req: &ForwardedRequest) -> bool {
        if let Some(ref m) = self {
            m.matches(req)
        } else {
            true
        }
    }
}

trait FieldMatch {
    type Field;

    fn field_matches(&self, value: &Self::Field) -> bool;

    fn get_field(req: &ForwardedRequest) -> &Self::Field;
}

trait GetField {
    type Field;
}

impl<T, F> Match for T
where
    T: FieldMatch<Field = F>,
{
    fn matches(&self, req: &ForwardedRequest) -> bool {
        let value = <T as FieldMatch>::get_field(req);
        self.field_matches(value)
    }
}

impl FieldMatch for IpAddr {
    type Field = Self;

    fn field_matches(&self, value: &Self::Field) -> bool {
        self.eq(value)
    }

    fn get_field(req: &ForwardedRequest) -> &Self::Field {
        &req.addr
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test() {
        let fr = ForwardedRequest {
            addr: std::net::IpAddr::from([127, 0, 0, 1]).into(),
            user_agent: String::from("user-agent"),
            host: String::from("host"),
            method: crate::types::Method::Get,
            uri: String::from("/uri?a=1&b=2"),
            path: String::from("/path"),
            country_code: Some(CountryCode::US),
            asn: Some(0),
            org: Some(String::from("my-org")),
            timestamp: chrono::Utc::now(),
            scheme: crate::types::Scheme::Https,
        };

        let addr = IpAddr(std::net::IpAddr::from([127, 0, 0, 1]));

        assert!(addr.matches(&fr));
    }
}

pub struct Host;
pub struct UserAgent;
pub struct Path;
pub struct Org;

impl Match for IpCidr {
    fn matches(&self, req: &ForwardedRequest) -> bool {
        self.contains(&req.addr)
    }
}

pub struct PatternMatch<T> {
    pattern: Pattern,
    pd: std::marker::PhantomData<T>,
}

impl Match for PatternMatch<Host> {
    fn matches(&self, req: &ForwardedRequest) -> bool {
        self.pattern.matches(&req.host)
    }
}

impl Match for PatternMatch<UserAgent> {
    fn matches(&self, req: &ForwardedRequest) -> bool {
        self.pattern.matches(&req.user_agent)
    }
}

impl Match for PatternMatch<Path> {
    fn matches(&self, req: &ForwardedRequest) -> bool {
        self.pattern.matches(&req.path)
    }
}

impl Match for PatternMatch<Org> {
    fn matches(&self, req: &ForwardedRequest) -> bool {
        if let Some(ref org) = req.org {
            self.pattern.matches(org)
        } else {
            false
        }
    }
}

pub struct Asn(u32);

impl FieldMatch for Asn {
    type Field = Option<u32>;

    fn field_matches(&self, value: &Self::Field) -> bool {
        if let Some(ref asn) = value {
            &self.0 == asn
        } else {
            false
        }
    }

    fn get_field(req: &ForwardedRequest) -> &Self::Field {
        &req.asn
    }
}
