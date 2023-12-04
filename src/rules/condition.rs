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
            Condition::Network(cidr) => cidr.contains(req.addr),
            Condition::UserAgent(pattern) => pattern.matches(&req.user_agent),
            Condition::Host(pattern) => pattern.matches(&req.host),
            Condition::Path(pattern) => pattern.matches(&req.path),
            Condition::CountryCode(code) => code.matches(&req.country_code),
            Condition::Method(method) => method.is(&req.method),
            Condition::Asn(asn) => req.asn == Some(*asn),
            Condition::Org(pattern) => req.org.as_ref().is_some_and(|org| pattern.matches(org)),
            Condition::Any => true,
        }
    }
}
