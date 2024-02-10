use crate::config::Config;
use actix_web::HttpRequest;
use cidr_utils::cidr::IpCidr;
use cidr_utils::utils::IpCidrCombiner;
use std::net::IpAddr;

pub struct TrustedProxies {
    cidr: IpCidrCombiner,
}

impl TrustedProxies {
    pub fn new<T>(cidrs: &Vec<T>) -> Self
    where
        T: AsRef<IpCidr>,
    {
        let mut combined = IpCidrCombiner::new();
        for cidr in cidrs {
            combined.push(*cidr.as_ref());
        }

        Self { cidr: combined }
    }

    pub fn from_config(config: &Config) -> Self {
        Self::new(&config.trusted_proxies)
    }

    pub fn is_trusted(&self, addr: &IpAddr) -> bool {
        self.cidr.contains(*addr)
    }

    pub fn parse_forwarded_ip(&self, xff: &str) -> Option<IpAddr> {
        let mut last = None;

        for elem in xff.rsplit(',') {
            let elem = elem.trim();

            let addr = match elem.parse::<IpAddr>() {
                Ok(addr) => addr,
                Err(e) => {
                    log::info!(
                        "failed to parse X-Forwarded-For '{}' segment '{}': {}",
                        xff,
                        elem,
                        e
                    );
                    return None;
                }
            };

            if let Some(last_addr) = last {
                if self.is_trusted(&last_addr) {
                    last = Some(addr);
                } else {
                    break;
                }
            } else {
                last = Some(addr);
            }
        }

        last
    }

    pub fn get_peer_ip(&self, req: &HttpRequest) -> IpAddr {
        req.peer_addr().expect("failed to acquire client ip").ip()
    }

    pub fn get_client_ip(&self, req: &HttpRequest) -> IpAddr {
        req.headers()
            .get(crate::types::X_FORWARDED_FOR)
            .and_then(|xff| {
                let xff = xff.to_str().ok()?;
                self.parse_forwarded_ip(xff)
            })
            .unwrap_or_else(|| self.get_peer_ip(req))
    }
}
