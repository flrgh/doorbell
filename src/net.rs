use cidr_utils::cidr::IpCidr;
use cidr_utils::utils::IpCidrCombiner;
use std::net::IpAddr;

pub struct TrustedProxies {
    cidr: IpCidrCombiner,
}

impl TrustedProxies {
    pub fn new(cidrs: &Vec<IpCidr>) -> Self {
        let mut combined = IpCidrCombiner::new();
        for cidr in cidrs {
            combined.push(*cidr);
        }

        Self { cidr: combined }
    }

    pub fn is_trusted(&self, addr: &IpAddr) -> bool {
        self.cidr.contains(*addr)
    }

    pub fn get_forwarded_ip(&self, xff: &str) -> Option<IpAddr> {
        let mut last = None;

        for elem in xff.rsplit(',') {
            let elem = elem.trim();

            let Ok(addr) = elem.parse::<IpAddr>() else {
                return None;
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
}
