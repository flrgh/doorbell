use super::*;
use chrono::{DateTime, Utc};
use std::cmp;

#[derive(Debug, Default)]
pub struct Collection {
    rules: Vec<Rule>,
    version: u64,
    max_conditions: usize,
    next_expiration: Option<DateTime<Utc>>,
}

impl Collection {
    pub fn new(rules: Vec<Rule>, version: u64) -> Self {
        let mut max_conditions = 0;
        let mut next_expiration = None;

        for rule in &rules {
            max_conditions = cmp::max(max_conditions, rule.conditions().len());

            if let Some(expires) = rule.expires {
                match next_expiration {
                    None => next_expiration = Some(expires),
                    Some(ne) => next_expiration = Some(cmp::min(ne, expires)),
                }
            }
        }

        Self {
            rules,
            version,
            max_conditions,
            next_expiration,
        }
    }

    pub fn get_match(&self, req: &ForwardedRequest) -> Option<&Rule> {
        let mut matched: Option<&Rule> = None;

        let iter = self
            .rules
            .iter()
            .filter(|r| !r.is_expired_at(&req.timestamp));

        for rule in iter {
            if rule.matches(req) {
                if rule.terminate || rule.conditions().len() == self.max_conditions {
                    matched = Some(rule);
                    break;
                }

                if let Some(last) = matched {
                    if last.conditions().len() < rule.conditions().len() {
                        matched = Some(rule);
                    }
                }
            }
        }

        matched
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn next_expiration(&self) -> Option<chrono::DateTime<Utc>> {
        self.next_expiration
    }
}
