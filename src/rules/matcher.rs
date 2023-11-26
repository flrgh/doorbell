use crate::rules::Rule;

use crate::geo::*;
use crate::rules::condition::*;
use crate::types::*;

#[derive(Default, Debug)]
pub struct Matcher<'a> {
    rules: Vec<&'a Rule>,
    max_conditions: usize,
}

impl<'a> Matcher<'a> {
    pub fn new() -> Self {
        Self {
            rules: vec![],
            max_conditions: 0,
        }
    }

    pub fn update(&'a mut self, rules: &'a Vec<Rule>) {
        self.rules.clear();
        self.rules.reserve_exact(rules.len());

        for rule in rules {
            if rule.is_expired() {
                continue;
            }

            self.rules.push(rule);
            if rule.conditions().len() > self.max_conditions {
                self.max_conditions = rule.conditions().len();
            }
        }

        self.rules.sort();
        self.rules.shrink_to_fit();
    }

    pub fn get_match(&'a self, req: &ForwardedRequest) -> Option<&'a Rule> {
        let mut matched: Option<&'a Rule> = None;

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

    pub fn drop_expired(&mut self) -> usize {
        let before = self.rules.len();
        self.rules.retain(|r| !r.is_expired());

        let dropped = before - self.rules.len();
        if dropped > 0 {
            self.rules.sort();
        }

        dropped
    }
}
