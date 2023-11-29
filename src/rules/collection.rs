use super::*;

#[derive(Debug, Default)]
pub struct Collection {
    rules: Vec<Rule>,
    version: u64,
    max_conditions: usize,
}

impl Collection {
    pub fn new(rules: Vec<Rule>, version: u64) -> Self {
        let mut max_conditions = 0;

        for rule in &rules {
            if rule.conditions().len() > max_conditions {
                max_conditions = rule.conditions().len();
            }
        }

        Self {
            rules,
            version,
            max_conditions,
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
}
