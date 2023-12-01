use regex::Regex;
use std::cmp::Ordering;
use std::str::FromStr;

#[derive(Debug, Clone, serde_derive::Deserialize, serde_derive::Serialize)]
#[serde(untagged, try_from = "String", into = "String")]
pub enum Pattern {
    Plain(String),
    Regex(Regex),
}

impl Pattern {
    pub fn matches(&self, s: &str) -> bool {
        match self {
            Pattern::Plain(p) => s == p,
            Pattern::Regex(r) => r.is_match(s),
        }
    }
}

impl Eq for Pattern {}

impl From<Pattern> for String {
    fn from(value: Pattern) -> Self {
        match value {
            Pattern::Plain(s) => s,
            Pattern::Regex(s) => format!("~{}", s.as_str()),
        }
    }
}

impl From<&Pattern> for String {
    fn from(value: &Pattern) -> Self {
        value.clone().into()
    }
}

impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        use Pattern::*;
        match (self, other) {
            (Plain(s), Plain(o)) => s == o,
            (Regex(s), Regex(o)) => s.as_str() == o.as_str(),
            _ => false,
        }
    }
}

impl PartialOrd for Pattern {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        use Pattern::*;

        if self != other {
            match (self, other) {
                (Plain(s), Plain(o)) => s.partial_cmp(o),
                (Regex(s), Regex(o)) => s.as_str().partial_cmp(o.as_str()),
                (Plain(_), Regex(_)) => Some(Ordering::Less),
                (Regex(_), Plain(_)) => Some(Ordering::Greater),
            }
        } else {
            None
        }
    }
}

impl TryFrom<&str> for Pattern {
    type Error = regex::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.strip_prefix('~') {
            Some(re) => Ok(Self::Regex(Regex::new(re)?)),
            None => Ok(Self::Plain(value.to_string())),
        }
    }
}

impl TryFrom<String> for Pattern {
    type Error = regex::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl FromStr for Pattern {
    type Err = regex::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl AsRef<[u8]> for Pattern {
    fn as_ref(&self) -> &[u8] {
        match self {
            Pattern::Plain(p) => p.as_bytes(),
            Pattern::Regex(r) => r.as_str().as_bytes(),
        }
    }
}
