//! Label-based domain patterns used by Clash provider and DNS documents.
use crate::ConfigError;
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainPattern {
    Exact(String),
    Suffix(String),
    Regex(String),
}

impl DomainPattern {
    pub fn parse(pattern: &str) -> Result<Self, ConfigError> {
        let invalid = || ConfigError::UnsupportedPolicyShape {
            path: "domain pattern".into(),
            reason: "expected bounded domain labels, whole-label * wildcards, or a leading +. or ."
                .into(),
        };
        if pattern.is_empty() || pattern.len() > 255 {
            return Err(invalid());
        }
        let pattern = pattern.to_ascii_lowercase();
        let (body, prefix) = if let Some(body) = pattern.strip_prefix("+.") {
            (body, 0)
        } else if let Some(body) = pattern.strip_prefix('.') {
            (body, 1)
        } else {
            (pattern.as_str(), 2)
        };
        let labels = body.split('.').collect::<Vec<_>>();
        if labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || (*label != "*"
                    && (label.starts_with('-')
                        || label.ends_with('-')
                        || !label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')))
        }) {
            return Err(invalid());
        }
        let wildcard = labels.contains(&"*");
        if !wildcard {
            if prefix == 0 {
                return Ok(Self::Suffix(body.into()));
            }
            if prefix == 2 {
                return Ok(Self::Exact(body.into()));
            }
        }
        let body = labels
            .into_iter()
            .map(|label| {
                if label == "*" {
                    "[^.]+".into()
                } else {
                    regex::escape(label)
                }
            })
            .collect::<Vec<String>>()
            .join("\\.");
        let lead = match prefix {
            0 => "(?:[^.]+\\.)*",
            1 => "(?:[^.]+\\.)+",
            _ => "",
        };
        Ok(Self::Regex(format!("(?i)^{lead}{body}\\.?$")))
    }

    /// Trie lookup compares labels from the suffix toward the host: an exact
    /// label precedes a single wildcard, then a suffix wildcard. Stable sort
    /// retains source order for policies of equal specificity.
    pub fn specificity(pattern: &str) -> Vec<u8> {
        pattern
            .split('.')
            .rev()
            .map(|label| match label {
                "+" | "" => 0,
                "*" => 1,
                _ => 2,
            })
            .collect()
    }

    pub fn condition(&self) -> Value {
        match self {
            Self::Exact(value) => json!({"domain":value}),
            Self::Suffix(value) => json!({"domain_suffix":value}),
            Self::Regex(value) => json!({"domain_regex":value}),
        }
    }

    pub fn matches(&self, host: &str) -> Result<bool, ConfigError> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        match self {
            Self::Exact(domain) => Ok(host == *domain),
            Self::Suffix(suffix) => Ok(host == *suffix
                || host
                    .strip_suffix(suffix)
                    .is_some_and(|prefix| prefix.ends_with('.'))),
            Self::Regex(pattern) => regex::Regex::new(pattern)
                .map(|regex| regex.is_match(&host))
                .map_err(|_| ConfigError::UnsupportedPolicyShape {
                    path: "domain pattern".into(),
                    reason: "domain pattern could not be compiled".into(),
                }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn labels_and_apex_have_distinct_wildcard_semantics() {
        for (pattern, matching, excluded) in [
            (
                "*.baidu.com",
                "tieba.baidu.com",
                vec!["baidu.com", "123.tieba.baidu.com"],
            ),
            ("+.baidu.com", "baidu.com", vec!["evilbaidu.com"]),
            (".baidu.com", "123.tieba.baidu.com", vec!["baidu.com"]),
            (
                "*.*.microsoft.com",
                "a.b.microsoft.com",
                vec!["b.microsoft.com", "c.a.b.microsoft.com"],
            ),
        ] {
            let parsed = DomainPattern::parse(pattern).unwrap();
            assert!(parsed.matches(matching).unwrap());
            for host in excluded {
                assert!(!parsed.matches(host).unwrap(), "{pattern} matched {host}");
            }
        }
    }
}
