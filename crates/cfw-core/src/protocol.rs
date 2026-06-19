use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum DeepLinkParseError {
    #[error("invalid clash:// URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("unsupported URL scheme: {0}")]
    UnsupportedScheme(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeepLinkAction {
    InstallConfig,
    InstallProfile,
    Quit,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeepLinkIntent {
    pub raw: String,
    pub action: DeepLinkAction,
    pub url: Option<String>,
    pub name: Option<String>,
    pub source: Option<String>,
}

pub fn parse_deep_link(raw: &str) -> Result<DeepLinkIntent, DeepLinkParseError> {
    let parsed = Url::parse(raw)?;
    if parsed.scheme() != "clash" {
        return Err(DeepLinkParseError::UnsupportedScheme(
            parsed.scheme().to_string(),
        ));
    }

    let action = match parsed.host_str().unwrap_or_default() {
        "install-config" => DeepLinkAction::InstallConfig,
        "install-profile" => DeepLinkAction::InstallProfile,
        "quit" => DeepLinkAction::Quit,
        _ => DeepLinkAction::Unknown,
    };
    let pairs = parsed.query_pairs().collect::<Vec<_>>();

    Ok(DeepLinkIntent {
        raw: raw.into(),
        action,
        url: pairs
            .iter()
            .find(|(key, _)| key == "url")
            .map(|(_, value)| value.to_string()),
        name: pairs
            .iter()
            .find(|(key, _)| key == "name")
            .map(|(_, value)| value.to_string()),
        source: pairs
            .iter()
            .find(|(key, _)| key == "source")
            .map(|(_, value)| value.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_install_config() {
        let intent = parse_deep_link(
            "clash://install-config?url=https%3A%2F%2Fexample.com%2Fa.yaml&name=Work",
        )
        .unwrap();
        assert_eq!(intent.action, DeepLinkAction::InstallConfig);
        assert_eq!(intent.url.as_deref(), Some("https://example.com/a.yaml"));
        assert_eq!(intent.name.as_deref(), Some("Work"));
    }

    #[test]
    fn rejects_non_clash_scheme() {
        let err = parse_deep_link("https://example.com").unwrap_err();
        assert!(matches!(err, DeepLinkParseError::UnsupportedScheme(_)));
    }
}
