//! The fields of one Clash proxy, each taken at most once and typed as it is
//! taken; whatever is left over is an error.

use super::{IGNORED_TUNING_KEYS, YamlMapping, YamlScalar, YamlValue, sanitized_token};

/// One proxy entry whose keys are consumed exactly once. Whatever is left
/// after conversion is either a documented tuning key or an error.
pub(super) struct ProxyFields {
    pub(super) context: String,
    pub(super) entries: Vec<(String, YamlValue)>,
}

impl ProxyFields {
    pub(super) fn new(mapping: YamlMapping, context: String) -> Self {
        Self {
            context,
            entries: mapping.into_entries(),
        }
    }

    /// Wraps a nested option mapping (`ws-opts`, `reality-opts`, ...).
    pub(super) fn from_nested(
        value: YamlValue,
        parent: &ProxyFields,
        key: &str,
    ) -> Result<Self, String> {
        let YamlValue::Mapping(mapping) = value else {
            return Err(format!("{}.{key} must be a YAML mapping", parent.context()));
        };
        Ok(Self::new(mapping, format!("{}.{key}", parent.context)))
    }

    pub(super) fn context(&self) -> &str {
        &self.context
    }

    pub(super) fn take(&mut self, key: &str) -> Option<YamlValue> {
        let index = self.entries.iter().position(|(name, _)| name == key)?;
        Some(self.entries.remove(index).1)
    }

    /// Whether `key` holds a non-empty scalar, without taking it.
    pub(super) fn has_text(&self, key: &str) -> bool {
        self.entries.iter().any(|(name, value)| {
            name == key
                && matches!(value, YamlValue::Scalar(scalar) if !scalar.is_null() && !scalar.text().is_empty())
        })
    }

    pub(super) fn take_scalar(&mut self, key: &str) -> Result<Option<YamlScalar>, String> {
        match self.take(key) {
            None => Ok(None),
            Some(YamlValue::Scalar(scalar)) => {
                if scalar.is_null() {
                    Ok(None)
                } else {
                    Ok(Some(scalar))
                }
            }
            Some(_) => Err(format!("{}.{key} must be a scalar value", self.context)),
        }
    }

    /// Takes a key as text, preserving the exact source bytes.
    pub(super) fn take_string(&mut self, key: &str) -> Result<Option<String>, String> {
        Ok(self
            .take_scalar(key)?
            .map(|scalar| scalar.text().to_owned()))
    }

    pub(super) fn require_string(&mut self, key: &str) -> Result<String, String> {
        self.take_string(key)?
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("{}.{key} is missing", self.context))
    }

    /// Takes a key as a YAML boolean. Quoted strings are not booleans.
    pub(super) fn take_bool(&mut self, key: &str) -> Result<Option<bool>, String> {
        match self.take_scalar(key)? {
            None => Ok(None),
            Some(scalar) => scalar
                .as_bool()
                .map(Some)
                .ok_or_else(|| format!("{}.{key} must be a YAML boolean", self.context)),
        }
    }

    pub(super) fn require_port(&mut self) -> Result<u16, String> {
        let text = self.require_string("port")?;
        text.parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| format!("{}.port is not a valid port", self.context))
    }

    pub(super) fn take_string_list(&mut self, key: &str) -> Result<Option<Vec<String>>, String> {
        match self.take(key) {
            None => Ok(None),
            Some(YamlValue::Sequence(items)) => items
                .into_iter()
                .map(|item| match item {
                    YamlValue::Scalar(scalar) if !scalar.is_null() => Ok(scalar.text().to_owned()),
                    _ => Err(format!(
                        "{}.{key} entries must be scalar values",
                        self.context
                    )),
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Some),
            Some(_) => Err(format!("{}.{key} must be a YAML sequence", self.context)),
        }
    }

    pub(super) fn take_string_or_list(&mut self, key: &str) -> Result<Option<Vec<String>>, String> {
        match self.take(key) {
            None => Ok(None),
            Some(YamlValue::Scalar(scalar)) if !scalar.is_null() => {
                Ok(Some(vec![scalar.text().to_owned()]))
            }
            Some(YamlValue::Scalar(_)) => Ok(None),
            Some(YamlValue::Sequence(items)) => items
                .into_iter()
                .map(|item| match item {
                    YamlValue::Scalar(scalar) if !scalar.is_null() => Ok(scalar.text().to_owned()),
                    _ => Err(format!(
                        "{}.{key} entries must be scalar values",
                        self.context
                    )),
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Some),
            Some(_) => Err(format!(
                "{}.{key} must be a scalar or YAML sequence",
                self.context
            )),
        }
    }

    /// Accepts documented tuning keys and fails the import on anything else.
    pub(super) fn reject_leftovers(&mut self) -> Result<(), String> {
        self.entries
            .retain(|(key, _)| !IGNORED_TUNING_KEYS.contains(&key.as_str()));
        if self.entries.is_empty() {
            return Ok(());
        }
        let keys = self
            .entries
            .iter()
            .map(|(key, _)| sanitized_token(key))
            .collect::<Vec<_>>()
            .join(", ");
        Err(format!("{} has unsupported keys: {keys}", self.context))
    }
}
