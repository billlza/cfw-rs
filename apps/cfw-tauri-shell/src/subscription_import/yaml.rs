//! Bounded YAML subset loader for subscription documents.
//!
//! Subscription bodies are untrusted network input, so this loader consumes
//! the low-level event stream directly instead of a document-level YAML
//! library. That keeps every safety decision explicit and local:
//!
//! - exactly one document is accepted;
//! - aliases, anchors, and merge keys are rejected, so no alias-amplification
//!   ("billion laughs") expansion can happen;
//! - container depth and total event count carry hard budgets;
//! - duplicate mapping keys are rejected instead of last-write-wins;
//! - scalars keep their source text. A field consumer decides whether a value
//!   is a string, boolean, or number, so a secret such as `password: 0123`
//!   never loses its exact bytes to YAML number resolution.
//!
//! Only the core-schema `!!str` tag is accepted (it forces plain scalars to
//! stay strings); every other tag fails the import.

use saphyr_parser::{Event, Parser, ScalarStyle, Tag};

use super::sanitized_token;

/// Hard budget on parser events for one subscription document. Source bodies
/// are already capped at `MAX_SUBSCRIPTION_SOURCE_BYTES` (4 MiB) and every
/// event consumes input, so a legitimate document stays far below this bound.
/// The smaller canonical profile limit is enforced after conversion.
const MAX_YAML_EVENTS: usize = 200_000;
/// Hard budget on container nesting. Clash documents need five levels
/// (root → proxies → proxy → ws-opts → headers); sixteen leaves headroom
/// without accepting pathological nesting.
const MAX_YAML_DEPTH: usize = 16;

/// One parsed YAML value with source-preserving scalars.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum YamlValue {
    Scalar(YamlScalar),
    Sequence(Vec<YamlValue>),
    Mapping(YamlMapping),
}

/// A scalar that remembers whether YAML core-schema resolution may apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct YamlScalar {
    text: String,
    /// True only for plain, untagged scalars. Quoted or `!!str`-tagged
    /// scalars are always strings, never `null`, booleans, or numbers.
    resolvable: bool,
}

impl YamlScalar {
    pub(super) fn string(text: String) -> Self {
        Self {
            text,
            resolvable: false,
        }
    }
    /// The exact source text of the scalar.
    pub(super) fn text(&self) -> &str {
        &self.text
    }

    /// True when the scalar is a YAML 1.2 core-schema null.
    pub(super) fn is_null(&self) -> bool {
        self.resolvable && matches!(self.text.as_str(), "" | "~" | "null" | "Null" | "NULL")
    }

    /// The YAML 1.2 core-schema boolean value, when the scalar is one.
    pub(super) fn as_bool(&self) -> Option<bool> {
        if !self.resolvable {
            return None;
        }
        match self.text.as_str() {
            "true" | "True" | "TRUE" => Some(true),
            "false" | "False" | "FALSE" => Some(false),
            _ => None,
        }
    }
}

/// An order-preserving mapping with unique scalar keys.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct YamlMapping {
    entries: Vec<(String, YamlValue)>,
}

impl YamlMapping {
    pub(super) fn get(&self, key: &str) -> Option<&YamlValue> {
        self.entries
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }
    pub(super) fn get_mut(&mut self, key: &str) -> Option<&mut YamlValue> {
        self.entries
            .iter_mut()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }
    pub(super) fn set(&mut self, key: &str, value: YamlValue) {
        if let Some(stored) = self.get_mut(key) {
            *stored = value;
        } else {
            self.entries.push((key.into(), value));
        }
    }
    pub(super) fn into_entries(self) -> Vec<(String, YamlValue)> {
        self.entries
    }
}

impl YamlValue {
    /// A flow-style YAML value, preserving scalar spelling. In particular,
    /// plain `True` used as a password must never become the string `true`.
    fn render(&self) -> String {
        match self {
            Self::Scalar(value) if value.as_bool().is_some() => value.text.clone(),
            Self::Scalar(value) if value.is_null() => "null".into(),
            Self::Scalar(value) => serde_json::to_string(value.text()).expect("string encoding"),
            Self::Sequence(values) => format!(
                "[{}]",
                values
                    .iter()
                    .map(Self::render)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::Mapping(mapping) => format!(
                "{{{}}}",
                mapping
                    .entries
                    .iter()
                    .map(|(key, value)| format!(
                        "{}: {}",
                        serde_json::to_string(key).expect("string encoding"),
                        value.render()
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    pub(super) fn render_document(&self) -> Result<String, String> {
        let Self::Mapping(mapping) = self else {
            return Err("provider profile root must be a mapping".into());
        };
        Ok(mapping
            .entries
            .iter()
            .map(|(key, value)| {
                let key = if key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                {
                    key.clone()
                } else {
                    serde_json::to_string(key).expect("string encoding")
                };
                format!("{key}: {}\n", value.render())
            })
            .collect())
    }
}

/// A container that is still being filled while its events stream in.
enum OpenContainer {
    Sequence(Vec<YamlValue>),
    Mapping {
        mapping: YamlMapping,
        pending_key: Option<String>,
    },
}

/// Parses exactly one bounded YAML document into a [`YamlValue`] tree.
pub(super) fn load_single_document(body: &str) -> Result<YamlValue, String> {
    let mut events = 0_usize;
    let mut document_open = false;
    let mut root: Option<YamlValue> = None;
    let mut stack: Vec<OpenContainer> = Vec::new();

    for step in Parser::new_from_str(body) {
        let (event, _span) =
            step.map_err(|error| format!("subscription YAML is invalid: {error}"))?;
        events += 1;
        if events > MAX_YAML_EVENTS {
            return Err(format!(
                "subscription YAML exceeds the {MAX_YAML_EVENTS}-event budget"
            ));
        }
        match event {
            Event::StreamStart => {}
            Event::StreamEnd => break,
            Event::DocumentStart(_) => {
                if document_open || root.is_some() {
                    return Err("subscription YAML must contain exactly one document".to_owned());
                }
                document_open = true;
            }
            Event::DocumentEnd => document_open = false,
            Event::Alias(_) => {
                return Err("subscription YAML aliases and merge keys are not supported".to_owned());
            }
            Event::Scalar(value, style, anchor_id, tag) => {
                reject_anchor(anchor_id)?;
                let resolvable = style == ScalarStyle::Plain && tag.is_none();
                if let Some(tag) = tag.as_deref()
                    && !is_core_schema_string_tag(tag)
                {
                    return Err("subscription YAML uses an unsupported tag".to_owned());
                }
                // The parser emits empty text for implicit null nodes. Keep the
                // existing importer text/key contract; explicit strings stay
                // empty and must not become the legacy null placeholder.
                let text = if resolvable && value.is_empty() {
                    "~".to_owned()
                } else {
                    value.into_owned()
                };
                let scalar = YamlValue::Scalar(YamlScalar { text, resolvable });
                attach(&mut stack, &mut root, scalar)?;
            }
            Event::SequenceStart(anchor_id, tag) => {
                reject_anchor(anchor_id)?;
                reject_container_tag(tag.as_deref())?;
                open_container(&mut stack, OpenContainer::Sequence(Vec::new()))?;
            }
            Event::MappingStart(anchor_id, tag) => {
                reject_anchor(anchor_id)?;
                reject_container_tag(tag.as_deref())?;
                open_container(
                    &mut stack,
                    OpenContainer::Mapping {
                        mapping: YamlMapping::default(),
                        pending_key: None,
                    },
                )?;
            }
            Event::SequenceEnd => {
                let Some(OpenContainer::Sequence(items)) = stack.pop() else {
                    return Err("subscription YAML sequence events are unbalanced".to_owned());
                };
                attach(&mut stack, &mut root, YamlValue::Sequence(items))?;
            }
            Event::MappingEnd => {
                let Some(OpenContainer::Mapping {
                    mapping,
                    pending_key,
                }) = stack.pop()
                else {
                    return Err("subscription YAML mapping events are unbalanced".to_owned());
                };
                if pending_key.is_some() {
                    return Err("subscription YAML mapping has a key without a value".to_owned());
                }
                attach(&mut stack, &mut root, YamlValue::Mapping(mapping))?;
            }
            Event::Nothing => {
                return Err("subscription YAML produced an unexpected parser event".to_owned());
            }
        }
    }

    root.ok_or_else(|| "subscription YAML document is empty".to_owned())
}

fn reject_anchor(anchor_id: usize) -> Result<(), String> {
    if anchor_id == 0 {
        Ok(())
    } else {
        Err("subscription YAML anchors are not supported".to_owned())
    }
}

fn reject_container_tag(tag: Option<&Tag>) -> Result<(), String> {
    if tag.is_none() {
        Ok(())
    } else {
        Err("subscription YAML uses an unsupported tag".to_owned())
    }
}

fn is_core_schema_string_tag(tag: &Tag) -> bool {
    tag.handle == "tag:yaml.org,2002:" && tag.suffix == "str"
}

fn open_container(stack: &mut Vec<OpenContainer>, container: OpenContainer) -> Result<(), String> {
    if stack.len() >= MAX_YAML_DEPTH {
        return Err(format!(
            "subscription YAML exceeds the nesting depth limit of {MAX_YAML_DEPTH}"
        ));
    }
    if let Some(OpenContainer::Mapping {
        pending_key: None, ..
    }) = stack.last()
    {
        return Err("subscription YAML mapping keys must be scalars".to_owned());
    }
    stack.push(container);
    Ok(())
}

/// Attaches a completed value to its parent container, or makes it the root.
fn attach(
    stack: &mut [OpenContainer],
    root: &mut Option<YamlValue>,
    value: YamlValue,
) -> Result<(), String> {
    match stack.last_mut() {
        None => {
            if root.is_some() {
                return Err("subscription YAML must contain exactly one document".to_owned());
            }
            *root = Some(value);
            Ok(())
        }
        Some(OpenContainer::Sequence(items)) => {
            items.push(value);
            Ok(())
        }
        Some(OpenContainer::Mapping {
            mapping,
            pending_key,
        }) => match pending_key.take() {
            Some(key) => {
                if mapping.entries.iter().any(|(existing, _)| *existing == key) {
                    return Err(format!(
                        "subscription YAML mapping has a duplicate key: {}",
                        sanitized_token(&key)
                    ));
                }
                mapping.entries.push((key, value));
                Ok(())
            }
            None => {
                let YamlValue::Scalar(scalar) = value else {
                    return Err("subscription YAML mapping keys must be scalars".to_owned());
                };
                *pending_key = Some(scalar.text);
                Ok(())
            }
        },
    }
}

#[cfg(test)]
mod tests;
