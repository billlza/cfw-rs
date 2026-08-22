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

/// Hard budget on parser events for one subscription document. The transport
/// layer already caps source bodies at 512 KiB and every event consumes input,
/// so a legitimate document stays far below this bound. The smaller canonical
/// profile limit is enforced after conversion.
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
    pub(super) fn into_entries(self) -> Vec<(String, YamlValue)> {
        self.entries
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
                let scalar = YamlValue::Scalar(YamlScalar {
                    text: value.into_owned(),
                    resolvable,
                });
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
mod tests {
    use super::*;

    fn scalar(value: &YamlValue) -> &YamlScalar {
        match value {
            YamlValue::Scalar(scalar) => scalar,
            other => panic!("expected scalar, got {other:?}"),
        }
    }

    #[test]
    fn loads_nested_mappings_sequences_and_scalar_styles() {
        let root = load_single_document(
            "proxies:\n  - name: \"0123\"\n    port: 443\n    quoted: 'true'\n    plain: true\n",
        )
        .expect("document loads");
        let YamlValue::Mapping(root) = root else {
            panic!("root must be a mapping");
        };
        let (key, proxies) = root.into_entries().remove(0);
        assert_eq!(key, "proxies");
        let YamlValue::Sequence(mut proxies) = proxies else {
            panic!("proxies must be a sequence");
        };
        let YamlValue::Mapping(proxy) = proxies.remove(0) else {
            panic!("proxy must be a mapping");
        };
        let entries = proxy.into_entries();
        assert_eq!(scalar(&entries[0].1).text(), "0123");
        assert_eq!(scalar(&entries[0].1).as_bool(), None);
        assert_eq!(scalar(&entries[1].1).text(), "443");
        assert_eq!(
            scalar(&entries[2].1).as_bool(),
            None,
            "quoted true is a string"
        );
        assert_eq!(scalar(&entries[3].1).as_bool(), Some(true));
    }

    #[test]
    fn preserves_leading_zeros_and_numeric_looking_secrets() {
        let root = load_single_document("password: 0123\n").expect("document loads");
        let YamlValue::Mapping(root) = root else {
            panic!("root must be a mapping");
        };
        let entries = root.into_entries();
        assert_eq!(scalar(&entries[0].1).text(), "0123");
    }

    #[test]
    fn accepts_core_schema_string_tag_and_flow_styles() {
        let root =
            load_single_document("{password: !!str 123, alpn: [h3, h2]}").expect("document loads");
        let YamlValue::Mapping(root) = root else {
            panic!("root must be a mapping");
        };
        let entries = root.into_entries();
        let password = scalar(&entries[0].1);
        assert_eq!(password.text(), "123");
        assert!(!password.is_null());
        assert_eq!(password.as_bool(), None);
        let YamlValue::Sequence(alpn) = &entries[1].1 else {
            panic!("alpn must be a sequence");
        };
        assert_eq!(alpn.len(), 2);
    }

    #[test]
    fn recognizes_core_schema_nulls_only_when_plain() {
        let root = load_single_document("a: null\nb: \"null\"\nc: ~\n").expect("document loads");
        let YamlValue::Mapping(root) = root else {
            panic!("root must be a mapping");
        };
        let entries = root.into_entries();
        assert!(scalar(&entries[0].1).is_null());
        assert!(!scalar(&entries[1].1).is_null());
        assert!(scalar(&entries[2].1).is_null());
    }

    #[test]
    fn rejects_aliases_anchors_and_merge_keys() {
        let alias = load_single_document("base: &a {x: 1}\nother: *a\n")
            .expect_err("aliases must be rejected");
        assert!(alias.contains("anchors are not supported"), "{alias}");
        let merge = load_single_document("base: {x: 1}\nother:\n  <<: *missing\n")
            .expect_err("merge aliases must be rejected");
        assert!(
            merge.contains("aliases and merge keys") || merge.contains("invalid"),
            "{merge}"
        );
    }

    #[test]
    fn rejects_duplicate_keys_without_echoing_long_content() {
        let error = load_single_document("name: a\nname: b\n")
            .expect_err("duplicate keys must be rejected");
        assert!(error.contains("duplicate key: <redacted>"), "{error}");
        assert!(!error.contains("name"), "{error}");
        let secret_like = "x".repeat(64);
        let error = load_single_document(&format!("{secret_like}: a\n{secret_like}: b\n"))
            .expect_err("duplicate keys must be rejected");
        assert!(error.contains("<redacted>"), "{error}");
        assert!(!error.contains(&secret_like), "{error}");
    }

    #[test]
    fn rejects_multiple_documents_unknown_tags_and_deep_nesting() {
        let multi = load_single_document("---\na: 1\n---\nb: 2\n")
            .expect_err("multi-document streams must be rejected");
        assert!(multi.contains("exactly one document"), "{multi}");

        let tagged = load_single_document("a: !!binary Zm9v\n")
            .expect_err("non-string tags must be rejected");
        assert!(tagged.contains("unsupported tag"), "{tagged}");

        let nested = "[".repeat(20) + &"]".repeat(20);
        let error = load_single_document(&nested).expect_err("deep nesting must be rejected");
        assert!(error.contains("nesting depth"), "{error}");
    }

    #[test]
    fn rejects_non_scalar_mapping_keys_and_empty_documents() {
        let complex =
            load_single_document("? [a, b]\n: c\n").expect_err("complex keys must be rejected");
        assert!(complex.contains("keys must be scalars"), "{complex}");
        let empty = load_single_document("").expect_err("empty documents must be rejected");
        assert!(empty.contains("empty"), "{empty}");
    }
}
