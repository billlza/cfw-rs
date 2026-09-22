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
                // saphyr 0.1 emits empty text for implicit null nodes. Keep the
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
mod tests {
    use super::*;

    fn scalar(value: &YamlValue) -> &YamlScalar {
        match value {
            YamlValue::Scalar(scalar) => scalar,
            other => panic!("expected scalar, got {other:?}"),
        }
    }

    #[test]
    fn empty_scalar_text_and_resolution_preserve_existing_import_behavior() {
        // Captured against saphyr-parser 0.0.12 before the dependency update.
        // Implicit empties use its legacy null placeholder, while explicit
        // string forms must retain their empty text and never become null.
        for (name, body, text, resolvable, is_null) in [
            ("implicit empty", "value:\n", "~", true, true),
            ("explicit tilde", "value: ~\n", "~", true, true),
            ("double quoted empty", "value: \"\"\n", "", false, false),
            ("single quoted empty", "value: ''\n", "", false, false),
            ("tagged empty", "value: !!str\n", "", false, false),
            ("tagged tilde", "value: !!str ~\n", "~", false, false),
            (
                "tagged quoted empty",
                "value: !!str \"\"\n",
                "",
                false,
                false,
            ),
            ("empty literal", "value: |-\n", "", false, false),
            ("plain null", "value: null\n", "null", true, true),
            ("tagged null", "value: !!str null\n", "null", false, false),
        ] {
            let YamlValue::Mapping(mapping) = load_single_document(body).expect(name) else {
                panic!("{name}: expected a mapping");
            };
            let value = scalar(mapping.get("value").expect("fixture value"));
            assert_eq!(value.text(), text, "{name}: source text");
            assert_eq!(value.resolvable, resolvable, "{name}: resolution flag");
            assert_eq!(value.is_null(), is_null, "{name}: null meaning");
            assert_eq!(value.as_bool(), None, "{name}: not a boolean");
        }
    }

    #[test]
    fn implicit_empty_and_explicit_tilde_keys_remain_duplicates() {
        for body in [
            "?\n: first\n~: second\n",
            "~: first\n?\n: second\n",
            "?\n: first\n?\n: second\n",
            "?\n: first\n\"~\": second\n",
            "?\n: first\n!!str ~: second\n",
            "\"\": first\n'': second\n",
            "? !!str\n: first\n\"\": second\n",
        ] {
            let error = load_single_document(body).expect_err("legacy duplicate key is rejected");
            assert!(error.contains("duplicate key: <redacted>"), "{error}");
            assert!(
                !error.contains("first") && !error.contains("second"),
                "{error}"
            );
        }
    }

    #[test]
    fn implicit_empty_keys_stay_distinct_from_empty_strings_and_null_spelling() {
        for (body, expected_keys) in [
            ("?\n: first\n\"\": second\n", ["~", ""]),
            ("\"\": first\n?\n: second\n", ["", "~"]),
            ("? !!str\n: first\n~: second\n", ["", "~"]),
            ("?\n: first\n? !!str\n: second\n", ["~", ""]),
            ("?\n: first\nnull: second\n", ["~", "null"]),
        ] {
            let YamlValue::Mapping(mapping) = load_single_document(body).expect("distinct keys")
            else {
                panic!("expected a mapping");
            };
            let entries = mapping.into_entries();
            let keys = entries
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>();
            assert_eq!(keys, expected_keys);
            assert_eq!(scalar(&entries[0].1).text(), "first");
            assert_eq!(scalar(&entries[1].1).text(), "second");
        }
    }

    #[test]
    fn container_depth_accepts_sixteen_and_rejects_seventeen() {
        assert_eq!(MAX_YAML_DEPTH, 16);
        let at_limit = "[".repeat(16) + "value" + &"]".repeat(16);
        assert!(load_single_document(&at_limit).is_ok());
        let over_limit = "[".repeat(17) + "value" + &"]".repeat(17);
        let error =
            load_single_document(&over_limit).expect_err("seventeenth container is rejected");
        assert!(error.contains("nesting depth limit of 16"), "{error}");
    }

    #[test]
    fn actual_parser_events_enforce_exact_resource_boundary() {
        assert_eq!(MAX_YAML_EVENTS, 200_000);
        let event_count = |body: &str| {
            Parser::new_from_str(body)
                .map(|step| step.expect("budget fixture must be valid YAML"))
                .count()
        };
        let envelope_events = event_count("[]");
        assert_eq!(event_count("[x]"), envelope_events + 1);
        for target_events in [200_000, 200_001] {
            let scalar_count = target_events - envelope_events;
            let body = format!("[{}]", vec!["x"; scalar_count].join(","));
            assert!(
                body.len() <= 512 * 1024,
                "fixture fits the source-body limit"
            );
            let observed_events = event_count(&body);
            assert_eq!(observed_events, target_events);
            println!(
                "YAML_BUDGET requested={target_events} observed={observed_events} envelope={envelope_events} scalars={scalar_count}"
            );
            match load_single_document(&body) {
                Ok(YamlValue::Sequence(values)) if target_events == MAX_YAML_EVENTS => {
                    assert_eq!(values.len(), scalar_count);
                }
                Err(error) if target_events > MAX_YAML_EVENTS => {
                    assert!(error.contains("200000-event budget"), "{error}");
                }
                other => panic!("unexpected result for {target_events} parser events: {other:?}"),
            }
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
