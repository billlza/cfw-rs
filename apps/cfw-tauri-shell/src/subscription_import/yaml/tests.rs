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
        // A block scalar with no content lines has no line break to clip.
        ("empty clipped literal", "value: |\n", "", false, false),
        ("empty folded", "value: >\n", "", false, false),
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
        let YamlValue::Mapping(mapping) = load_single_document(body).expect("distinct keys") else {
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
fn a_nul_character_fails_the_document_instead_of_ending_it() {
    // A parser that reads NUL as the end of input would import the first
    // mapping entry and silently drop everything after it.
    for body in ["a: 1\n\0b: 2\n", "a: 1\0\nb: 2\n", "a: \"1\0\"\n", "\0"] {
        let error = load_single_document(body).expect_err("NUL must fail the document");
        assert!(
            error.starts_with("subscription YAML is invalid: "),
            "{body:?}: {error}"
        );
    }
}

#[test]
fn a_byte_order_mark_is_accepted_only_before_the_document() {
    let YamlValue::Mapping(mapping) =
        load_single_document("\u{feff}a: 1\n").expect("a leading byte order mark is skipped")
    else {
        panic!("expected a mapping");
    };
    assert_eq!(
        mapping.into_entries()[0].0,
        "a",
        "the mark is not part of the key"
    );

    // Anywhere else the mark would become an invisible part of a key or a
    // value, so the document fails.
    for body in ["a: 1\n\u{feff}b: 2\n", "a: \u{feff}1\n", "a: [\u{feff}]\n"] {
        let error = load_single_document(body).expect_err("a byte order mark inside a document");
        assert!(error.contains("byte order mark"), "{body:?}: {error}");
    }
}

#[test]
fn a_flow_sequence_pair_keeps_a_flow_mapping_value_whole() {
    // `[a: {b: c, d: e}, f]` holds the single-pair mapping `a: {b: c, d: e}`
    // and the string `f`. The pair must not end at the comma inside its value.
    let root = load_single_document("[a: {b: c, d: e}, f]").expect("document loads");
    let YamlValue::Sequence(items) = root else {
        panic!("expected a sequence");
    };
    assert_eq!(items.len(), 2);
    let YamlValue::Mapping(pair) = &items[0] else {
        panic!("expected a single-pair mapping");
    };
    let Some(YamlValue::Mapping(value)) = pair.get("a") else {
        panic!("expected the pair's value to be a mapping");
    };
    assert_eq!(scalar(value.get("b").expect("first entry")).text(), "c");
    assert_eq!(scalar(value.get("d").expect("second entry")).text(), "e");
    assert_eq!(scalar(&items[1]).text(), "f");
}

#[test]
fn container_depth_accepts_sixteen_and_rejects_seventeen() {
    assert_eq!(MAX_YAML_DEPTH, 16);
    let at_limit = "[".repeat(16) + "value" + &"]".repeat(16);
    assert!(load_single_document(&at_limit).is_ok());
    let over_limit = "[".repeat(17) + "value" + &"]".repeat(17);
    let error = load_single_document(&over_limit).expect_err("seventeenth container is rejected");
    assert!(error.contains("nesting depth limit of 16"), "{error}");
}

#[test]
fn actual_parser_events_enforce_exact_resource_boundary() {
    assert_eq!(MAX_YAML_EVENTS, 200_000);
    let event_count = |body: &str| {
        Parser::new_from_str(body).fold(0, |count, step| {
            step.expect("budget fixture must be valid YAML");
            count + 1
        })
    };
    let envelope_events = event_count("[]");
    assert_eq!(event_count("[x]"), envelope_events + 1);
    for target_events in [200_000, 200_001] {
        let scalar_count = target_events - envelope_events;
        let body = format!("[{}]", vec!["x"; scalar_count].join(","));
        assert!(
            body.len() <= cfw_singbox_config::MAX_SUBSCRIPTION_SOURCE_BYTES,
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
    let alias =
        load_single_document("base: &a {x: 1}\nother: *a\n").expect_err("aliases must be rejected");
    assert!(alias.contains("anchors are not supported"), "{alias}");
    // A defined anchor is refused before its alias; an alias without one is
    // refused by the parser itself.
    let merge = load_single_document("base: {x: 1}\nother:\n  <<: *missing\n")
        .expect_err("merge aliases must be rejected");
    assert!(
        merge.starts_with("subscription YAML is invalid: ") && merge.contains("unknown anchor"),
        "{merge}"
    );
}

#[test]
fn rejects_duplicate_keys_without_echoing_long_content() {
    let error =
        load_single_document("name: a\nname: b\n").expect_err("duplicate keys must be rejected");
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

    let tagged =
        load_single_document("a: !!binary Zm9v\n").expect_err("non-string tags must be rejected");
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

#[test]
fn rejects_tagged_containers_and_mapping_keys() {
    for body in ["a: !!map {b: 1}\n", "a: !!seq [1]\n"] {
        assert_eq!(
            load_single_document(body).map(|_| ()),
            Err("subscription YAML uses an unsupported tag".into()),
            "{body}"
        );
    }
    assert_eq!(
        load_single_document("? {a: 1}\n: b\n").map(|_| ()),
        Err("subscription YAML mapping keys must be scalars".into())
    );
}

#[test]
fn set_replaces_a_key_in_place_and_rendering_quotes_what_is_not_a_plain_key() {
    let YamlValue::Mapping(mut mapping) =
        load_single_document("a: 1\n'b c': 2\n").expect("mapping")
    else {
        panic!("a mapping root");
    };
    mapping.set("a", YamlValue::Scalar(YamlScalar::string("3".into())));
    mapping.set("d", YamlValue::Scalar(YamlScalar::string("4".into())));
    assert_eq!(
        YamlValue::Mapping(mapping).render_document().as_deref(),
        Ok("a: \"3\"\n\"b c\": \"2\"\nd: \"4\"\n")
    );
    assert_eq!(
        YamlValue::Sequence(Vec::new()).render_document(),
        Err("provider profile root must be a mapping".into())
    );
}
