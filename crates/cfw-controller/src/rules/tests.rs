use super::*;

#[test]
fn rules_snapshot_decodes_controller_rules() {
    // The pinned handler serializes only type/payload/proxy. Absence of a
    // mihomo-only field must survive as None, never a fabricated 0 or -1.
    let snapshot: RulesSnapshot = serde_json::from_str(include_str!(
        "../../tests/fixtures/sing-box-1.13.15-rules.json"
    ))
    .unwrap();
    assert_eq!(snapshot.rules.len(), 1);
    assert_eq!(snapshot.rules[0].index, None);
    assert_eq!(snapshot.rules[0].kind, "Default");
    assert_eq!(snapshot.rules[0].hits, None);
    assert_eq!(snapshot.rules[0].size, None);
    assert_eq!(snapshot.rules[0].provider, None);
    assert!(snapshot.rules[0].extra.is_empty());
}
