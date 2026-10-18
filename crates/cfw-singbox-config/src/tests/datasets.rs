use serde_json::json;

use crate::datasets::{CountryCode, Dataset, GeositeCode, MAX_GEO_DATASETS};

/// Names SagerNet/sing-geosite publishes (rule-set branch, read 2026-10-15),
/// including attribute lists and their `@!` negations.
const PUBLISHED: &[&str] = &[
    "cn",
    "geolocation-!cn",
    "geolocation-cn",
    "category-ads-all",
    "google@cn",
    "google@!cn",
    "category-companies@!cn",
];

/// Edge shapes the grammar admits that no published name is claimed to take:
/// a digits-only list name and a list name ending in `!`. A well-formed name
/// that is not published passes validation and fails at its download.
const GRAMMAR_ONLY: &[&str] = &["0", "cn!"];

const REFUSED: &[&str] = &[
    "", "CN", "Cn", "!cn", "-cn", "_cn", "a_b", "@cn", "cn@", "cn@!", "cn@!!x", "cn@-x", "cn@_x",
    "a@b@c", "cn@x@y", "../cn", "cn..x", "cn.x", "cn/x", "cn\\x", "cn%2fx", "cn?x", "cn#x", "{cn}",
    "cn:x", "c n", " cn", "cn\n", "中国",
];

#[test]
fn geosite_codes_admit_the_published_grammar() {
    for code in PUBLISHED.iter().chain(GRAMMAR_ONLY) {
        assert_eq!(
            GeositeCode::parse(code).as_ref().map(GeositeCode::as_str),
            Some(*code),
            "{code}"
        );
    }
    for code in REFUSED {
        assert_eq!(GeositeCode::parse(code), None, "{code:?}");
    }
    let longest = "a".repeat(96);
    assert!(GeositeCode::parse(&longest).is_some());
    assert!(GeositeCode::parse(&"a".repeat(97)).is_none());
    let attributed = format!("{}@b", "a".repeat(94));
    assert_eq!(attributed.len(), 96);
    assert!(GeositeCode::parse(&attributed).is_some());
    assert!(GeositeCode::parse(&format!("{}@b", "a".repeat(95))).is_none());
}

/// Every string of up to three characters over an alphabet that mixes the
/// legal characters with path, query, case and whitespace hazards agrees with
/// an independent regular-expression oracle of the published grammar.
#[test]
fn geosite_grammar_matches_an_independent_oracle_exhaustively() {
    let oracle = regex::Regex::new(r"^[a-z0-9][a-z0-9!-]*(@!?[a-z0-9][a-z0-9-]*)?$").unwrap();
    let alphabet = [
        'a', 'z', '0', '9', '-', '_', '!', '@', '.', '/', '%', '?', '#', '{', ':', ' ', 'A', '\t',
    ];
    let mut checked = 0;
    let mut accepted = 0;
    let mut buffer = String::new();
    let mut visit = |text: &str| {
        let expected = oracle.is_match(text) && !text.is_empty() && text.len() <= 96;
        assert_eq!(GeositeCode::parse(text).is_some(), expected, "{text:?}");
        checked += 1;
        accepted += usize::from(expected);
    };
    for first in alphabet {
        buffer.clear();
        buffer.push(first);
        visit(&buffer);
        for second in alphabet {
            buffer.truncate(1);
            buffer.push(second);
            visit(&buffer);
            for third in alphabet {
                buffer.truncate(2);
                buffer.push(third);
                visit(&buffer);
            }
        }
    }
    assert_eq!(checked, 18 + 18 * 18 + 18 * 18 * 18);
    assert!(
        accepted > 100,
        "the oracle must accept a real share: {accepted}"
    );
}

/// The resources are byte-identical to the literals routing and DNS
/// projection built before the shared helper existed.
#[test]
fn dataset_resources_equal_the_previous_literals() {
    let geoip = Dataset::GeoIp(CountryCode::parse("CN").unwrap());
    assert_eq!(geoip.tag(), "cfw-geoip-cn");
    assert_eq!(
        serde_json::to_string(&geoip.resource("PROXY")).unwrap(),
        serde_json::to_string(&json!({
            "type": "remote",
            "tag": "cfw-geoip-cn",
            "format": "binary",
            "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
            "download_detour": "PROXY",
            "update_interval": "1d",
        }))
        .unwrap()
    );
    let geosite = Dataset::GeoSite(GeositeCode::parse("geolocation-!cn").unwrap());
    assert_eq!(geosite.tag(), "cfw-geosite-geolocation-!cn");
    assert_eq!(
        serde_json::to_string(&geosite.resource("cfw-proxy-selector")).unwrap(),
        serde_json::to_string(&json!({"type":"remote","tag":"cfw-geosite-geolocation-!cn","format":"binary",
            "url":"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs",
            "download_detour":"cfw-proxy-selector","update_interval":"1d"}))
        .unwrap()
    );
    // GeoIP sorts before GeoSite, then by name: the order resources keep.
    let mut ordered = [
        Dataset::GeoSite(GeositeCode::parse("cn").unwrap()),
        Dataset::GeoIp(CountryCode::parse("us").unwrap()),
        Dataset::GeoIp(CountryCode::parse("CN").unwrap()),
    ];
    ordered.sort();
    assert_eq!(
        ordered.iter().map(Dataset::tag).collect::<Vec<_>>(),
        ["cfw-geoip-cn", "cfw-geoip-us", "cfw-geosite-cn"]
    );
    assert_eq!(MAX_GEO_DATASETS, 256);
}

/// A GeoIP dataset name is two ASCII letters, kept in lowercase as
/// SagerNet/sing-geoip names its sets: route rules write the code in
/// uppercase and DNS policies in lowercase, and both name the same set.
#[test]
fn country_codes_are_two_ascii_letters_kept_in_lowercase() {
    for (code, name) in [("CN", "cn"), ("cn", "cn"), ("Us", "us"), ("zz", "zz")] {
        assert_eq!(
            CountryCode::parse(code).as_ref().map(CountryCode::as_str),
            Some(name),
            "{code}"
        );
    }
    for code in [
        "", "c", "cnn", "LAN", "c1", "1c", "c-", "c/", "..", "c.", "c ", " c", "c\n", "é", "中",
        "中国",
    ] {
        assert_eq!(CountryCode::parse(code), None, "{code:?}");
    }
}
