//! DNS selectors over the shared route datasets: rule sets and geosite.

use super::*;

#[test]
fn dns_dataset_selectors_project_shared_resources_and_keep_source_order() {
    let mut input = source();
    input["dns"]["nameserver_policy"] = json!([
        {"domain":"+.example.org","servers":[{"type":"tcp","server":"1.1.1.1","server_port":53}]},
        {"domain":"geosite:cn","servers":[{"type":"tcp","server":"223.5.5.5","server_port":53}]},
        {"domain":"special.example.org","servers":[{"type":"tcp","server":"9.9.9.9","server_port":53}]}
    ]);
    input["dns"]["fallback_servers"] = json!([{"type":"udp","server":"8.8.4.4","server_port":53}]);
    input["dns"]["fallback_filter"] = json!({"geoip_code":"cn","geosite":["geolocation-!cn"]});
    input["dns"]["fake_ip"] = json!({"exclude":["geosite:cn"]});
    let output = project(&input, ProjectionMode::LocalProxy);
    assert_eq!(output["dns"]["rules"][0]["domain_suffix"], "example.org");
    assert_eq!(
        output["dns"]["rules"][1]["rule_set"],
        json!(["cfw-geosite-cn"])
    );
    assert_eq!(output["dns"]["rules"][2]["domain"], "special.example.org");
    let resources = output["route"]["rule_set"].as_array().unwrap();
    assert_eq!(resources.len(), 3);
    assert_eq!(
        resources
            .iter()
            .filter(|resource| resource["tag"] == "cfw-geosite-cn")
            .count(),
        1
    );
    assert!(
        output["dns"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|rule| rule["response_ip_accept_all"] == true)
    );
    assert!(output["experimental"]["cache_file"]["enabled"] == true);
    input["dns"]["fallback_filter"]["geoip_code"] = json!("../cn");
    assert!(ValidatedSingBoxProfile::parse(&input.to_string()).is_err());
    // A DNS policy writes its country code in lowercase, unlike a route rule.
    for code in ["CN", "Cn", "c1", "cnn"] {
        input["dns"]["fallback_filter"]["geoip_code"] = json!(code);
        let error = ValidatedSingBoxProfile::parse(&input.to_string()).expect_err(code);
        assert!(
            error
                .to_string()
                .contains("DNS GeoIP code requires a lowercase two-letter country code"),
            "{code}: {error}"
        );
    }
}

#[test]
fn dns_geosite_selectors_share_the_route_dataset_grammar() {
    let with = |code: &str| {
        let mut nameserver = source();
        nameserver["dns"]["nameserver_policy"] = json!([
            {"domain":format!("geosite:{code}"),"servers":[{"type":"tcp","server":"223.6.6.6","server_port":53}]}
        ]);
        let mut fallback = source();
        fallback["dns"]["fallback_servers"] =
            json!([{"type":"udp","server":"8.8.4.4","server_port":53}]);
        fallback["dns"]["fallback_filter"] = json!({"geosite":[code]});
        let mut fake = source();
        fake["dns"]["fake_ip"] = json!({"exclude":[format!("geosite:{code}")]});
        [nameserver, fallback, fake].map(|value| ValidatedSingBoxProfile::parse(&value.to_string()))
    };
    for code in ["cn", "geolocation-!cn", "google@!cn", "category-ads-all"] {
        for result in with(code) {
            assert!(result.is_ok(), "{code}: {result:?}");
        }
    }
    for code in ["!cn", "-cn", "a_b", "cn@", "a@b@c", "CN"] {
        for result in with(code) {
            let error = result.expect_err(code).to_string();
            assert!(
                error.contains("geosite names must be published sing-geosite dataset names"),
                "{code}: {error}"
            );
        }
    }
}

#[test]
fn dns_rule_set_providers_refuse_geosite_conditions_instead_of_panicking() {
    let mut input = source();
    input["providers"] = json!({"rules":[{"name":"sites","source":{"interval_seconds":86400},
    "format":"yaml","behavior":"classical","rules":[
        {"type":"domain_suffix","value":"example.org"},
        {"type":"geo_site","value":"cn"}
    ]}]});
    input["dns"]["nameserver_policy"] = json!([
        {"domain":"rule-set:sites","servers":[{"type":"tcp","server":"223.6.6.6","server_port":53}]}
    ]);
    let error = ValidatedSingBoxProfile::parse(&input.to_string())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("DNS rule-set providers must contain only domain conditions"),
        "{error}"
    );
}
