//! Representative large subscriptions exercise parsing, reference validation,
//! projection, and credential pointers together. Timings are observations, not
//! machine-dependent pass thresholds.
use cfw_singbox_config::{EngineSettings, ProjectionMode, ValidatedSingBoxProfile};
use serde_json::{Value, json};
use std::time::Instant;

fn subscription(nodes: usize, groups: usize) -> Value {
    let tags: Vec<_> = (0..nodes).map(|index| format!("Node-{index:04}")).collect();
    let mut outbounds: Vec<_> = tags.iter().enumerate().map(|(index, tag)| json!({
        "type":"socks5", "tag":tag, "server":"capacity.example.com", "server_port":1080,
        "authentication":{
            "username_credential_ref":{"id":format!("aaaaaaaa-aaaa-4aaa-8aaa-{:012x}",index*2),"kind":"socks5_username"},
            "password_credential_ref":{"id":format!("aaaaaaaa-aaaa-4aaa-8aaa-{:012x}",index*2+1),"kind":"socks5_password"}
        }
    })).collect();
    for index in 0..groups {
        outbounds.push(json!({"type":"selector","tag":format!("Group-{index}"),"outbounds":tags}));
    }
    json!({"outbounds":outbounds,"route":{"final":"Group-0"}})
}

#[test]
fn representative_subscriptions_preserve_nodes_groups_and_credentials() {
    for (nodes, groups) in [(128, 4), (512, 16), (1024, 32)] {
        let input = subscription(nodes, groups).to_string();
        let started = Instant::now();
        let profile = ValidatedSingBoxProfile::parse(&input).expect("representative subscription");
        let parsed = started.elapsed();
        let projected = profile
            .project(
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                ProjectionMode::SystemProxy,
                &EngineSettings::default(),
            )
            .expect("project large subscription");
        assert_eq!(projected.credential_slots().len(), nodes * 2);
        let configuration: Value = serde_json::from_str(projected.as_json()).unwrap();
        let outbounds = configuration["outbounds"].as_array().unwrap();
        for index in 0..groups {
            let tag = format!("Group-{index}");
            let group = outbounds
                .iter()
                .find(|outbound| outbound["tag"] == tag)
                .unwrap();
            assert_eq!(group["outbounds"].as_array().unwrap().len(), nodes);
        }
        eprintln!(
            "capacity nodes={nodes} groups={groups} source_bytes={} projected_bytes={} parse_ms={:.2} total_ms={:.2}",
            input.len(),
            projected.as_json().len(),
            parsed.as_secs_f64() * 1000.0,
            started.elapsed().as_secs_f64() * 1000.0
        );
    }
}

#[test]
fn excessive_nodes_groups_edges_and_dependency_depth_are_rejected() {
    for (nodes, groups) in [(1025, 1), (1, 129), (1024, 33)] {
        assert!(ValidatedSingBoxProfile::parse(&subscription(nodes, groups).to_string()).is_err());
    }
    // Validate both source orders: cached children must not hide total depth.
    for reverse in [false, true] {
        let mut outbounds:Vec<_>=(0..34).map(|i|json!({"type":"selector","tag":format!("g{i}"),"outbounds":[if i==33 {"DIRECT".to_string()} else {format!("g{}",i+1)}]})).collect();
        outbounds.push(json!({"type":"direct","tag":"DIRECT"}));
        if reverse {
            outbounds.reverse();
        }
        let error = ValidatedSingBoxProfile::parse(&json!({"outbounds":outbounds}).to_string())
            .unwrap_err();
        assert!(error.to_string().contains("depth exceeds"));
    }
}
