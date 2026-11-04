use std::collections::{BTreeMap, BTreeSet};

use crate::{ConfigError, EngineSettings, ProjectionMode, ValidatedSingBoxProfile};
use serde_json::{Value, json};

mod datasets;
mod latency_probes;
mod resolvers;
mod roles;

const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

fn source() -> Value {
    json!({"outbounds":[{"type":"socks5","tag":"proxy","server":"node.example.com","server_port":1080},{"type":"direct","tag":"direct"}],
        "route":{"final":"proxy","rules":[{"type":"domain","value":"direct.example.com","outbound":"direct"}]},
        "dns":{"servers":[{"type":"tcp","server":"1.1.1.1","server_port":53},{"type":"tcp","server":"8.8.8.8","server_port":53},{"type":"tcp","server":"9.9.9.9","server_port":53}],
        "bootstrap_servers":["223.5.5.5"],
        "nameserver_policy":[{"domain":"+.example.org","servers":[{"type":"tcp","server":"223.6.6.6","server_port":53}]},{"domain":"special.example.org","servers":[{"type":"tcp","server":"119.29.29.29","server_port":53}]}],
        "proxy_servers":[{"type":"tcp","server":"180.76.76.76","server_port":53}],
        "direct_servers":[{"type":"tcp","server":"114.114.114.114","server_port":53}]}})
}

fn project(value: &Value, mode: ProjectionMode) -> Value {
    let profile =
        ValidatedSingBoxProfile::parse(&value.to_string()).expect("validated DNS profile");
    serde_json::from_str(
        profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .expect("projected DNS policy")
            .as_json(),
    )
    .expect("JSON")
}
