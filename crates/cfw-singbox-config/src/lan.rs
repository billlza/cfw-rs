//! Optional LAN ingress is separate from local proxy and controller ownership.
use crate::LanProxySettings;
use serde_json::{Value, json};

pub(crate) const LAN_INBOUND_TAG: &str = "cfw-lan-proxy";

pub(crate) fn inbound(settings: &LanProxySettings) -> Value {
    json!({"type":"mixed","tag":LAN_INBOUND_TAG,"listen":settings.listen,"listen_port":settings.port})
}

pub(crate) fn access_rule(settings: &LanProxySettings) -> Value {
    // This rule precedes DNS hijacking and every user/global route. A caller
    // outside the explicitly trusted ranges can never reach an outbound.
    json!({"type":"logical","mode":"and","rules":[{"inbound":[LAN_INBOUND_TAG]},{"source_ip_cidr":settings.allowed_source_cidrs,"invert":true}],"action":"reject"})
}
