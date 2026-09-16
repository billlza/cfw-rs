//! Resource bounds measured by the subscription-capacity fixture. Node, group,
//! and edge budgets are independent so groups do not consume the node allowance.
pub const MAX_PROXY_NODES: usize = 1_024;
pub const MAX_PROXY_GROUPS: usize = 128;
pub const MAX_GROUP_MEMBERSHIPS: usize = 32_768;
pub const MAX_OUTBOUNDS: usize = MAX_PROXY_NODES + MAX_PROXY_GROUPS + 2;
pub const MAX_PROFILE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_ENGINE_CONFIG_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CREDENTIAL_SLOTS: usize = 2 * MAX_PROXY_NODES;
pub const MAX_CREDENTIAL_VAULT_BINDINGS: usize = 8_192;
pub const MAX_SUBSCRIPTION_SOURCE_BYTES: usize = 4 * 1024 * 1024;
