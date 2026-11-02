//! Rust-side adapter for the signed macOS networking boundary.
//!
//! The product coordinator depends only on `cfw-engine-api`; this crate maps
//! native Host Bridge and ProxyAgent failures into stable domain errors. The
//! eventual C ABI transport must implement [`NativeBridge`] without exposing
//! Swift, XPC, Network Extension, or libbox details to the application layer.

mod backend;
mod bridge;
mod error;
mod generation_store;
mod missing_bridge;
mod native_bridge;
#[cfg(test)]
mod test_support;

pub use backend::AppleNetworkBackend;
pub use bridge::{NativeBridge, NativeBridgeFuture};
pub use error::{NativeBridgeError, NativeBridgeErrorCode};
pub use generation_store::{GenerationStoreError, KeychainEngineGenerationStore};
pub use missing_bridge::MissingNativeBridge;
pub use native_bridge::{NATIVE_BRIDGE_OUTER_WATCHDOG, NativeFrameworkBridge};
