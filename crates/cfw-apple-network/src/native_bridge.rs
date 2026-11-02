//! The native Host Bridge over the versioned C ABI of the signed framework:
//! loading it, invoking it under a watchdog, and the commands sent through it.

use std::sync::Arc;

use crate::native_bridge::abi::LoadedABI;

mod abi;
mod budget;
mod commands;
mod credentials;
#[cfg(test)]
mod fake_native;
mod invoke;
mod services;
mod transport;

pub use budget::NATIVE_BRIDGE_OUTER_WATCHDOG;

#[derive(Clone)]
pub struct NativeFrameworkBridge {
    state: Arc<BridgeState>,
}

enum BridgeState {
    Available(LoadedABI),
    Unavailable(String),
}

impl std::fmt::Debug for NativeFrameworkBridge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeFrameworkBridge")
            .field("available", &self.is_available())
            .finish_non_exhaustive()
    }
}

impl NativeFrameworkBridge {
    /// Resolves the versioned ABI from the linked image or the fixed framework
    /// location inside the current application bundle. No environment or
    /// user-controlled search path is accepted.
    pub fn load() -> Self {
        match LoadedABI::load() {
            Ok(abi) => Self {
                state: Arc::new(BridgeState::Available(abi)),
            },
            Err(message) => Self {
                state: Arc::new(BridgeState::Unavailable(message)),
            },
        }
    }

    pub fn is_available(&self) -> bool {
        matches!(self.state.as_ref(), BridgeState::Available(_))
    }

    pub fn unavailable_reason(&self) -> Option<&str> {
        match self.state.as_ref() {
            BridgeState::Available(_) => None,
            BridgeState::Unavailable(message) => Some(message),
        }
    }
}
