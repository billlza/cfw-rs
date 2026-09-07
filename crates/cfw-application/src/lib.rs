//! Serialized application use cases for the mutually-exclusive network modes.
//!
//! This crate owns product state transitions. It has no dependency on Tauri,
//! Swift, Network Extension, or libbox implementation details.

mod controller;
mod coordinator;
mod coordinator_actor;
mod coordinator_startup;
mod cutover;
mod error;
mod restart;
mod runtime;
mod transition;

pub use controller::EngineControllerAccess;
pub use coordinator::{CoordinatorOptions, CoordinatorTask, EngineModeCoordinator};
pub use error::{EngineCoordinatorError, EngineOperation, RecoveredRuntimeMismatch};
pub use restart::EngineRestartSpec;

#[cfg(test)]
mod tests;
