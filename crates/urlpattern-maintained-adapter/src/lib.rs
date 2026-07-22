//! Security migration adapter for Tauri's `urlpattern 0.3` dependency.
//!
//! The pinned Tauri line still requests the 0.3 API, whose implementation
//! depends on the unmaintained `unic-*` family. URLPattern 0.6 preserves the
//! API surface Tauri uses and replaces that dependency. This crate deliberately
//! contains no behavior of its own and should be removed once Tauri consumes
//! URLPattern 0.6 or newer directly.

pub use urlpattern_upstream::*;
