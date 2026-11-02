//! The profile repository against real private directories: what it stores,
//! lists, selects and replaces, and what it refuses to read.

#[path = "../support/private_file.rs"]
mod private_file_fixture;

mod absent;
#[cfg(target_os = "macos")]
mod byte_limit;
mod credential_snapshot;
mod file_safety;
mod import;
mod invalid_profiles;
#[cfg(target_os = "macos")]
mod lock_wait;
mod replace;
#[cfg(target_os = "macos")]
mod repository_path;
mod selection;
mod support;
mod temporaries;
