//! The profile repository against real private directories: what it stores,
//! lists, selects and replaces, and what it refuses to read.

#[path = "../support/private_file.rs"]
mod private_file_fixture;

mod credential_snapshot;
mod file_safety;
mod import;
mod invalid_profiles;
mod replace;
mod selection;
mod support;
mod temporaries;
