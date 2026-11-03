use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use super::*;
use crate::test_support::{
    assert_private_directory, assert_private_file, hold_directory_lock, symlink, write_private,
};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn test_store(name: &str) -> (PathBuf, SettingsStore) {
    let root = env::temp_dir().join(format!(
        "cfw-settings-{name}-{}-{}",
        std::process::id(),
        TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let store = SettingsStore::new(AppPaths::from_app_home(root.join("app")));
    (root, store)
}

mod paths;
mod preferences;
mod runtime_documents;
mod window_bounds;
