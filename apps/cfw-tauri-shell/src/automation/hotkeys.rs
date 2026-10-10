//! Stage newly registered keys, remove retired keys, then commit preferences.
//! A failed operation restores only registrations changed by that operation.
use super::policy::ShortcutAction;
use tauri::AppHandle;
use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut};

pub(super) trait KeyRegistry {
    fn register(&self, key: Shortcut) -> Result<(), String>;
    fn unregister(&self, key: Shortcut) -> Result<(), String>;
}
impl KeyRegistry for AppHandle {
    fn register(&self, key: Shortcut) -> Result<(), String> {
        self.global_shortcut()
            .register(key)
            .map_err(|error| format!("shortcut registration failed: {error}"))
    }
    fn unregister(&self, key: Shortcut) -> Result<(), String> {
        self.global_shortcut()
            .unregister(key)
            .map_err(|error| format!("shortcut removal failed: {error}"))
    }
}

pub(super) struct KeyChangeError {
    pub message: String,
    pub restored: bool,
}

impl KeyChangeError {
    pub(super) fn preserved(message: String) -> Self {
        Self {
            message,
            restored: true,
        }
    }

    pub(super) fn uncertain(message: String) -> Self {
        Self {
            message,
            restored: false,
        }
    }
}

pub(super) fn replace_keys<R: KeyRegistry>(
    registry: &R,
    previous: &[(Shortcut, ShortcutAction)],
    next: &[(Shortcut, ShortcutAction)],
    commit: impl FnOnce() -> Result<(), KeyChangeError>,
) -> Result<(), KeyChangeError> {
    let old: std::collections::BTreeSet<_> = previous.iter().map(|(key, _)| key.id()).collect();
    let new: std::collections::BTreeSet<_> = next.iter().map(|(key, _)| key.id()).collect();
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let result = (|| {
        for (key, _) in next {
            if !old.contains(&key.id()) {
                registry.register(*key).map_err(KeyChangeError::preserved)?;
                added.push(*key);
            }
        }
        for (key, _) in previous {
            if !new.contains(&key.id()) {
                registry
                    .unregister(*key)
                    .map_err(KeyChangeError::preserved)?;
                removed.push(*key);
            }
        }
        commit()
    })();
    if let Err(error) = result {
        let mut failures = Vec::new();
        for key in added.into_iter().rev() {
            if let Err(error) = registry.unregister(key) {
                failures.push(error)
            }
        }
        for key in removed {
            if let Err(error) = registry.register(key) {
                failures.push(error)
            }
        }
        return Err(KeyChangeError {
            restored: error.restored && failures.is_empty(),
            message: if failures.is_empty() {
                error.message
            } else {
                format!(
                    "{}; shortcut restoration failed: {}",
                    error.message,
                    failures.join("; ")
                )
            },
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::BTreeSet};
    struct Registry {
        keys: RefCell<BTreeSet<u32>>,
        occupied: u32,
    }
    impl KeyRegistry for Registry {
        fn register(&self, key: Shortcut) -> Result<(), String> {
            if key.id() == self.occupied {
                return Err("occupied".into());
            }
            assert!(self.keys.borrow_mut().insert(key.id()));
            Ok(())
        }
        fn unregister(&self, key: Shortcut) -> Result<(), String> {
            assert!(self.keys.borrow_mut().remove(&key.id()));
            Ok(())
        }
    }
    #[test]
    fn collisions_and_storage_failure_preserve_previous_registrations() {
        let first: Shortcut = "Control+Shift+A".parse().unwrap();
        let second: Shortcut = "Control+Shift+B".parse().unwrap();
        let third: Shortcut = "Control+Shift+C".parse().unwrap();
        let previous = [(first, ShortcutAction::ShowDashboard)];
        let registry = Registry {
            keys: RefCell::new([first.id()].into()),
            occupied: third.id(),
        };
        let error = replace_keys(
            &registry,
            &previous,
            &[
                (second, ShortcutAction::ToggleCore),
                (third, ShortcutAction::ToggleTunnel),
            ],
            || panic!("cannot commit a partial registration"),
        )
        .unwrap_err();
        assert!(error.restored);
        assert_eq!(*registry.keys.borrow(), [first.id()].into());
        let error = replace_keys(
            &registry,
            &previous,
            &[(second, ShortcutAction::ToggleCore)],
            || Err(KeyChangeError::preserved("store conflict".into())),
        )
        .unwrap_err();
        assert!(error.restored);
        assert_eq!(*registry.keys.borrow(), [first.id()].into());

        let error = replace_keys(
            &registry,
            &previous,
            &[(second, ShortcutAction::ToggleCore)],
            || {
                Err(KeyChangeError::uncertain(
                    "preference restoration failed".into(),
                ))
            },
        )
        .unwrap_err();
        assert!(
            !error.restored,
            "restored keys cannot prove storage was restored"
        );
        assert_eq!(*registry.keys.borrow(), [first.id()].into());
    }
}
