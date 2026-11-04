//! Test-only failures of chosen storage operations, so the recovery of an
//! interrupted multi-file transaction runs against a real directory.
//!
//! A test scripts the operations it expects, in order. Each storage operation
//! is checked against the next scripted step only: a step that names another
//! operation or entry lets the call through untouched.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;

/// A storage operation a script can intercept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    /// Writing an entry's bytes to its temporary file, before the entry changes.
    Write,
    /// Unlinking an entry.
    Unlink,
    /// Syncing the directory once an entry was renamed into place or unlinked.
    Sync,
}

/// One scripted operation. It fails or passes, and may first run a change
/// made meanwhile, such as another writer that ignores the repository lock.
pub(crate) struct Step {
    operation: Operation,
    entry: Option<String>,
    fails: bool,
    meanwhile: Option<Box<dyn FnOnce()>>,
}

impl Step {
    /// The next `operation` fails.
    pub(crate) fn fail(operation: Operation) -> Self {
        Self {
            operation,
            entry: None,
            fails: true,
            meanwhile: None,
        }
    }

    /// The next `operation` succeeds; the step only marks its place.
    pub(crate) fn pass(operation: Operation) -> Self {
        Self {
            fails: false,
            ..Self::fail(operation)
        }
    }

    /// Limits the step to `operation` on this entry.
    pub(crate) fn on(self, entry: &str) -> Self {
        Self {
            entry: Some(entry.to_owned()),
            ..self
        }
    }

    /// Runs `change` when the step is reached, before the operation.
    pub(crate) fn meanwhile(self, change: impl FnOnce() + 'static) -> Self {
        Self {
            meanwhile: Some(Box::new(change)),
            ..self
        }
    }

    fn matches(&self, operation: Operation, entry: &str) -> bool {
        self.operation == operation && self.entry.as_deref().is_none_or(|name| name == entry)
    }
}

thread_local! {
    static SCRIPT: RefCell<VecDeque<Step>> = const { RefCell::new(VecDeque::new()) };
}

/// The scripted steps of this thread; dropping it discards any not reached.
#[must_use = "the script is discarded when it is dropped"]
pub(crate) struct Script(());

impl Script {
    /// Steps no operation has reached yet.
    pub(crate) fn remaining(&self) -> usize {
        SCRIPT.with(|script| script.borrow().len())
    }
}

impl Drop for Script {
    fn drop(&mut self) {
        SCRIPT.with(|script| script.borrow_mut().clear());
    }
}

/// Scripts the storage operations of this thread.
pub(crate) fn script(steps: impl IntoIterator<Item = Step>) -> Script {
    SCRIPT.with(|script| {
        let mut script = script.borrow_mut();
        assert!(
            script.is_empty(),
            "another failure script is active on this thread"
        );
        script.extend(steps);
    });
    Script(())
}

/// Called by the storage adapter before `operation` on `entry`.
pub(crate) fn check(operation: Operation, entry: &str) -> io::Result<()> {
    let reached = SCRIPT.with(|script| {
        let mut script = script.borrow_mut();
        if script
            .front()
            .is_some_and(|step| step.matches(operation, entry))
        {
            script.pop_front()
        } else {
            None
        }
    });
    let Some(step) = reached else {
        return Ok(());
    };
    if let Some(change) = step.meanwhile {
        change();
    }
    if step.fails {
        Err(io::Error::other(injected(operation, entry)))
    } else {
        Ok(())
    }
}

/// The message of the error a failing step injects.
pub(crate) fn injected(operation: Operation, entry: &str) -> String {
    format!("injected {operation:?} failure of {entry}")
}
