//! Test-only failures of named lineage cache steps, so each filesystem failure
//! the cache reports can be produced on demand.

use std::cell::RefCell;
use std::io;

thread_local! {
    static FAILING: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
}

/// The steps of this thread that fail once; dropping it discards any not reached.
#[must_use = "the failures are discarded when this is dropped"]
pub(super) struct Failures(());

impl Failures {
    /// Named steps that have not run yet.
    pub(super) fn remaining(&self) -> usize {
        FAILING.with(|failing| failing.borrow().len())
    }
}

impl Drop for Failures {
    fn drop(&mut self) {
        FAILING.with(|failing| failing.borrow_mut().clear());
    }
}

/// Makes each named step fail the next time it runs on this thread.
pub(super) fn fail(steps: &[&'static str]) -> Failures {
    FAILING.with(|failing| {
        let mut failing = failing.borrow_mut();
        assert!(
            failing.is_empty(),
            "another failure set is active on this thread"
        );
        failing.extend_from_slice(steps);
    });
    Failures(())
}

/// Called before each named step.
pub(super) fn check(operation: &str) -> io::Result<()> {
    FAILING.with(|failing| {
        let mut failing = failing.borrow_mut();
        match failing.iter().position(|name| *name == operation) {
            Some(index) => {
                failing.remove(index);
                Err(io::Error::other(format!("injected failure of {operation}")))
            }
            None => Ok(()),
        }
    })
}
