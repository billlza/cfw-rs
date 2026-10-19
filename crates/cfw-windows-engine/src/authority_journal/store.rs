use super::*;
use cfw_windows_storage::{
    EntryKind, MachineRecordError, MachineRecordGuard, PrivateDirectory, PrivateMachineRecord,
    Publication, ReadPolicy, WriteTransaction,
};
use std::{ffi::OsStr, path::Path, time::Duration};
use uuid::Uuid;

const MARKER: &str = "authority-store-v1";
const MARKER_TEMP: &str = ".authority-store-v1.tmp";
const MAX_ENTRIES: usize = 16;
const LOCK_WAIT: Duration = Duration::from_secs(3);
type Result<T> = std::result::Result<T, JournalStoreError>;

#[derive(Debug, thiserror::Error)]
pub enum JournalStoreError {
    #[error("authority journal requires recovery: {0}")]
    Validation(#[from] JournalValidationError),
    #[error("authority journal private storage: {0}")]
    Storage(#[from] cfw_windows_storage::Error),
    #[error("authority journal independent anchor: {0}")]
    Anchor(#[from] MachineRecordError),
    #[error("authority journal marker, anchor, or generation entry is missing or unexpected")]
    StoreIdentity,
    #[error("authority journal capacity cannot finish another lifecycle")]
    Capacity,
    #[error("authority journal operation failed ({operation}); lock release failed ({cleanup})")]
    Cleanup {
        operation: Box<Self>,
        cleanup: Box<Self>,
    },
    #[cfg(feature = "native-service-validation")]
    #[error("authority journal stopped at a native validation fault point")]
    InjectedFault,
}

/// Installation-supplied dedicated SYSTEM directory and registry scope. No
/// caller-selected path or scope may be taken from an untrusted request.
pub struct WindowsAuthorityJournal {
    directory: PrivateDirectory,
    anchor: PrivateMachineRecord,
    record_capacity: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "native-service-validation", derive(Debug))]
pub enum JournalFaultPoint {
    AnchorCreated,
    MarkerPublished,
    PendingAnchorPublished,
    JournalPublished,
    HeadPublished,
    CommittedAnchorPublished,
    OldGenerationRemoved,
}

impl WindowsAuthorityJournal {
    pub fn open(root: &Path, scope: &str) -> Result<Self> {
        // Reject non-SYSTEM/impersonated identities before creating files.
        let anchor = PrivateMachineRecord::new(scope)?;
        let directory = PrivateDirectory::open_or_create(root)?;
        Ok(Self {
            directory,
            anchor,
            record_capacity: MAX_RECORDS,
        })
    }
    #[cfg(feature = "native-service-validation")]
    pub fn open_with_record_capacity_for_validation(
        root: &Path,
        scope: &str,
        capacity: u64,
    ) -> Result<Self> {
        if !(LIFECYCLE_FINISH_RESERVE + 2..=MAX_RECORDS).contains(&capacity) {
            return Err(JournalStoreError::Capacity);
        }
        let mut value = Self::open(root, scope)?;
        value.record_capacity = capacity;
        Ok(value)
    }
    pub fn recover(&self) -> Result<JournalRecovery> {
        let guard = self.anchor.lock(LOCK_WAIT)?;
        let result = (|| {
            let mut files = self.directory.write()?;
            self.recover_locked(&mut files, &guard)
        })();
        finish(result, guard.release())
    }
    pub fn append(&self, state: &AuthorityCommittedState) -> Result<JournalCursor> {
        self.append_with_hook(state, &mut |_| Ok(()))
    }
    #[cfg(feature = "native-service-validation")]
    pub fn append_interrupted_for_validation(
        &self,
        state: &AuthorityCommittedState,
        point: JournalFaultPoint,
    ) -> Result<JournalCursor> {
        self.append_with_hook(state, &mut |at| {
            if at == point {
                Err(JournalStoreError::InjectedFault)
            } else {
                Ok(())
            }
        })
    }
    fn append_with_hook(
        &self,
        state: &AuthorityCommittedState,
        hook: &mut impl FnMut(JournalFaultPoint) -> Result<()>,
    ) -> Result<JournalCursor> {
        state.validate()?;
        let guard = self.anchor.lock(LOCK_WAIT)?;
        let result = (|| {
            let mut files = self.directory.write()?;
            let prior = self.recover_locked(&mut files, &guard)?;
            if let Some(previous) = &prior.committed {
                state.validate_successor(previous)?;
            } else if state.transition() != JournalTransition::EnrollOff {
                return Err(JournalValidationError::Sequence.into());
            }
            let mut anchor = match load_anchor(&guard)? {
                Some(anchor) => anchor,
                None => {
                    let anchor = JournalAnchor::new(Uuid::new_v4(), None, None)?;
                    replace_anchor(&guard, None, &anchor)?;
                    hook(JournalFaultPoint::AnchorCreated)?;
                    ensure_marker(&mut files, &anchor)?;
                    hook(JournalFaultPoint::MarkerPublished)?;
                    anchor
                }
            };
            if let (Some(cursor), Some(previous)) = (anchor.committed(), prior.committed.as_ref()) {
                let reserve = LIFECYCLE_FINISH_RESERVE;
                let needs_compaction = cursor.sequence().saturating_add(reserve)
                    > self.record_capacity
                    || cursor.committed_length().saturating_add(
                        reserve * (MAX_RECORD_PAYLOAD + codec::HEADER_BYTES) as u64,
                    ) > MAX_JOURNAL_BYTES as u64;
                if matches!(
                    state.transition(),
                    JournalTransition::Prepare | JournalTransition::ReserveGeneration
                ) && needs_compaction
                {
                    let generation = cursor
                        .generation()
                        .checked_add(1)
                        .ok_or(JournalStoreError::Capacity)?;
                    let checkpoint = previous.checkpoint()?;
                    anchor = Self::publish(
                        &mut files,
                        &guard,
                        anchor,
                        generation,
                        Vec::new(),
                        &checkpoint,
                        hook,
                    )?;
                    cleanup_old(&mut files, &anchor, hook)?;
                }
            }
            if anchor
                .committed()
                .is_some_and(|cursor| cursor.sequence() >= self.record_capacity)
            {
                return Err(JournalStoreError::Capacity);
            }
            let (generation, bytes) = if let Some(cursor) = anchor.committed() {
                (
                    cursor.generation(),
                    required_read(
                        &files,
                        &journal_name(cursor.generation()),
                        MAX_JOURNAL_BYTES,
                    )?,
                )
            } else {
                (1, Vec::new())
            };
            anchor = Self::publish(&mut files, &guard, anchor, generation, bytes, state, hook)?;
            cleanup_old(&mut files, &anchor, hook)?;
            anchor
                .committed()
                .cloned()
                .ok_or(JournalStoreError::StoreIdentity)
        })();
        finish(result, guard.release())
    }

    fn publish(
        files: &mut WriteTransaction,
        guard: &MachineRecordGuard<'_>,
        anchor: JournalAnchor,
        generation: u64,
        mut bytes: Vec<u8>,
        state: &AuthorityCommittedState,
        hook: &mut impl FnMut(JournalFaultPoint) -> Result<()>,
    ) -> Result<JournalAnchor> {
        let (sequence, previous) = if bytes.is_empty() {
            (1, [0; 32])
        } else {
            let cursor = anchor.committed().ok_or(JournalStoreError::StoreIdentity)?;
            let decoded = decode_journal(&bytes)?;
            decoded.verify_cursor(cursor)?;
            state.validate_successor(decoded.state())?;
            (
                cursor
                    .sequence()
                    .checked_add(1)
                    .ok_or(JournalStoreError::Capacity)?,
                *cursor.record_sha256(),
            )
        };
        let encoded = encode_record(state, sequence, previous)?;
        if bytes.len().saturating_add(encoded.bytes.len()) > MAX_JOURNAL_BYTES {
            return Err(JournalStoreError::Capacity);
        }
        bytes.extend(encoded.bytes);
        let cursor = JournalCursor::new(
            generation,
            sequence,
            bytes.len() as u64,
            encoded.digest,
            state.revision(),
        )?;
        let pending = JournalAnchor::new(
            anchor.store_id(),
            anchor.committed().cloned(),
            Some(cursor.clone()),
        )?;
        replace_anchor(guard, Some(&anchor), &pending)?;
        hook(JournalFaultPoint::PendingAnchorPublished)?;
        publish(files, &journal_name(generation), &bytes, MAX_JOURNAL_BYTES)?;
        hook(JournalFaultPoint::JournalPublished)?;
        publish(
            files,
            &head_name(generation),
            &cursor.encode()?,
            MAX_HEAD_BYTES,
        )?;
        hook(JournalFaultPoint::HeadPublished)?;
        let committed = JournalAnchor::new(anchor.store_id(), Some(cursor), None)?;
        replace_anchor(guard, Some(&pending), &committed)?;
        hook(JournalFaultPoint::CommittedAnchorPublished)?;
        Ok(committed)
    }

    fn recover_locked(
        &self,
        files: &mut WriteTransaction,
        guard: &MachineRecordGuard<'_>,
    ) -> Result<JournalRecovery> {
        let entries = inspect_entries(files)?;
        let Some(mut anchor) = load_anchor(guard)? else {
            if !entries.is_empty() {
                return Err(JournalStoreError::StoreIdentity);
            }
            return Ok(JournalRecovery {
                committed: None,
                cursor: None,
                action: RecoveryAction::VerifyOff,
            });
        };
        ensure_marker(files, &anchor)?;
        if anchor.pending().is_some() {
            anchor = recover_pending(files, guard, &anchor)?;
        }
        let Some(cursor) = anchor.committed() else {
            if inspect_entries(files)?.iter().any(|name| name != MARKER) {
                return Err(JournalStoreError::StoreIdentity);
            }
            return Ok(JournalRecovery {
                committed: None,
                cursor: None,
                action: RecoveryAction::VerifyOff,
            });
        };
        let decoded = read_committed(files, cursor)?;
        let action = decoded.state().restart_action()?;
        cleanup_old(files, &anchor, &mut |_| Ok(()))?;
        Ok(JournalRecovery {
            committed: Some(decoded.state().clone()),
            cursor: Some(cursor.clone()),
            action,
        })
    }
}

fn finish<T>(result: Result<T>, release: std::result::Result<(), MachineRecordError>) -> Result<T> {
    match (result, release) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
        (Err(operation), Err(error)) => Err(JournalStoreError::Cleanup {
            operation: Box::new(operation),
            cleanup: Box::new(error.into()),
        }),
    }
}
fn load_anchor(guard: &MachineRecordGuard<'_>) -> Result<Option<JournalAnchor>> {
    guard
        .read()?
        .map(|bytes| JournalAnchor::decode(&bytes).map_err(Into::into))
        .transpose()
}
fn replace_anchor(
    guard: &MachineRecordGuard<'_>,
    expected: Option<&JournalAnchor>,
    replacement: &JournalAnchor,
) -> Result<()> {
    let before = expected.map(JournalAnchor::encode).transpose()?;
    guard.compare_exchange(before.as_deref(), &replacement.encode()?)?;
    Ok(())
}
fn journal_name(generation: u64) -> String {
    format!("journal-{generation}.bin")
}
fn head_name(generation: u64) -> String {
    format!("head-{generation}.json")
}
fn temporary(name: &str) -> String {
    format!(".{name}.tmp")
}
fn read(files: &WriteTransaction, name: &str, maximum: usize) -> Result<Option<Vec<u8>>> {
    Ok(files
        .read(name, maximum, ReadPolicy::Private)?
        .map(|snapshot| snapshot.bytes))
}
fn read_temporary(files: &WriteTransaction, name: &str, maximum: usize) -> Result<Option<Vec<u8>>> {
    Ok(files
        .read_temporary(name, maximum)?
        .map(|snapshot| snapshot.bytes))
}
fn required_read(files: &WriteTransaction, name: &str, maximum: usize) -> Result<Vec<u8>> {
    read(files, name, maximum)?.ok_or(JournalStoreError::StoreIdentity)
}
fn publish(files: &mut WriteTransaction, name: &str, bytes: &[u8], maximum: usize) -> Result<()> {
    // Never use replace(), whose generic cleanup discards an existing temporary.
    // Only validated recovery owns removal of a journal temporary.
    files.publish_with_temporary(name, &temporary(name), bytes, maximum, Publication::Replace)?;
    Ok(())
}
fn remove_temporary(files: &mut WriteTransaction, name: &str) -> Result<()> {
    files.unlink_managed_entry(OsStr::new(name))?;
    files.sync_directory()?;
    Ok(())
}

fn ensure_marker(files: &mut WriteTransaction, anchor: &JournalAnchor) -> Result<()> {
    let bytes = anchor.store_id().to_string().into_bytes();
    let marker = read(files, MARKER, 64)?;
    let temp = read_temporary(files, MARKER_TEMP, 64)?;
    if marker.as_ref().is_some_and(|actual| actual != &bytes)
        || temp.as_ref().is_some_and(|actual| actual != &bytes)
    {
        return Err(JournalStoreError::StoreIdentity);
    }
    if marker.is_some() && temp.is_none() {
        return Ok(());
    }
    if anchor.committed().is_some()
        || anchor.pending().is_some()
        || inspect_entries(files)?
            .iter()
            .any(|name| name != MARKER && name != MARKER_TEMP)
    {
        return Err(JournalStoreError::StoreIdentity);
    }
    if temp.is_some() {
        remove_temporary(files, MARKER_TEMP)?;
    }
    publish(files, MARKER, &bytes, 64)
}

fn read_committed(files: &WriteTransaction, cursor: &JournalCursor) -> Result<DecodedJournal> {
    let journal = journal_name(cursor.generation());
    let head = head_name(cursor.generation());
    if read_temporary(files, &temporary(&journal), MAX_JOURNAL_BYTES)?.is_some()
        || read_temporary(files, &temporary(&head), MAX_HEAD_BYTES)?.is_some()
    {
        return Err(JournalValidationError::Anchor.into());
    }
    let decoded = decode_journal(&required_read(files, &journal, MAX_JOURNAL_BYTES)?)?;
    decoded.verify_cursor(cursor)?;
    if JournalCursor::decode(&required_read(files, &head, MAX_HEAD_BYTES)?)? != *cursor {
        return Err(JournalValidationError::Anchor.into());
    }
    Ok(decoded)
}

fn recover_pending(
    files: &mut WriteTransaction,
    guard: &MachineRecordGuard<'_>,
    anchor: &JournalAnchor,
) -> Result<JournalAnchor> {
    let pending = anchor.pending().ok_or(JournalStoreError::StoreIdentity)?;
    let committed = anchor.committed();
    let same_generation = committed.filter(|cursor| cursor.generation() == pending.generation());
    let previous_other = committed
        .filter(|cursor| cursor.generation() != pending.generation())
        .map(|cursor| read_committed(files, cursor))
        .transpose()?;
    let journal_name = journal_name(pending.generation());
    let head_name = head_name(pending.generation());
    let journal = read(files, &journal_name, MAX_JOURNAL_BYTES)?;
    let journal_temp = read_temporary(files, &temporary(&journal_name), MAX_JOURNAL_BYTES)?;
    let head = read(files, &head_name, MAX_HEAD_BYTES)?
        .map(|bytes| JournalCursor::decode(&bytes))
        .transpose()?;
    let head_temp = read_temporary(files, &temporary(&head_name), MAX_HEAD_BYTES)?
        .map(|bytes| JournalCursor::decode(&bytes))
        .transpose()?;
    if head
        .as_ref()
        .is_some_and(|value| value != pending && Some(value) != same_generation)
        || head_temp.as_ref().is_some_and(|value| value != pending)
    {
        return Err(JournalValidationError::Anchor.into());
    }
    let mut candidate = None;
    if let Some(bytes) = journal.as_ref() {
        let decoded = decode_journal(bytes)?;
        if decoded.cursor(pending.generation())? == *pending {
            candidate = Some(bytes.clone());
        } else if same_generation.is_none_or(|cursor| decoded.verify_cursor(cursor).is_err()) {
            return Err(JournalValidationError::Anchor.into());
        }
    } else if same_generation.is_some() {
        return Err(JournalValidationError::Anchor.into());
    }
    if let Some(bytes) = journal_temp.as_ref() {
        decode_journal(bytes)?.verify_cursor(pending)?;
        candidate = Some(bytes.clone());
    }
    let Some(bytes) = candidate else {
        // No granted operation can precede the final anchor commit. A fully
        // unchanged committed image (or absent new generation) can abort intent.
        if head_temp.is_some() || head.as_ref() != same_generation {
            return Err(JournalValidationError::Anchor.into());
        }
        if let Some(cursor) = same_generation {
            read_committed(files, cursor)?;
        } else if journal.is_some() || head.is_some() {
            return Err(JournalValidationError::Anchor.into());
        }
        let cleared = JournalAnchor::new(anchor.store_id(), committed.cloned(), None)?;
        replace_anchor(guard, Some(anchor), &cleared)?;
        return Ok(cleared);
    };
    let decoded = decode_journal(&bytes)?;
    decoded.verify_cursor(pending)?;
    if let Some(previous) = previous_other {
        if previous.state().checkpoint()? != *decoded.state() {
            return Err(JournalValidationError::Anchor.into());
        }
    } else if let Some(cursor) = same_generation {
        let prefix = bytes
            .get(..cursor.committed_length() as usize)
            .ok_or(JournalValidationError::Truncated)?;
        decode_journal(prefix)?.verify_cursor(cursor)?;
    } else if decoded.state().transition() != JournalTransition::EnrollOff {
        return Err(JournalValidationError::Anchor.into());
    }
    // Re-publish validated complete bytes to re-establish durability even after
    // an earlier operation reported an uncertain flush. Partial temps quarantine.
    if journal_temp.is_some() {
        remove_temporary(files, &temporary(&journal_name))?;
    }
    publish(files, &journal_name, &bytes, MAX_JOURNAL_BYTES)?;
    if head_temp.is_some() {
        remove_temporary(files, &temporary(&head_name))?;
    }
    publish(files, &head_name, &pending.encode()?, MAX_HEAD_BYTES)?;
    let completed = JournalAnchor::new(anchor.store_id(), Some(pending.clone()), None)?;
    replace_anchor(guard, Some(anchor), &completed)?;
    Ok(completed)
}

fn generation(name: &str) -> Option<u64> {
    let base = if name.starts_with('.') {
        name.strip_prefix('.')?.strip_suffix(".tmp")?
    } else {
        name
    };
    let digits = base
        .strip_prefix("journal-")
        .and_then(|value| value.strip_suffix(".bin"))
        .or_else(|| {
            base.strip_prefix("head-")
                .and_then(|value| value.strip_suffix(".json"))
        })?;
    let value = digits.parse::<u64>().ok()?;
    (value > 0 && value.to_string() == digits).then_some(value)
}
fn inspect_entries(files: &WriteTransaction) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for name in files.entry_names(MAX_ENTRIES)? {
        let text = name.to_str().ok_or(JournalStoreError::StoreIdentity)?;
        if (text != MARKER && text != MARKER_TEMP && generation(text).is_none())
            || files.entry_kind(&name)? != EntryKind::File
        {
            return Err(JournalStoreError::StoreIdentity);
        }
        names.push(text.to_owned());
    }
    Ok(names)
}
fn cleanup_old(
    files: &mut WriteTransaction,
    anchor: &JournalAnchor,
    hook: &mut impl FnMut(JournalFaultPoint) -> Result<()>,
) -> Result<()> {
    if anchor.pending().is_some() {
        return Err(JournalValidationError::Anchor.into());
    }
    let current = anchor
        .committed()
        .ok_or(JournalStoreError::StoreIdentity)?
        .generation();
    let names = inspect_entries(files)?;
    // Validate the entire cleanup set before changing any directory entry.
    for name in &names {
        if name == MARKER_TEMP
            || generation(name)
                .is_some_and(|g| g > current || (g == current && name.starts_with('.')))
        {
            return Err(JournalStoreError::StoreIdentity);
        }
        if generation(name).is_some_and(|g| g < current) {
            if name.starts_with('.') {
                files.validate_temporary(name)?;
            } else {
                drop(files.open_private_file(name)?);
            }
        }
    }
    for name in names {
        if generation(&name).is_some_and(|g| g < current) {
            files.unlink_managed_entry(OsStr::new(&name))?;
            files.sync_directory()?;
            hook(JournalFaultPoint::OldGenerationRemoved)?;
        }
    }
    Ok(())
}
