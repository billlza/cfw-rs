use super::*;
use sha2::{Digest, Sha256};

// Windows has a distinct versioned payload with full SID/logon ownership; a
// macOS UID journal must never be accepted as this platform's state.
const MAGIC: &[u8; 8] = b"CFWWJR01";
pub(crate) const HEADER_BYTES: usize = 8 + 4 + 8 + 32 + 32 + 4;
type Result<T> = std::result::Result<T, JournalValidationError>;

pub struct EncodedRecord {
    pub bytes: Vec<u8>,
    pub digest: [u8; 32],
}

pub fn encode_record(
    state: &AuthorityCommittedState,
    sequence: u64,
    previous: [u8; 32],
) -> Result<EncodedRecord> {
    if sequence == 0 || sequence > MAX_RECORDS {
        return Err(JournalValidationError::Capacity);
    }
    if sequence == 1
        && (previous != [0; 32]
            || !matches!(
                state.transition(),
                JournalTransition::EnrollOff | JournalTransition::Checkpoint
            ))
    {
        return Err(JournalValidationError::Sequence);
    }
    let payload = state.encode()?;
    let mut frame = Vec::with_capacity(HEADER_BYTES + payload.len());
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&sequence.to_be_bytes());
    frame.extend_from_slice(&previous);
    frame.extend_from_slice(&Sha256::digest(&payload));
    let checksum = crc32(frame.iter().chain(payload.iter()).copied());
    frame.extend_from_slice(&checksum.to_be_bytes());
    frame.extend_from_slice(&payload);
    let digest = Sha256::digest(&frame).into();
    Ok(EncodedRecord {
        bytes: frame,
        digest,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedJournal {
    state: AuthorityCommittedState,
    sequence: u64,
    committed_length: u64,
    record_sha256: [u8; 32],
}
impl DecodedJournal {
    pub fn state(&self) -> &AuthorityCommittedState {
        &self.state
    }
    pub fn cursor(&self, generation: u64) -> Result<JournalCursor> {
        JournalCursor::new(
            generation,
            self.sequence,
            self.committed_length,
            self.record_sha256,
            self.state.revision(),
        )
    }
    pub fn verify_cursor(&self, cursor: &JournalCursor) -> Result<()> {
        cursor.validate()?;
        if self.cursor(cursor.generation())? != *cursor {
            return Err(JournalValidationError::Integrity);
        }
        Ok(())
    }
}

pub fn decode_journal(bytes: &[u8]) -> Result<DecodedJournal> {
    if bytes.is_empty() {
        return Err(JournalValidationError::Truncated);
    }
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(JournalValidationError::Capacity);
    }
    let mut offset = 0;
    let mut sequence = 1;
    let mut previous = [0; 32];
    let mut last: Option<AuthorityCommittedState> = None;
    while offset < bytes.len() {
        if sequence > MAX_RECORDS {
            return Err(JournalValidationError::Capacity);
        }
        let start = offset;
        let header = bytes
            .get(start..start + HEADER_BYTES)
            .ok_or(JournalValidationError::Truncated)?;
        if header.get(..8) != Some(MAGIC.as_slice()) {
            return Err(JournalValidationError::Encoding);
        }
        let size = u32::from_be_bytes(array(&header[8..12])?) as usize;
        if size == 0 || size > MAX_RECORD_PAYLOAD {
            return Err(JournalValidationError::Capacity);
        }
        if u64::from_be_bytes(array(&header[12..20])?) != sequence {
            return Err(JournalValidationError::Sequence);
        }
        if header[20..52] != previous {
            return Err(JournalValidationError::Integrity);
        }
        let payload_start = start + HEADER_BYTES;
        offset = payload_start + size;
        let payload = bytes
            .get(payload_start..offset)
            .ok_or(JournalValidationError::Truncated)?;
        let payload_digest: [u8; 32] = Sha256::digest(payload).into();
        if payload_digest != header[52..84]
            || crc32(header[..84].iter().chain(payload.iter()).copied())
                != u32::from_be_bytes(array(&header[84..88])?)
        {
            return Err(JournalValidationError::Integrity);
        }
        let state = AuthorityCommittedState::decode(payload)?;
        if let Some(prior) = &last {
            state.validate_successor(prior)?;
        } else if !matches!(
            state.transition(),
            JournalTransition::EnrollOff | JournalTransition::Checkpoint
        ) {
            return Err(JournalValidationError::Sequence);
        }
        previous = Sha256::digest(&bytes[start..offset]).into();
        last = Some(state);
        sequence += 1;
    }
    Ok(DecodedJournal {
        state: last.ok_or(JournalValidationError::Truncated)?,
        sequence: sequence - 1,
        committed_length: offset as u64,
        record_sha256: previous,
    })
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| JournalValidationError::Truncated)
}
fn crc32(bytes: impl Iterator<Item = u8>) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

#[cfg(test)]
mod checksum_tests {
    #[test]
    fn crc_matches_the_standard_check_vector() {
        assert_eq!(super::crc32(b"123456789".iter().copied()), 0xcbf4_3926);
    }
}
