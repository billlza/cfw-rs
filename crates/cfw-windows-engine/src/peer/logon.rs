//! Whether the logon a run was recorded under still exists.
//!
//! Windows keeps a logon identifier unique until the system restarts, and it
//! deletes a logon session only together with its last token. A process holds
//! its token for as long as its process object exists. So when no session has
//! the recorded identifier, or the identifier now names another account, the
//! recorded logon is gone and no process that ran under it is left.
use super::PeerIdentityError;
use crate::authority_journal::RecordedOwner;
use std::{io, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::{LUID, NTSTATUS, STATUS_SUCCESS},
    Security::{
        Authentication::Identity::{
            LsaFreeReturnBuffer, LsaGetLogonSessionData, LsaNtStatusToWinError,
            SECURITY_LOGON_SESSION_DATA,
        },
        GetLengthSid, IsValidSid,
    },
};

/// `STATUS_NO_SUCH_LOGON_SESSION` of ntstatus.h.
const NO_SUCH_LOGON_SESSION: NTSTATUS = 0xC000_005F_u32 as NTSTATUS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordedLogon {
    /// A session of the recorded account has the recorded identifier. Its
    /// processes may be alive; this is never read as their retirement.
    Present,
    /// No session has the recorded identifier, or one of another account has.
    Ended,
}

/// The caller must be able to read other logon sessions: SYSTEM is.
pub(crate) fn observe_recorded_logon(
    owner: &RecordedOwner,
) -> Result<RecordedLogon, PeerIdentityError> {
    let identifier = owner.authentication_id();
    let luid = LUID {
        LowPart: identifier as u32,
        HighPart: (identifier >> 32) as u32 as i32,
    };
    let mut data: *mut SECURITY_LOGON_SESSION_DATA = null_mut();
    let status = unsafe { LsaGetLogonSessionData(&luid, &mut data) };
    if status == NO_SUCH_LOGON_SESSION {
        return Ok(RecordedLogon::Ended);
    }
    if status != STATUS_SUCCESS {
        return Err(PeerIdentityError::Native {
            operation: "read the recorded logon session",
            source: io::Error::from_raw_os_error(unsafe { LsaNtStatusToWinError(status) } as i32),
        });
    }
    if data.is_null() {
        return Err(PeerIdentityError::InvalidIdentity);
    }
    struct Returned(*mut SECURITY_LOGON_SESSION_DATA);
    impl Drop for Returned {
        fn drop(&mut self) {
            unsafe { LsaFreeReturnBuffer(self.0.cast()) };
        }
    }
    let returned = Returned(data);
    let session = unsafe { &*returned.0 };
    if session.LogonId.LowPart != luid.LowPart || session.LogonId.HighPart != luid.HighPart {
        return Err(PeerIdentityError::InvalidIdentity);
    }
    // Only the account decides. A session's terminal session can change while
    // its processes live, so a different one proves nothing. Neither does a
    // session whose account cannot be read.
    let sid = session.Sid;
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(PeerIdentityError::InvalidIdentity);
    }
    let length = unsafe { GetLengthSid(sid) } as usize;
    let account = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) };
    Ok(if account == owner.sid_bytes() {
        RecordedLogon::Present
    } else {
        RecordedLogon::Ended
    })
}

/// Validation only: whether the caller reads the logon of `owner` as ended.
#[cfg(feature = "native-service-validation")]
pub fn recorded_logon_ended_for_validation(
    owner: &RecordedOwner,
) -> Result<bool, PeerIdentityError> {
    observe_recorded_logon(owner).map(|logon| logon == RecordedLogon::Ended)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current() -> crate::NativeUserSession {
        crate::NativePeerProcess::open(std::process::id())
            .unwrap()
            .identity()
            .user_session()
            .clone()
    }
    fn recorded(session: &crate::NativeUserSession) -> serde_json::Value {
        serde_json::to_value(RecordedOwner::from_native(session).unwrap()).unwrap()
    }
    fn owner(value: serde_json::Value) -> RecordedOwner {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn the_logon_of_this_process_is_present() {
        let session = current();
        assert_eq!(
            observe_recorded_logon(&owner(recorded(&session))).unwrap(),
            RecordedLogon::Present
        );
    }

    #[test]
    fn an_identifier_no_session_has_is_ended() {
        // Identifiers are handed out in increasing order from a small number
        // at every start of the system; this one is never reached.
        let mut value = recorded(&current());
        value["authentication_id"] = serde_json::json!(u64::MAX - 1);
        assert_eq!(
            observe_recorded_logon(&owner(value)).unwrap(),
            RecordedLogon::Ended
        );
    }

    #[test]
    fn the_identifier_of_another_account_is_ended_and_the_terminal_session_decides_nothing() {
        let session = current();
        // This process's identifier, recorded for another account: the system
        // restarted since, and the identifier was handed out again.
        let mut other = recorded(&session);
        let sid = other["sid"].as_array_mut().unwrap();
        let last = sid.len() - 1;
        sid[last] = serde_json::json!(sid[last].as_u64().unwrap() ^ 1);
        assert_eq!(
            observe_recorded_logon(&owner(other)).unwrap(),
            RecordedLogon::Ended
        );
        // The same account and identifier in another terminal session is
        // still this logon.
        let mut moved = recorded(&session);
        moved["session_id"] = serde_json::json!(session.session_id() ^ 0x40);
        assert_eq!(
            observe_recorded_logon(&owner(moved)).unwrap(),
            RecordedLogon::Present
        );
    }
}
