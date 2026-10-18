use std::ptr::{null, null_mut};

use cfw_engine_api::CredentialVaultError as Error;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use zeroize::{Zeroize, Zeroizing};

use crate::document::MAX_DOCUMENT_BYTES;

pub(crate) const MAX_CIPHERTEXT_BYTES: usize = MAX_DOCUMENT_BYTES + 64 * 1024;
// Public domain separation, not a password or an application identity check.
const ENTROPY: &[u8] = b"com.bill.clashforwindows.credential-vault.v1";

/// This store belongs to the interactive user's process identity. A service
/// must not accidentally create a different user's vault through impersonation.
/// A future privileged broker needs a separate authenticated owner boundary.
pub(crate) fn require_process_identity() -> Result<(), Error> {
    cfw_windows_storage::require_process_identity().map_err(|_| Error::AccessDenied)
}

pub(crate) fn protect(plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    transform(plaintext, true).map(|bytes| bytes.to_vec())
}

pub(crate) fn unprotect(ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    transform(ciphertext, false)
}

fn transform(input: &[u8], protect: bool) -> Result<Zeroizing<Vec<u8>>, Error> {
    let input_limit = if protect {
        MAX_DOCUMENT_BYTES
    } else {
        MAX_CIPHERTEXT_BYTES
    };
    if input.is_empty() || input.len() > input_limit {
        return Err(Error::Corrupt);
    }
    let input_blob = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(input.len()).map_err(|_| Error::CapacityExceeded)?,
        pbData: input.as_ptr().cast_mut(),
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: ENTROPY.len() as u32,
        pbData: ENTROPY.as_ptr().cast_mut(),
    };
    let mut output = OwnedBlob(CRYPT_INTEGER_BLOB::default());
    // SAFETY: DPAPI borrows the input and entropy only for this call. Reserved
    // and UI arguments are null. OwnedBlob erases/frees the returned allocation.
    let success = unsafe {
        if protect {
            CryptProtectData(
                &input_blob,
                null(),
                &entropy,
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        } else {
            CryptUnprotectData(
                &input_blob,
                null_mut(),
                &entropy,
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        }
    };
    if success == 0 {
        // Decryption failures can mean corruption or an unavailable key. They
        // never mean an absent vault, and no replacement is attempted.
        return Err(if protect {
            Error::Unavailable
        } else {
            Error::IdentityRejected
        });
    }
    let limit = if protect {
        MAX_CIPHERTEXT_BYTES
    } else {
        MAX_DOCUMENT_BYTES
    };
    if output.0.pbData.is_null() || output.0.cbData == 0 || output.0.cbData as usize > limit {
        return Err(Error::Corrupt);
    }
    // SAFETY: successful DPAPI output is an allocation of cbData bytes whose
    // lifetime is held by output; the checked bound also fits Rust slice limits.
    let bytes = unsafe { std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize) };
    Ok(Zeroizing::new(bytes.to_vec()))
}

struct OwnedBlob(CRYPT_INTEGER_BLOB);

impl Drop for OwnedBlob {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            // SAFETY: DPAPI allocates cbData bytes with LocalAlloc; this guard
            // exclusively owns them and frees them exactly once after erasing.
            unsafe {
                std::slice::from_raw_parts_mut(self.0.pbData, self.0.cbData as usize).zeroize();
                LocalFree(self.0.pbData.cast());
            }
        }
    }
}
