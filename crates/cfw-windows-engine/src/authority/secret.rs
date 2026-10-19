use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub(super) struct Ticket(Zeroizing<[u8; 32]>);
#[derive(Clone)]
pub(super) struct TicketDigest {
    bytes: Zeroizing<[u8; 32]>,
    domain: &'static [u8],
}
const PREPARATION: &[u8] = b"cfw-windows-authority-preparation-v1\0";
const RECOVERY: &[u8] = b"cfw-windows-authority-proxy-recovery-v1\0";
impl Ticket {
    #[cfg(windows)]
    pub(super) fn generate() -> super::Result<Self> {
        use windows_sys::Win32::Security::Cryptography::{
            BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
        };
        let mut bytes = Zeroizing::new([0; 32]);
        // The synchronous system-preferred RNG receives one initialized, owned
        // buffer. Failure clears it; there is no zero/default/random fallback.
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                bytes.as_mut_ptr(),
                32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status != 0 {
            return Err(super::AuthorityError::Entropy(status));
        }
        Ok(Self(bytes))
    }
    pub(super) fn digest(&self) -> TicketDigest {
        TicketDigest::of(self.0.as_ref(), PREPARATION)
    }
    pub(super) fn recovery_digest(&self) -> TicketDigest {
        TicketDigest::of(self.0.as_ref(), RECOVERY)
    }
    pub(super) fn expose<T>(&self, consume: impl FnOnce(&[u8]) -> T) -> T {
        consume(self.0.as_ref())
    }
    #[cfg(test)]
    pub(super) fn for_test(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}
impl TicketDigest {
    fn of(bytes: &[u8], domain: &'static [u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update(domain);
        hash.update(bytes);
        Self {
            bytes: Zeroizing::new(hash.finalize().into()),
            domain,
        }
    }
    pub(super) fn accepts(&self, bytes: &[u8]) -> bool {
        if bytes.len() != 32 {
            return false;
        }
        let candidate = Self::of(bytes, self.domain);
        bool::from(self.bytes.as_ref().ct_eq(candidate.bytes.as_ref()))
    }
}
