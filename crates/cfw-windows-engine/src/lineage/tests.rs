use super::*;
use crate::PeerIdentityError;
use sha2::{Digest, Sha256};
use windows_sys::Win32::Security::{ImpersonateSelf, RevertToSelf, SecurityImpersonation};

fn unavailable_store() -> WindowsEngineGenerationStore {
    let path = std::env::current_exe().unwrap();
    let hash = Sha256::digest(std::fs::read(&path).unwrap()).into();
    let image = Arc::new(VerifiedExecutable::open(&path, hash, "0.5.0").unwrap());
    WindowsEngineGenerationStore::new(format!("CFW-lineage-{}", uuid::Uuid::new_v4()), image)
}

#[test]
fn unavailable_authority_never_creates_a_local_installation_or_counter() {
    let store = unavailable_store();
    assert!(store.load_lineage().is_err());
    assert!(store.reserve_generation(0).is_err());
    assert!(store.bound_session.lock().unwrap().is_none());
}

#[test]
fn impersonating_thread_cannot_read_or_reserve_process_lineage() {
    let store = unavailable_store();
    assert_ne!(unsafe { ImpersonateSelf(SecurityImpersonation) }, 0);
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            assert_ne!(unsafe { RevertToSelf() }, 0);
        }
    }
    let revert = Revert;
    for result in [
        store.load_lineage().map(|_| ()),
        store.reserve_generation(0).map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(LineageError::Authority(WireError::Identity(
                PeerIdentityError::Observer(cfw_windows_storage::Error::ImpersonatedIdentity)
            )))
        ));
    }
    drop(revert);
    assert!(store.bound_session.lock().unwrap().is_none());
}

#[test]
fn a_store_cannot_adopt_a_replacement_installation_or_epoch() {
    let original = EngineSessionIdentity {
        installation_id: uuid::Uuid::from_u128(1).to_string(),
        config_epoch: 1,
    };
    let mut binding = None;
    bind(&mut binding, &original).unwrap();
    bind(&mut binding, &original).unwrap();
    for changed in [
        EngineSessionIdentity {
            installation_id: uuid::Uuid::from_u128(2).to_string(),
            ..original.clone()
        },
        EngineSessionIdentity {
            config_epoch: 2,
            ..original.clone()
        },
    ] {
        assert!(matches!(
            bind(&mut binding, &changed),
            Err(LineageError::IdentityChanged)
        ));
        assert_eq!(binding, Some(original.clone()));
    }
}
