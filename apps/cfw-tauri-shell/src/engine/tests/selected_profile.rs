//! What a change of the runtime preferences asks of the selected profile:
//! before it takes a place among the mode changes, and where it has its turn
//! there.
use super::restoration::{RestorationRightsBridge, engine_with_rights_bridge};
use super::saved_preferences::{MAC_TUNNEL_MTU, temporary_store};
use super::*;
use crate::engine::runtime_settings::{
    PROFILE_IPV6_DNS_CHANGED, PreferencesBasis, RequestedChange, admit_requested_change,
    prepare_runtime_settings,
};
use cfw_singbox_config::{EngineLogLevel, RuntimePreferences};

/// The form of saved preferences that showed IPv6 DNS on, as the profile
/// where none is selected gives it.
const SAVED: PreferencesBasis = PreferencesBasis::Saved {
    ipv6_dns_enabled: true,
};

/// The change of the log level that the tests of the selected profile make.
fn louder(basis: PreferencesBasis) -> RequestedChange {
    RequestedChange {
        preferences: RuntimePreferences {
            log_level: EngineLogLevel::Debug,
            ..RuntimePreferences::default()
        },
        expected_revision: None,
        basis,
    }
}

/// A selected profile that fails validation refuses every change before the
/// queue, with the words of the repository, as the queue refuses it: the view
/// of the settings after a change derives effective DNS from the selected
/// document. A start that loaded the profile before then goes on with it, and
/// a change refused only in the queue would have ended its retry for nothing.
/// The reader of the engine, with which the commands admit a change, reads
/// the selection of the repository it is given.
#[tokio::test]
async fn a_selected_profile_that_fails_validation_refuses_a_change_before_the_queue() {
    let (_root, store) = temporary_store();
    let profiles = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(profiles.path().join("profiles"));
    crate::profile_fixtures::store_selected_reality_without_utls(
        profiles.path().join("profiles").as_path(),
        &repository,
    );
    let refusal = repository
        .load_selected()
        .expect_err("a selection that fails validation")
        .to_string();
    let engine = engine_with_rights_bridge(Arc::new(RestorationRightsBridge::default()));
    let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));
    let mistaken = PreferencesBasis::Saved {
        ipv6_dns_enabled: false,
    };
    for basis in [PreferencesBasis::InForce, SAVED, mistaken] {
        let admitted = admit_requested_change(
            &endpoints,
            &store,
            MAC_TUNNEL_MTU,
            || repository.load_selected(),
            |_| Ok(louder(basis)),
        );
        assert_eq!(admitted.map(|_| ()), Err(refusal.clone()), "{basis:?}");
        let admitted = engine
            .saved_runtime_preferences()
            .admit(&store, &repository, |_| Ok(louder(basis)));
        assert_eq!(admitted.map(|_| ()), Err(refusal.clone()), "{basis:?}");
        let queued = prepare_runtime_settings(
            store.clone(),
            &endpoints,
            &repository,
            MAC_TUNNEL_MTU,
            EngineMode::Off,
            louder(basis),
        );
        assert_eq!(queued.err(), Some(refusal.clone()), "{basis:?}");
    }
    assert_eq!(endpoints.read().expect("endpoints").preference_writes, 0);
}

/// An update of a subscription holds the profile repository for longer than
/// the read of the selected profile waits. A change is admitted meanwhile,
/// one that leaves IPv6 DNS to the profile among them, and is not refused for
/// the repository: it takes its place in the queue after the update, and is
/// asked of the selected profile there.
#[test]
fn a_change_is_admitted_while_the_profiles_are_held_and_asked_of_them_in_the_queue() {
    let (_root, store) = temporary_store();
    let profiles = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(profiles.path().join("profiles"));
    let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));
    // The form showed IPv6 DNS off, and the profile where none is selected
    // turns it on.
    let mistaken = PreferencesBasis::Saved {
        ipv6_dns_enabled: false,
    };
    let admit = |basis: PreferencesBasis| {
        admit_requested_change(
            &endpoints,
            &store,
            MAC_TUNNEL_MTU,
            || repository.load_selected(),
            |_| Ok(louder(basis)),
        )
        .map(|admitted| admitted.requested().basis)
    };
    let held = repository
        .begin_credential_profile_mutation()
        .expect("the repository");
    // The admission runs on another thread than the one that holds it, as
    // beside an update.
    std::thread::scope(|scope| {
        for basis in [PreferencesBasis::InForce, mistaken] {
            let admitted = scope
                .spawn(move || admit(basis))
                .join()
                .expect("the admission");
            assert_eq!(admitted, Ok(basis), "{basis:?}");
        }
    });
    drop(held);
    let queued = prepare_runtime_settings(
        store.clone(),
        &endpoints,
        &repository,
        MAC_TUNNEL_MTU,
        EngineMode::Off,
        louder(mistaken),
    );
    assert_eq!(queued.err(), Some(PROFILE_IPV6_DNS_CHANGED.to_owned()));
    assert_eq!(admit(mistaken), Err(PROFILE_IPV6_DNS_CHANGED.to_owned()));
    assert_eq!(
        admit(PreferencesBasis::InForce),
        Ok(PreferencesBasis::InForce)
    );
}

/// The selected profile is asked what a change leaves to it before the queue
/// as in it, and not the profile where none is selected: one that turns IPv6
/// DNS off gives the form that showed it off what that form showed, and
/// refuses the form that showed it on.
#[test]
fn the_selected_profile_is_asked_what_a_change_leaves_to_it_before_the_queue() {
    let (_root, store) = temporary_store();
    let profiles = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(profiles.path().join("profiles"));
    let imported = repository
        .import(
            Some("No IPv6 DNS"),
            &super::admitted_change::profile_without_ipv6_dns(),
        )
        .expect("import the profile");
    repository.select(&imported.id).expect("select the profile");
    let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));
    for (shown, refusal) in [(false, None), (true, Some(PROFILE_IPV6_DNS_CHANGED))] {
        let basis = PreferencesBasis::Saved {
            ipv6_dns_enabled: shown,
        };
        let expected = refusal.map_or(Ok(()), |refusal| Err(refusal.to_owned()));
        let admitted = admit_requested_change(
            &endpoints,
            &store,
            MAC_TUNNEL_MTU,
            || repository.load_selected(),
            |_| Ok(louder(basis)),
        );
        assert_eq!(admitted.map(|_| ()), expected, "shown {shown}");
        let queued = prepare_runtime_settings(
            store.clone(),
            &endpoints,
            &repository,
            MAC_TUNNEL_MTU,
            EngineMode::Off,
            louder(basis),
        );
        assert_eq!(queued.map(|_| ()), expected, "shown {shown}");
    }
}
