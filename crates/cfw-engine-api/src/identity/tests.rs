use super::*;
use crate::test_support::INSTALLATION_ID;

#[test]
fn a_command_context_carries_its_session_and_the_reserved_generation() {
    let session = EngineSessionIdentity {
        installation_id: INSTALLATION_ID.into(),
        config_epoch: 3,
    };
    assert_eq!(
        EngineCommandContext::new(&session, 9),
        EngineCommandContext {
            installation_id: INSTALLATION_ID.into(),
            config_epoch: 3,
            generation: 9,
        }
    );
}
