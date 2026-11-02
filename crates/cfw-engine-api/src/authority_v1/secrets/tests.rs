use super::*;
use crate::CredentialKind;
use crate::authority_v1::test_support::credential_ref;

fn slot(seed: u128, length: usize) -> SecretSlot {
    SecretSlot::new(
        credential_ref(seed, CredentialKind::TrojanPassword),
        &vec![1; length],
    )
    .unwrap()
}

#[test]
fn sensitive_bytes_are_non_empty_bounded_and_lent_out() {
    assert!(matches!(
        SensitiveBytes::new(&[], 4),
        Err(CodecError::BoundViolation)
    ));
    assert!(matches!(
        SensitiveBytes::new(&[1; 5], 4),
        Err(CodecError::BoundViolation)
    ));
    let mut lent = Vec::new();
    SensitiveBytes::new(&[1, 2, 3, 4], 4)
        .unwrap()
        .expose(|bytes| lent.extend_from_slice(bytes));
    assert_eq!(lent, [1, 2, 3, 4]);
}

#[test]
fn tickets_and_capabilities_have_exact_lengths() {
    let mut lent = Vec::new();
    StartTicket::new(&[7; TICKET_BYTES])
        .unwrap()
        .expose(|bytes| lent.extend_from_slice(bytes));
    assert_eq!(lent, [7; TICKET_BYTES]);
    for length in [0, TICKET_BYTES - 1, TICKET_BYTES + 1] {
        assert!(matches!(
            StartTicket::new(&vec![7; length]),
            Err(CodecError::BoundViolation)
        ));
    }
    assert!(OwnerCapability::new(&[9; CAPABILITY_BYTES]).is_ok());
    for length in [0, CAPABILITY_BYTES - 1, CAPABILITY_BYTES + 1] {
        assert!(matches!(
            OwnerCapability::new(&vec![9; length]),
            Err(CodecError::BoundViolation)
        ));
    }
}

#[test]
fn secret_slots_hold_one_non_empty_bounded_secret() {
    for length in [0, MAX_INDIVIDUAL_SECRET_BYTES + 1] {
        assert!(matches!(
            SecretSlot::new(
                credential_ref(1, CredentialKind::TrojanPassword),
                &vec![1; length]
            ),
            Err(CodecError::BoundViolation)
        ));
    }
}

#[test]
fn secret_material_counts_unique_slots_within_its_budgets() {
    let material = SecretMaterial::new(vec![slot(1, 3), slot(2, 5)]).unwrap();
    assert_eq!((material.slot_count(), material.total_byte_count()), (2, 8));
    let empty = SecretMaterial::new(Vec::new()).unwrap();
    assert_eq!((empty.slot_count(), empty.total_byte_count()), (0, 0));
    assert!(matches!(
        SecretMaterial::new(vec![slot(1, 3), slot(1, 5)]),
        Err(CodecError::BoundViolation)
    ));

    let full_budget = MAX_TOTAL_SECRET_BYTES / MAX_INDIVIDUAL_SECRET_BYTES;
    let at_budget = (0..full_budget as u128)
        .map(|seed| slot(seed, MAX_INDIVIDUAL_SECRET_BYTES))
        .collect();
    assert_eq!(
        SecretMaterial::new(at_budget).unwrap().total_byte_count(),
        MAX_TOTAL_SECRET_BYTES
    );
    let over_budget = (0..=full_budget as u128)
        .map(|seed| slot(seed, MAX_INDIVIDUAL_SECRET_BYTES))
        .collect();
    assert!(matches!(
        SecretMaterial::new(over_budget),
        Err(CodecError::BoundViolation)
    ));

    let most = (0..MAX_CREDENTIAL_SLOTS as u128)
        .map(|seed| slot(seed, 1))
        .collect();
    assert_eq!(
        SecretMaterial::new(most).unwrap().slot_count(),
        MAX_CREDENTIAL_SLOTS
    );
    let too_many = (0..=MAX_CREDENTIAL_SLOTS as u128)
        .map(|seed| slot(seed, 1))
        .collect();
    assert!(matches!(
        SecretMaterial::new(too_many),
        Err(CodecError::BoundViolation)
    ));
}
