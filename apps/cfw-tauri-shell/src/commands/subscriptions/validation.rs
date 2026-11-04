//! A document reaches the repository only as a validated profile that
//! projects for both modes.

use super::*;

/// Parses and validates a document, and proves it projects for both modes before
/// it can be stored, so an unstartable profile is rejected at import time.
pub(super) fn validated_profile(
    body: &str,
    settings: &EngineSettings,
) -> Result<ValidatedSingBoxProfile, String> {
    let profile = ValidatedSingBoxProfile::parse(body).map_err(|error| error.to_string())?;
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        profile
            .project("00000000-0000-4000-8000-000000000000", mode, settings)
            .map_err(|error| error.to_string())?;
    }
    Ok(profile)
}

pub(super) fn validated_subscription_import(
    body: &str,
    settings: &EngineSettings,
) -> Result<crate::subscription_import::ImportedSubscription, String> {
    let imported = import_subscription_document(body)?;
    validate_subscription_projection(&imported, settings)?;
    Ok(imported)
}

pub(in crate::commands) fn validated_subscription_import_with_namespace(
    body: &str,
    settings: &EngineSettings,
    credential_namespace: uuid::Uuid,
) -> Result<crate::subscription_import::ImportedSubscription, String> {
    let imported =
        import_subscription_document_with_credential_namespace(body, credential_namespace)?;
    validate_subscription_projection(&imported, settings)?;
    Ok(imported)
}

pub(super) fn validated_subscription_import_with_reusable_references(
    body: &str,
    settings: &EngineSettings,
    references: Vec<cfw_singbox_config::CredentialRef>,
) -> Result<crate::subscription_import::ImportedSubscription, String> {
    let imported = import_subscription_document_with_reusable_references(body, references)?;
    validate_subscription_projection(&imported, settings)?;
    Ok(imported)
}

pub(super) fn validate_subscription_projection(
    imported: &crate::subscription_import::ImportedSubscription,
    settings: &EngineSettings,
) -> Result<(), String> {
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        imported
            .profile
            .project("00000000-0000-4000-8000-000000000000", mode, settings)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}
