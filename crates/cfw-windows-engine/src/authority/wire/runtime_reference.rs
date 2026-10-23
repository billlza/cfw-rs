use super::*;

/// A lifetime reference only. It grants no query, assignment, termination or
/// execution rights. Retain it across local worker failure until the service
/// independently resolves cleanup; dropping it is not an Off observation.
#[cfg(windows)]
pub struct RuntimeReference {
    context: LeaseContext,
    _keeper: crate::authority::RuntimeKeeper,
}
#[cfg(windows)]
impl RuntimeReference {
    pub fn context(&self) -> &LeaseContext {
        &self.context
    }
}

pub struct RuntimeReferenceGrant {
    pub(in crate::authority) context: LeaseContext,
    pub(in crate::authority) keeper_handle: u64,
    #[cfg(windows)]
    pub(in crate::authority) keeper: Option<crate::authority::RuntimeKeeper>,
}
impl RuntimeReferenceGrant {
    pub fn context(&self) -> &LeaseContext {
        &self.context
    }
    #[cfg(windows)]
    pub(in crate::authority) fn adopt(
        &mut self,
        owner: &crate::NativePeerProcess,
        verify: impl FnOnce(u64) -> Result<()>,
    ) -> Result<()> {
        if self.keeper.is_some() {
            return Err(WireError::Correlation);
        }
        self.keeper = Some(crate::authority::RuntimeKeeper::adopt(
            self.keeper_handle,
            &self.context.operation.root,
            owner,
            verify,
        )?);
        Ok(())
    }
    #[cfg(windows)]
    pub fn into_reference(mut self) -> Result<RuntimeReference> {
        Ok(RuntimeReference {
            context: self.context,
            _keeper: self.keeper.take().ok_or(WireError::Correlation)?,
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    context: LeaseContext,
    keeper_handle: u64,
}
pub(super) fn encode_reference(id: Uuid, grant: &RuntimeReferenceGrant) -> Result<Message> {
    #[cfg(windows)]
    if grant.keeper.is_some() {
        return Err(WireError::Correlation);
    }
    envelope(
        id,
        ResponseTag::RuntimeRetained,
        &Payload {
            context: grant.context.clone(),
            keeper_handle: grant.keeper_handle,
        },
    )
}
pub(super) fn decode_reference(
    bytes: &[u8],
    context: &LeaseContext,
    owner: &crate::authority_journal::RecordedOwner,
) -> Result<RuntimeReferenceGrant> {
    let value: Payload = decode(bytes)?;
    validate_handle(value.keeper_handle)?;
    if value.context != *context || value.context.operation.owner != *owner {
        return Err(WireError::Correlation);
    }
    Ok(RuntimeReferenceGrant {
        context: value.context,
        keeper_handle: value.keeper_handle,
        #[cfg(windows)]
        keeper: None,
    })
}
