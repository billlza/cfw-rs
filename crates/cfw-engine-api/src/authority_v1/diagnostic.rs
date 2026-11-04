//! Diagnostics of Authority failures that carry no secret.

use super::*;

/// Bounded, non-secret diagnostic metadata for Authority failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityDiagnostic {
    kind: BackendErrorKind,
    operation_id: Option<Uuid>,
    generation: Option<u64>,
    role: Option<AuthorityRole>,
    digest_prefix: Option<String>,
}

impl AuthorityDiagnostic {
    pub fn new(kind: BackendErrorKind) -> Self {
        Self {
            kind,
            operation_id: None,
            generation: None,
            role: None,
            digest_prefix: None,
        }
    }

    pub fn with_operation(mut self, operation_id: Uuid, generation: u64) -> Self {
        self.operation_id = Some(operation_id);
        self.generation = Some(generation);
        self
    }

    pub fn with_role(mut self, role: AuthorityRole) -> Self {
        self.role = Some(role);
        self
    }

    pub fn with_digest(mut self, digest: &str) -> Result<Self, CodecError> {
        if !is_digest(digest) {
            return Err(CodecError::BoundViolation);
        }
        self.digest_prefix = Some(digest[..12].to_owned());
        Ok(self)
    }
}

impl fmt::Display for AuthorityDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = serde_json::to_value(self.kind)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "internal".to_owned());
        write!(formatter, "code={code}")?;
        if let Some(operation_id) = self.operation_id {
            write!(formatter, " operation_id={operation_id}")?;
        }
        if let Some(generation) = self.generation {
            write!(formatter, " generation={generation}")?;
        }
        if let Some(role) = self.role {
            let role = serde_json::to_value(role)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "unknown".to_owned());
            write!(formatter, " role={role}")?;
        }
        if let Some(prefix) = &self.digest_prefix {
            write!(formatter, " digest_prefix={prefix}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
