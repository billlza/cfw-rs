//! The hand-off's documents: their canonical encoding and validation, the
//! ticket's time window, and the sweep of stale documents.

use super::*;

impl StartupTicket {
    pub(super) fn validate_at(&self, now_unix_ms: u64) -> Result<(), String> {
        if self.schema_version != TICKET_SCHEMA_VERSION
            || self.document != TICKET_DOCUMENT
            || require_canonical_token(&self.token).is_err()
            || !valid_ticket_window(self.issued_at_unix_ms, self.expires_at_unix_ms, now_unix_ms)
            || self.parent.uid != unsafe { libc::geteuid() }
            || self.parent.pid == 0
            || !self.parent.start_identity.is_valid()
            || self.parent.executable != self.child_executable
            || !self.child_executable.is_absolute()
            || self.child_argv != child_argv(&self.token)
            || validate_renderer_challenges(&self.token, &self.renderer_challenges).is_err()
        {
            return Err("migration handoff startup ticket is invalid".into());
        }
        Ok(())
    }
}

impl ReadyAcknowledgement {
    pub(super) fn validate(&self, ticket: &StartupTicket, expected_pid: u32) -> Result<(), String> {
        if self.schema_version != READY_SCHEMA_VERSION
            || self.document != READY_DOCUMENT
            || self.token != ticket.token
            || self.issued_at_unix_ms != ticket.issued_at_unix_ms
            || self.expires_at_unix_ms != ticket.expires_at_unix_ms
            || !valid_ticket_window(
                self.issued_at_unix_ms,
                self.expires_at_unix_ms,
                current_unix_ms()?,
            )
            || self.child.uid != unsafe { libc::geteuid() }
            || self.child.pid == 0
            || self.child.pid != expected_pid
            || !self.child.start_identity.is_valid()
            || self.child.executable != ticket.child_executable
            || self.window_label != READY_WINDOW_LABEL
            || !ticket.renderer_challenges.contains(&self.renderer)
        {
            return Err("migration handoff ready acknowledgement is invalid".into());
        }
        Ok(())
    }
}

pub(super) fn child_argv(token: &str) -> Vec<String> {
    vec![HANDOFF_FLAG.into(), TICKET_FLAG.into(), token.into()]
}

pub(super) fn require_canonical_token(value: &str) -> Result<(), String> {
    if Uuid::parse_str(value).is_ok_and(|parsed| parsed.hyphenated().to_string() == value) {
        Ok(())
    } else {
        Err("migration handoff token is not a canonical lowercase UUID".into())
    }
}

pub(super) fn new_renderer_challenges(
    startup_token: &str,
) -> Result<Vec<RendererReadyChallenge>, String> {
    let mut seen = std::collections::BTreeSet::from([startup_token.to_owned()]);
    let mut challenges = Vec::with_capacity(RENDERER_CHALLENGE_COUNT);
    for index in 0..RENDERER_CHALLENGE_COUNT {
        let challenge = Uuid::new_v4().hyphenated().to_string();
        if !seen.insert(challenge.clone()) {
            return Err(
                "renderer-ready challenge generation collided with existing authority".into(),
            );
        }
        challenges.push(RendererReadyChallenge {
            generation: u32::try_from(index + 1)
                .map_err(|_| "renderer-ready generation exceeds u32".to_owned())?,
            challenge,
        });
    }
    validate_renderer_challenges(startup_token, &challenges)?;
    Ok(challenges)
}

fn validate_renderer_challenges(
    startup_token: &str,
    challenges: &[RendererReadyChallenge],
) -> Result<(), String> {
    if challenges.len() != RENDERER_CHALLENGE_COUNT {
        return Err("migration handoff renderer challenge count is invalid".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for (index, challenge) in challenges.iter().enumerate() {
        let expected_generation = u32::try_from(index + 1)
            .map_err(|_| "renderer-ready generation exceeds u32".to_owned())?;
        if challenge.generation != expected_generation
            || require_canonical_renderer_challenge(&challenge.challenge).is_err()
            || challenge.challenge == startup_token
            || !seen.insert(challenge.challenge.as_str())
        {
            return Err(
                "migration handoff renderer challenges are not canonical and unique".into(),
            );
        }
    }
    Ok(())
}

pub(super) fn require_canonical_renderer_challenge(value: &str) -> Result<(), String> {
    if value.len() != 36 {
        return Err("renderer-ready challenge has the wrong length".into());
    }
    let parsed = Uuid::parse_str(value)
        .map_err(|_| "renderer-ready challenge is not a canonical UUIDv4".to_owned())?;
    if parsed.get_version_num() != 4 || parsed.hyphenated().to_string() != value {
        return Err("renderer-ready challenge is not a canonical UUIDv4".into());
    }
    Ok(())
}

pub(super) fn current_unix_ms() -> Result<u64, String> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock predates the Unix epoch".to_owned())?;
    u64::try_from(elapsed.as_millis())
        .map_err(|_| "system clock does not fit the handoff timestamp format".to_owned())
}

pub(super) fn duration_millis(duration: Duration) -> Result<u64, String> {
    u64::try_from(duration.as_millis())
        .map_err(|_| "handoff duration does not fit the timestamp format".to_owned())
}

fn valid_ticket_window(issued_at_unix_ms: u64, expires_at_unix_ms: u64, now: u64) -> bool {
    let Ok(skew_ms) = duration_millis(TICKET_CLOCK_SKEW) else {
        return false;
    };
    canonical_ticket_window(issued_at_unix_ms, expires_at_unix_ms)
        && issued_at_unix_ms <= now.saturating_add(skew_ms)
        && now <= expires_at_unix_ms
}

fn canonical_ticket_window(issued_at_unix_ms: u64, expires_at_unix_ms: u64) -> bool {
    let Ok(lifetime_ms) = duration_millis(TICKET_LIFETIME) else {
        return false;
    };
    issued_at_unix_ms > 0
        && issued_at_unix_ms
            .checked_add(lifetime_ms)
            .is_some_and(|expiry| expiry == expires_at_unix_ms)
}

pub(super) fn ticket_filename(token: &str) -> String {
    format!("ticket-{token}.json")
}

pub(super) fn ready_filename(token: &str) -> String {
    format!("ready-{token}.json")
}

pub(super) fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to encode migration handoff document: {error}"))?;
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err("migration handoff document exceeds 16 KiB".into());
    }
    Ok(bytes)
}

pub(super) fn decode_canonical<T>(bytes: &[u8], label: &str) -> Result<T, String>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.is_empty() || bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(format!("{label} is empty or oversized"));
    }
    let value = serde_json::from_slice::<T>(bytes)
        .map_err(|error| format!("{label} is invalid: {error}"))?;
    if canonical_bytes(&value)? != bytes {
        return Err(format!("{label} is not canonical JSON"));
    }
    Ok(value)
}

impl PrivateDirectory {
    pub(super) fn sweep_stale(&self, now_unix_ms: u64) -> Result<(), String> {
        let entries = self.entry_names()?;
        let grace = duration_millis(STALE_DOCUMENT_GRACE)?;
        for name in entries {
            let Some((file, bytes)) = self.read_locked_optional(&name)? else {
                continue;
            };
            let (token, expires_at_unix_ms) = if let Some(token) = document_token(&name, "ticket-")
            {
                let ticket: StartupTicket = decode_canonical(&bytes, "stale startup ticket")?;
                if ticket.schema_version != TICKET_SCHEMA_VERSION
                    || ticket.document != TICKET_DOCUMENT
                    || ticket.token != token
                    || !canonical_ticket_window(ticket.issued_at_unix_ms, ticket.expires_at_unix_ms)
                {
                    return Err("stale startup ticket identity is invalid".into());
                }
                (ticket.token, ticket.expires_at_unix_ms)
            } else if let Some(token) = document_token(&name, "ready-") {
                let ready: ReadyAcknowledgement =
                    decode_canonical(&bytes, "stale readiness acknowledgement")?;
                if ready.schema_version != READY_SCHEMA_VERSION
                    || ready.document != READY_DOCUMENT
                    || ready.token != token
                    || !canonical_ticket_window(ready.issued_at_unix_ms, ready.expires_at_unix_ms)
                {
                    return Err("stale readiness acknowledgement identity is invalid".into());
                }
                (ready.token, ready.expires_at_unix_ms)
            } else {
                return Err(format!(
                    "handoff directory contains unexpected document {name:?}"
                ));
            };
            debug_assert!(name.contains(&token));
            if now_unix_ms > expires_at_unix_ms.saturating_add(grace) {
                self.unlink_locked(&name, file)?;
            }
        }
        Ok(())
    }
}

fn document_token(name: &str, prefix: &str) -> Option<String> {
    let token = name.strip_prefix(prefix)?.strip_suffix(".json")?;
    require_canonical_token(token).ok()?;
    Some(token.to_owned())
}
