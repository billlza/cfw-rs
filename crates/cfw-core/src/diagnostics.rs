//! Small local diagnostic journals. They never contain configuration objects.
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::SettingsStoreError;
use crate::settings_storage::SecureDirectory;

const MAX_RECORDS: usize = 128;
const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_MESSAGE_CHARS: usize = 2048;

#[derive(Clone, Copy)]
pub enum DiagnosticTopic {
    Startup,
    Network,
    NetworkWarnings,
    Update,
}

impl DiagnosticTopic {
    fn file_name(self) -> &'static str {
        match self {
            Self::Startup => "startup.json",
            Self::Network => "network-errors.json",
            Self::NetworkWarnings => "network-warnings.json",
            Self::Update => "update.json",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticEntry {
    pub unix_ms: u64,
    pub process_id: u32,
    pub product_version: String,
    pub build_number: Option<String>,
    pub source_commit: Option<String>,
    pub code: String,
    pub message: String,
}

impl DiagnosticEntry {
    pub fn new(code: &str, message: &str) -> Result<Self, SettingsStoreError> {
        if code.is_empty()
            || code.len() > 64
            || !code
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(SettingsStoreError::InvalidPath);
        }
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(std::io::Error::other)?;
        let unix_ms = u64::try_from(elapsed.as_millis()).map_err(std::io::Error::other)?;
        Ok(Self {
            unix_ms,
            process_id: std::process::id(),
            product_version: env!("CARGO_PKG_VERSION").to_owned(),
            build_number: option_env!("CFW_BUILD_NUMBER").map(str::to_owned),
            source_commit: option_env!("CFW_REPOSITORY_COMMIT").map(str::to_owned),
            code: code.to_owned(),
            message: redact_diagnostic_text(message)
                .chars()
                .take(MAX_MESSAGE_CHARS)
                .collect(),
        })
    }
}

pub struct DiagnosticJournal {
    logs_directory: PathBuf,
    directory: PathBuf,
}

impl DiagnosticJournal {
    pub fn new(logs_directory: &Path) -> Self {
        Self {
            logs_directory: logs_directory.to_path_buf(),
            directory: logs_directory.join("diagnostics"),
        }
    }

    pub fn append(
        &self,
        topic: DiagnosticTopic,
        batch: &[DiagnosticEntry],
    ) -> Result<(), SettingsStoreError> {
        if batch.is_empty() {
            return Ok(());
        }
        // Validate the parent before creating its private child. In particular,
        // an existing legacy logs symlink must never redirect this journal.
        let _parent = SecureDirectory::open_or_create(&self.logs_directory)?;
        let directory = SecureDirectory::open_or_create(&self.directory)?;
        directory.update_atomic(topic.file_name(), MAX_FILE_BYTES, |previous| {
            let mut entries: Vec<DiagnosticEntry> = match previous {
                Some(bytes) => serde_json::from_slice(bytes)?,
                None => Vec::new(),
            };
            entries.extend_from_slice(batch);
            if entries.len() > MAX_RECORDS {
                entries.drain(..entries.len() - MAX_RECORDS);
            }
            for entry in &mut entries {
                if entry.code.is_empty()
                    || entry.code.len() > 64
                    || !entry
                        .code
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                {
                    return Err(SettingsStoreError::InvalidPath);
                }
                entry.message = redact_diagnostic_text(&entry.message)
                    .chars()
                    .take(MAX_MESSAGE_CHARS)
                    .collect();
            }
            loop {
                let encoded = serde_json::to_vec_pretty(&entries)?;
                if encoded.len() <= MAX_FILE_BYTES {
                    return Ok(encoded);
                }
                // UTF-8 width and JSON escaping are bounded by bytes as well as
                // record count. Rotation removes only the oldest valid record.
                entries.remove(0);
            }
        })
    }
}

/// Redact before truncation, including quoted JSON values and URL userinfo.
/// ASCII matching preserves Unicode byte boundaries in the original message.
pub fn redact_diagnostic_text(value: &str) -> String {
    let mut text: String = value.chars().take(8192).collect();
    let mut cursor = 0;
    while let Some(offset) = text[cursor..].find("://") {
        let start = cursor + offset + 3;
        let end = text[start..]
            .find(|c: char| c.is_whitespace() || matches!(c, '/' | '?' | '#' | '\'' | '"'))
            .map_or(text.len(), |offset| start + offset);
        if let Some(at) = text[start..end].rfind('@') {
            text.replace_range(start..start + at, "[redacted]");
        }
        cursor = start;
        let url_end = text[start..]
            .find(|c: char| c.is_whitespace() || matches!(c, '\'' | '"'))
            .map_or(text.len(), |offset| start + offset);
        if let Some(query) = text[start..url_end].find('?') {
            text.replace_range(start + query..url_end, "?[redacted]");
        }
    }
    cursor = 0;
    while let Some(offset) = text[cursor..].to_ascii_lowercase().find("bearer ") {
        let start = cursor + offset + 7;
        let end = text[start..]
            .find(|c: char| c.is_whitespace() || matches!(c, '\'' | '"' | ',' | ';'))
            .map_or(text.len(), |offset| start + offset);
        text.replace_range(start..end, "[redacted]");
        cursor = start + "[redacted]".len();
    }
    let mut output = String::new();
    cursor = 0;
    while cursor < text.len() {
        let start = cursor;
        let byte = text.as_bytes()[cursor];
        let word = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-');
        if !byte.is_ascii_alphabetic() || (cursor > 0 && word(text.as_bytes()[cursor - 1])) {
            let ch = text[cursor..].chars().next().expect("character boundary");
            output.push(ch);
            cursor += ch.len_utf8();
            continue;
        }
        while cursor < text.len() && word(text.as_bytes()[cursor]) {
            cursor += 1;
        }
        let key = text[start..cursor].to_ascii_lowercase();
        let sensitive = matches!(
            key.as_str(),
            "token"
                | "key"
                | "secret"
                | "password"
                | "passwd"
                | "authorization"
                | "auth"
                | "username"
                | "sig"
                | "signature"
        ) || key.starts_with("x-amz-");
        let mut separator = cursor;
        if matches!(text.as_bytes().get(separator), Some(b'"' | b'\'')) {
            separator += 1;
        }
        while text
            .as_bytes()
            .get(separator)
            .is_some_and(u8::is_ascii_whitespace)
        {
            separator += 1;
        }
        if !sensitive || !matches!(text.as_bytes().get(separator), Some(b':' | b'=')) {
            output.push_str(&text[start..cursor]);
            continue;
        }
        let mut value_start = separator + 1;
        while text
            .as_bytes()
            .get(value_start)
            .is_some_and(u8::is_ascii_whitespace)
        {
            value_start += 1;
        }
        let quote = text
            .as_bytes()
            .get(value_start)
            .copied()
            .filter(|b| matches!(b, b'"' | b'\''));
        if quote.is_some() {
            value_start += 1;
        }
        let mut end = value_start;
        let mut escaped = false;
        while end < text.len() {
            let b = text.as_bytes()[end];
            if let Some(q) = quote {
                if !escaped && b == q {
                    break;
                }
                escaped = !escaped && b == b'\\';
            } else if b.is_ascii_whitespace()
                || matches!(b, b'&' | b',' | b';' | b')' | b'"' | b'\'')
            {
                break;
            }
            end += 1;
        }
        output.push_str(&text[start..value_start]);
        output.push_str("[redacted]");
        cursor = end;
    }
    output
}

#[cfg(test)]
mod tests;
