#[cfg(target_os = "macos")]
use std::fs::{self, File};
#[cfg(target_os = "macos")]
use std::io::Write as _;
#[cfg(target_os = "macos")]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use futures_util::{Stream, StreamExt as _};
use minisign_verify::{PublicKey, Signature};
use reqwest::Url;
use reqwest::header::ACCEPT;
use reqwest::redirect::Policy;
use sha2::{Digest, Sha256};

use super::contract::UpdateAuthorization;
use super::error::{DownloadFailureStage, NetworkFailureCategory, Result, UpdateError};
use super::metadata::{
    CONNECT_TIMEOUT, USER_AGENT, sanitized_network_error, validate_release_asset_url,
};
use super::state::DownloadCancellation;
use crate::transport_security::external_https_client_builder;

// Keep this release/runtime contract aligned with scripts/make_updater_manifest.sh.
pub(super) const MAX_UPDATE_ARCHIVE_BYTES: u64 = 192 * 1024 * 1024;
const UPDATE_REQUEST_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// A transfer that delivers nothing for this long has stalled; the whole
/// request is bounded separately.
const STALL_TIMEOUT: Duration = Duration::from_secs(60);
const EMBEDDED_TAURI_CONFIG: &str = include_str!("../../tauri.conf.json");
const MAX_TRUSTED_COMMENT_BYTES: usize = 1024;
const MAX_ARCHIVE_NAME_BYTES: usize = 255;

/// Re-authenticate an already pinned candidate after process handoff, without
/// downloading again. Callers retain native file/ancestor pins through install.
#[cfg(windows)]
pub(super) fn verify_existing_archive(
    authorization: &UpdateAuthorization,
    path: &Path,
) -> Result<[u8; 32]> {
    let input = std::fs::File::open(path).map_err(|e| UpdateError::Staging {
        stage: "reopen-authorized-package",
        kind: e.kind(),
    })?;
    verify_archive_reader(
        &embedded_public_key()?,
        authorization,
        input,
        MAX_UPDATE_ARCHIVE_BYTES,
    )
}

#[cfg(any(windows, test))]
fn verify_archive_reader(
    key: &PublicKey,
    authorization: &UpdateAuthorization,
    mut input: impl std::io::Read,
    maximum: u64,
) -> Result<[u8; 32]> {
    let signature = decode_signature(&authorization.signature)?;
    let mut verifier = key
        .verify_stream(&signature)
        .map_err(|_| UpdateError::SignatureVerification)?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = input.read(&mut buffer).map_err(|e| UpdateError::Staging {
            stage: "read-authorized-package",
            kind: e.kind(),
        })?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .filter(|n| *n <= maximum)
            .ok_or(UpdateError::ArchiveTooLarge { maximum })?;
        verifier.update(&buffer[..count]);
        digest.update(&buffer[..count]);
    }
    if total == 0 {
        return Err(UpdateError::EmptyArchive);
    }
    verifier
        .finalize()
        .map_err(|_| UpdateError::SignatureVerification)?;
    validate_signature_archive(&signature, &authorization.archive_name)?;
    Ok(digest.finalize().into())
}

/// Downloads the authorized archive and returns the SHA-256 of the exact
/// Minisign-authenticated bytes, for binding subsequent native inspection.
///
/// The file exists afterwards only if every byte was received within bounds
/// and the complete stream matches the release signature for exactly this
/// archive name. Nothing parses the archive before that.
pub(super) async fn download_verified_archive<F>(
    authorization: &UpdateAuthorization,
    destination: &Path,
    cancellation: &DownloadCancellation,
    on_progress: F,
) -> Result<[u8; 32]>
where
    F: FnMut(u64, Option<u64>) -> Result<()>,
{
    let public_key = embedded_public_key()?;
    let expected_url = authorization.download_url.clone();
    let client = external_https_client_builder()
        .map_err(|_| UpdateError::TlsProviderUnavailable)?
        .user_agent(USER_AGENT)
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(UPDATE_REQUEST_TIMEOUT)
        .redirect(Policy::custom(move |attempt| {
            match validate_redirect(&expected_url, attempt.previous(), attempt.url()) {
                Ok(()) => attempt.follow(),
                Err(error) => attempt.error(error),
            }
        }))
        .build()
        .map_err(|error| sanitized_network_error(DownloadFailureStage::ClientBuild, &error))?;

    let request = client
        .get(&authorization.download_url)
        .header(ACCEPT, "application/octet-stream")
        .send();
    tokio::pin!(request);
    let response = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Err(UpdateError::DownloadCancelled),
        response = &mut request => response.map_err(|error| {
            sanitized_network_error(DownloadFailureStage::ArchiveRequest, &error)
        })?,
    };
    if response.url().as_str() != authorization.download_url {
        validate_release_asset_url(response.url()).map_err(UpdateError::Redirect)?;
    }
    if !response.status().is_success() {
        return Err(UpdateError::HttpStatus(response.status()));
    }
    let declared_length = response.content_length();
    let chunks = response.bytes_stream().map(|chunk| {
        chunk.map_err(|error| sanitized_network_error(DownloadFailureStage::ArchiveBody, &error))
    });
    receive_verified_archive(
        &public_key,
        authorization,
        ArchiveBounds {
            declared_length,
            maximum: MAX_UPDATE_ARCHIVE_BYTES,
            stall_timeout: STALL_TIMEOUT,
        },
        chunks,
        destination,
        cancellation,
        on_progress,
    )
    .await
}

#[derive(Debug, Clone, Copy)]
struct ArchiveBounds {
    declared_length: Option<u64>,
    maximum: u64,
    stall_timeout: Duration,
}

async fn receive_verified_archive<S, B, F>(
    public_key: &PublicKey,
    authorization: &UpdateAuthorization,
    bounds: ArchiveBounds,
    chunks: S,
    destination: &Path,
    cancellation: &DownloadCancellation,
    mut on_progress: F,
) -> Result<[u8; 32]>
where
    S: Stream<Item = Result<B>>,
    B: AsRef<[u8]>,
    F: FnMut(u64, Option<u64>) -> Result<()>,
{
    let signature = decode_signature(&authorization.signature)?;
    // Reject an obviously replayed signature before any transfer. The same
    // check is repeated after finalize(), when the comment is authenticated.
    validate_signature_archive(&signature, &authorization.archive_name)?;
    let mut verifier = public_key
        .verify_stream(&signature)
        .map_err(|_| UpdateError::SignatureVerification)?;
    if let Some(declared) = bounds.declared_length
        && declared > bounds.maximum
    {
        return Err(UpdateError::DeclaredArchiveTooLarge {
            declared,
            maximum: bounds.maximum,
        });
    }

    let mut partial = PartialArchive::create(destination)?;
    let mut digest = Sha256::new();
    let mut received = 0_u64;
    tokio::pin!(chunks);
    loop {
        let next = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(UpdateError::DownloadCancelled),
            next = tokio::time::timeout(bounds.stall_timeout, chunks.next()) => {
                next.map_err(|_| UpdateError::Network {
                    stage: DownloadFailureStage::ArchiveBody,
                    category: NetworkFailureCategory::Timeout,
                    status_code: None,
                })?
            }
        };
        let Some(chunk) = next else {
            break;
        };
        let chunk = chunk?;
        let chunk = chunk.as_ref();
        received = received
            .checked_add(chunk.len() as u64)
            .filter(|total| *total <= bounds.maximum)
            .ok_or(UpdateError::ArchiveTooLarge {
                maximum: bounds.maximum,
            })?;
        partial.write(chunk)?;
        verifier.update(chunk);
        digest.update(chunk);
        on_progress(received, bounds.declared_length)?;
    }
    if received == 0 {
        return Err(UpdateError::EmptyArchive);
    }
    if let Some(declared) = bounds.declared_length
        && declared != received
    {
        return Err(UpdateError::ArchiveLengthMismatch {
            declared,
            actual: received,
        });
    }
    verifier
        .finalize()
        .map_err(|_| UpdateError::SignatureVerification)?;
    validate_signature_archive(&signature, &authorization.archive_name)?;
    partial.commit()?;
    Ok(digest.finalize().into())
}

/// The archive file while it is still unauthenticated. Dropping it without
/// `commit` removes the file, so no failed transfer leaves bytes behind.
struct PartialArchive {
    #[cfg(target_os = "macos")]
    path: PathBuf,
    #[cfg(target_os = "macos")]
    file: Option<File>,
    #[cfg(windows)]
    stream: Option<cfw_windows_storage::StreamedFile>,
}

#[cfg(target_os = "macos")]
impl PartialArchive {
    fn create(path: &Path) -> Result<Self> {
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(staging_error("create-archive"))?;
        Ok(Self {
            path: path.to_path_buf(),
            file: Some(file),
        })
    }

    fn write(&mut self, chunk: &[u8]) -> Result<()> {
        self.file
            .as_mut()
            .expect("an uncommitted archive keeps its file")
            .write_all(chunk)
            .map_err(staging_error("write-archive"))
    }

    fn commit(mut self) -> Result<()> {
        let file = self
            .file
            .take()
            .expect("an uncommitted archive keeps its file");
        if let Err(error) = file.sync_all() {
            self.file = Some(file);
            return Err(staging_error("sync-archive")(error));
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl Drop for PartialArchive {
    fn drop(&mut self) {
        if self.file.take().is_some()
            && let Err(error) = fs::remove_file(&self.path)
        {
            eprintln!("failed to remove an unauthenticated update archive: {error}");
        }
    }
}

#[cfg(windows)]
impl PartialArchive {
    fn create(path: &Path) -> Result<Self> {
        let parent = path.parent().ok_or_else(|| {
            storage_error("create-archive")(cfw_windows_storage::Error::InvalidName)
        })?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                storage_error("create-archive")(cfw_windows_storage::Error::InvalidName)
            })?;
        // Staging owns creation and admission of the transaction directory.
        // A missing or unsafe parent is never silently created by a download.
        let directory = cfw_windows_storage::PrivateDirectory::open_existing(parent)
            .map_err(storage_error("open-archive-directory"))?
            .ok_or(UpdateError::Staging {
                stage: "open-archive-directory",
                kind: std::io::ErrorKind::NotFound,
            })?;
        let temporary = format!(".{name}.{}.tmp", uuid::Uuid::new_v4());
        let stream = directory
            .begin_stream(name, &temporary, MAX_UPDATE_ARCHIVE_BYTES as usize)
            .map_err(storage_error("create-archive"))?;
        Ok(Self {
            stream: Some(stream),
        })
    }

    fn write(&mut self, chunk: &[u8]) -> Result<()> {
        self.stream
            .as_mut()
            .expect("an uncommitted archive keeps its stream")
            .write_chunk(chunk)
            .map_err(storage_error("write-archive"))
    }

    fn commit(mut self) -> Result<()> {
        self.stream
            .take()
            .expect("an uncommitted archive keeps its stream")
            .commit()
            .map_err(storage_error("publish-archive"))
    }
}

#[cfg(windows)]
impl Drop for PartialArchive {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take()
            && let Err(error) = stream.discard()
        {
            eprintln!("failed to remove an unauthenticated update archive: {error}");
        }
    }
}

#[cfg(windows)]
fn storage_error(stage: &'static str) -> impl Fn(cfw_windows_storage::Error) -> UpdateError {
    move |source| UpdateError::WindowsStorage { stage, source }
}

#[cfg(target_os = "macos")]
fn staging_error(stage: &'static str) -> impl Fn(std::io::Error) -> UpdateError {
    move |error| UpdateError::Staging {
        stage,
        kind: error.kind(),
    }
}

fn validate_redirect(
    expected_url: &str,
    previous: &[Url],
    target: &Url,
) -> std::result::Result<(), String> {
    if previous.len() != 1 || previous[0].as_str() != expected_url {
        return Err("only one redirect from the canonical GitHub URL is allowed".into());
    }
    validate_release_asset_url(target)
}

fn embedded_public_key() -> Result<PublicKey> {
    let config: serde_json::Value =
        serde_json::from_str(EMBEDDED_TAURI_CONFIG).map_err(|_| UpdateError::InvalidPublicKey)?;
    let encoded = config
        .pointer("/plugins/updater/pubkey")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(UpdateError::InvalidPublicKey)?;
    let envelope = decode_base64_utf8(encoded).ok_or(UpdateError::InvalidPublicKey)?;
    PublicKey::decode(&envelope).map_err(|_| UpdateError::InvalidPublicKey)
}

fn decode_signature(encoded: &str) -> Result<Signature> {
    let envelope = decode_base64_utf8(encoded).ok_or(UpdateError::InvalidSignature)?;
    Signature::decode(envelope.trim()).map_err(|_| UpdateError::InvalidSignature)
}

fn validate_signature_archive(signature: &Signature, expected_archive: &str) -> Result<()> {
    if parse_trusted_comment(signature.trusted_comment())? != expected_archive {
        return Err(UpdateError::SignatureArchiveMismatch);
    }
    Ok(())
}

// Keep this grammar identical to the release verifier in
// crates/cfw-release-verifier/src/main.rs, which is built in isolation and
// cannot share code with the application. Minisign authenticates this trusted
// comment only when stream finalization succeeds.
fn parse_trusted_comment(comment: &str) -> Result<&str> {
    if comment.len() > MAX_TRUSTED_COMMENT_BYTES
        || comment
            .bytes()
            .any(|byte| byte.is_ascii_control() && byte != b'\t')
    {
        return Err(UpdateError::InvalidSignatureComment);
    }
    let mut fields = comment.split('\t');
    let timestamp = fields
        .next()
        .and_then(|field| field.strip_prefix("timestamp:"))
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or(UpdateError::InvalidSignatureComment)?;
    if timestamp.len() > 20
        || timestamp
            .parse::<u64>()
            .map_or(true, |parsed| parsed.to_string() != timestamp)
    {
        return Err(UpdateError::InvalidSignatureComment);
    }
    let archive = fields
        .next()
        .and_then(|field| field.strip_prefix("file:"))
        .filter(|value| {
            !value.is_empty()
                && !matches!(*value, "." | "..")
                && value.len() <= MAX_ARCHIVE_NAME_BYTES
                && !value.contains(['/', '\\', ':'])
                && value.bytes().all(|byte| !byte.is_ascii_control())
        })
        .ok_or(UpdateError::InvalidSignatureComment)?;
    if fields.next().is_some() {
        return Err(UpdateError::InvalidSignatureComment);
    }
    Ok(archive)
}

fn decode_base64_utf8(encoded: &str) -> Option<String> {
    String::from_utf8(STANDARD.decode(encoded).ok()?).ok()
}

#[cfg(test)]
mod tests;
