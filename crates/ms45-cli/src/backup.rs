use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use ms45_core::flasher::MemoryRegion;
use ms45_core::read_only::{Identity, ReadOnlyAdapter, MAX_READ};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PROGRESS_SCHEMA: &str = "ms45.backup-progress.v2";
const MANIFEST_SCHEMA: &str = "ms45.backup-manifest.v1";
const ENCRYPTED_MANIFEST_SCHEMA: &str = "ms45.backup-manifest.v2";
const PROTOCOL_VERSION: &str = "MS45R1";
pub(crate) const ADAPTER_TIMEOUT: Duration = Duration::from_secs(3);
pub(crate) const READ_PASSES: usize = 2;

#[derive(Clone, Copy)]
pub(crate) struct BackupRequest<'a> {
    pub region: MemoryRegion,
    pub region_name: &'a str,
    pub start: u32,
    pub length: usize,
    pub output: &'a Path,
    pub vin_sha256: &'a str,
    pub bridge_version: &'a str,
    pub encryption: Option<&'a EncryptionCommand>,
}

pub(crate) struct EncryptionCommand {
    pub program: PathBuf,
    pub args: Vec<OsString>,
}

pub(crate) struct BackupOutcome {
    pub plaintext_sha256: String,
    pub output_sha256: String,
    pub resumed_bytes: usize,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Progress {
    schema_version: String,
    variant: String,
    hardware_reference: String,
    software_reference: String,
    vin_sha256: String,
    region: String,
    start: u32,
    length: usize,
    block_size: usize,
    started_at: String,
    bridge_version: String,
    blocks: Vec<VerifiedBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encrypted_publication: Option<EncryptedPublication>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EncryptedPublication {
    length: usize,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct BackupManifest<'a> {
    schema_version: &'static str,
    ecu_identity_hashes: IdentityHashes,
    address_range: AddressRange<'a>,
    timestamps: Timestamps<'a>,
    binary: Binary<'a>,
    bridge_version: &'a str,
    cli_version: &'static str,
    read_parameters: ReadParameters,
    #[serde(skip_serializing_if = "Option::is_none")]
    plaintext: Option<Plaintext<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption: Option<Encryption<'a>>,
}

#[derive(Debug, Serialize)]
struct IdentityHashes {
    variant_sha256: String,
    hardware_reference_sha256: String,
    software_reference_sha256: String,
    vin_sha256: String,
}

#[derive(Debug, Serialize)]
struct AddressRange<'a> {
    region: &'a str,
    start: u32,
    end_exclusive: u32,
    length: usize,
}

#[derive(Debug, Serialize)]
struct Timestamps<'a> {
    started_at: &'a str,
    completed_at: &'a str,
}

#[derive(Debug, Serialize)]
struct Binary<'a> {
    file_name: String,
    length: usize,
    sha256: &'a str,
}

#[derive(Debug, Serialize)]
struct Plaintext<'a> {
    length: usize,
    sha256: &'a str,
}

#[derive(Debug, Serialize)]
struct Encryption<'a> {
    method: &'static str,
    command: &'a str,
}

#[derive(Debug, Serialize)]
struct ReadParameters {
    protocol: &'static str,
    block_size: usize,
    timeout_milliseconds: u64,
    passes: usize,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VerifiedBlock {
    offset: usize,
    length: usize,
    sha256: String,
}

pub(crate) fn run(
    session: &mut ReadOnlyAdapter,
    identity: &Identity,
    request: BackupRequest<'_>,
) -> Result<BackupOutcome> {
    let partial_path = sidecar(request.output, ".partial");
    let progress_path = sidecar(request.output, ".progress.json");
    let manifest_path = manifest_path(request.output);
    let mut progress = load_progress(&progress_path, identity, request)?;
    let completed = total_completed(&progress)?;
    if manifest_path.exists() {
        bail!(
            "refusing to overwrite existing backup manifest {}",
            manifest_path.display()
        );
    }
    if request.output.exists() {
        if completed != request.length {
            bail!(
                "refusing to overwrite existing backup output {}",
                request.output.display()
            );
        }
        if partial_path.exists() {
            verify_partial(&partial_path, &progress)
                .context("recovery partial does not match verified progress")?;
        }
        let plaintext_digest = if request.encryption.is_some() {
            let publication = progress
                .encrypted_publication
                .as_ref()
                .context("encrypted backup output exists without verified publication metadata")?;
            let output_len = usize::try_from(std::fs::metadata(request.output)?.len())?;
            if output_len != publication.length
                || digest_file(request.output)? != publication.sha256
            {
                bail!("encrypted backup output does not match verified publication metadata");
            }
            digest_file(&partial_path)?
        } else {
            if usize::try_from(std::fs::metadata(request.output)?.len())? != request.length {
                bail!("finalized backup length does not match verified progress");
            }
            verify_partial(request.output, &progress)
                .context("finalized backup does not match verified progress")?;
            digest_file(request.output)?
        };
        verify_second_pass(session, request, &plaintext_digest)?;
        let output_digest = digest_file(request.output)?;
        write_manifest(
            &manifest_path,
            identity,
            request,
            &progress.started_at,
            &plaintext_digest,
            &output_digest,
        )?;
        cleanup_recovery_files(&partial_path, &progress_path)?;
        return Ok(BackupOutcome {
            plaintext_sha256: plaintext_digest,
            output_sha256: output_digest,
            resumed_bytes: request.length,
        });
    }
    if partial_path.exists() && !progress_path.exists() {
        bail!(
            "refusing to overwrite orphaned backup partial {}",
            partial_path.display()
        );
    }
    let completed = verify_partial(&partial_path, &progress)?;
    let mut partial = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&partial_path)
        .with_context(|| format!("failed to open {}", partial_path.display()))?;

    // Bytes beyond the last durable manifest entry may have come from an
    // interrupted write. Never treat them as a completed adapter read.
    partial.set_len(completed as u64)?;
    partial.seek(SeekFrom::Start(completed as u64))?;

    while total_completed(&progress)? < request.length {
        let offset = total_completed(&progress)?;
        let block_len = (request.length - offset).min(MAX_READ);
        let address = request
            .start
            .checked_add(u32::try_from(offset).context("backup offset overflow")?)
            .context("backup address overflow")?;
        let block = session.read(request.region, address, block_len)?;
        if block.len() != block_len {
            bail!("adapter returned an ambiguous partial block");
        }
        partial.write_all(&block)?;
        partial.sync_data()?;
        partial.seek(SeekFrom::Start(offset as u64))?;
        let mut disk_block = vec![0; block_len];
        partial.read_exact(&mut disk_block)?;
        if disk_block != block {
            bail!("backup block failed on-disk verification");
        }
        partial.seek(SeekFrom::End(0))?;
        progress.blocks.push(VerifiedBlock {
            offset,
            length: block_len,
            sha256: hex_digest(&block),
        });
        persist_progress(&progress_path, &progress)?;
    }

    partial.sync_all()?;
    drop(partial);
    let plaintext_digest = digest_file(&partial_path)?;
    verify_second_pass(session, request, &plaintext_digest)?;
    let output_digest = if let Some(encryption) = request.encryption {
        publish_encrypted(
            &partial_path,
            request.output,
            encryption,
            &progress_path,
            &mut progress,
        )?
    } else {
        std::fs::hard_link(&partial_path, request.output).with_context(|| {
            format!(
                "failed to finalize {} as {}",
                partial_path.display(),
                request.output.display()
            )
        })?;
        plaintext_digest.clone()
    };
    sync_parent(request.output)?;
    write_manifest(
        &manifest_path,
        identity,
        request,
        &progress.started_at,
        &plaintext_digest,
        &output_digest,
    )?;
    cleanup_recovery_files(&partial_path, &progress_path)?;
    Ok(BackupOutcome {
        plaintext_sha256: plaintext_digest,
        output_sha256: output_digest,
        resumed_bytes: completed,
    })
}

fn publish_encrypted(
    plaintext: &Path,
    output: &Path,
    encryption: &EncryptionCommand,
    progress_path: &Path,
    progress: &mut Progress,
) -> Result<String> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let temporary = tempfile::NamedTempFile::new_in(parent)?;
    let input = File::open(plaintext)?;
    let stdout = temporary.reopen()?;
    let status = Command::new(&encryption.program)
        .args(&encryption.args)
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(stdout))
        .status()
        .with_context(|| {
            format!(
                "failed to start encryption command {}",
                encryption.program.display()
            )
        })?;
    if !status.success() {
        bail!(
            "encryption command {} failed with {status}",
            encryption.program.display()
        );
    }
    temporary.as_file().sync_all()?;
    let length = usize::try_from(temporary.as_file().metadata()?.len())?;
    if length == 0 {
        bail!("encryption command produced empty output");
    }
    let sha256 = digest_file(temporary.path())?;
    progress.encrypted_publication = Some(EncryptedPublication {
        length,
        sha256: sha256.clone(),
    });
    persist_progress(progress_path, progress)?;
    temporary
        .persist_noclobber(output)
        .map_err(|error| error.error)
        .with_context(|| {
            format!(
                "failed to finalize encrypted backup as {}",
                output.display()
            )
        })?;
    Ok(sha256)
}

fn cleanup_recovery_files(partial_path: &Path, progress_path: &Path) -> Result<()> {
    if partial_path.exists() {
        std::fs::remove_file(partial_path)?;
    }
    std::fs::remove_file(progress_path)?;
    sync_parent(progress_path)
}

fn verify_second_pass(
    session: &mut ReadOnlyAdapter,
    request: BackupRequest<'_>,
    first_pass_digest: &str,
) -> Result<()> {
    let mut digest = Sha256::new();
    let mut offset = 0usize;
    while offset < request.length {
        let block_len = (request.length - offset).min(MAX_READ);
        let address = request
            .start
            .checked_add(u32::try_from(offset).context("backup offset overflow")?)
            .context("backup address overflow")?;
        let block = session
            .read(request.region, address, block_len)
            .context("backup verification read failed")?;
        if block.len() != block_len {
            bail!("adapter returned an ambiguous verification block");
        }
        digest.update(&block);
        offset = offset
            .checked_add(block_len)
            .context("backup verification length overflow")?;
    }
    let second_pass_digest = format!("{:x}", digest.finalize());
    if second_pass_digest != first_pass_digest {
        bail!("backup verification failed: independent read pass hashes do not match");
    }
    Ok(())
}

fn load_progress(path: &Path, identity: &Identity, request: BackupRequest<'_>) -> Result<Progress> {
    let expected = Progress {
        schema_version: PROGRESS_SCHEMA.into(),
        variant: identity.variant.clone(),
        hardware_reference: identity.hardware_reference.clone(),
        software_reference: identity.software_reference.clone(),
        vin_sha256: request.vin_sha256.into(),
        region: request.region_name.into(),
        start: request.start,
        length: request.length,
        block_size: MAX_READ,
        started_at: now(),
        bridge_version: request.bridge_version.into(),
        blocks: Vec::new(),
        encrypted_publication: None,
    };
    if !path.exists() {
        return Ok(expected);
    }
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read backup progress {}", path.display()))?;
    let saved: Progress = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid backup progress {}", path.display()))?;
    if saved.schema_version != expected.schema_version
        || saved.variant != expected.variant
        || saved.hardware_reference != expected.hardware_reference
        || saved.software_reference != expected.software_reference
        || saved.vin_sha256 != expected.vin_sha256
        || saved.region != expected.region
        || saved.start != expected.start
        || saved.length != expected.length
        || saved.block_size != expected.block_size
        || saved.bridge_version != expected.bridge_version
    {
        bail!("backup progress does not match ECU identity or requested range");
    }
    Ok(saved)
}

fn verify_partial(path: &Path, progress: &Progress) -> Result<usize> {
    if progress.blocks.is_empty() {
        return Ok(0);
    }
    let mut file = File::open(path).with_context(|| {
        format!(
            "verified backup progress exists but {} is missing",
            path.display()
        )
    })?;
    let file_len = usize::try_from(file.metadata()?.len()).context("partial file is too large")?;
    let mut completed = 0usize;
    for (index, block) in progress.blocks.iter().enumerate() {
        if completed >= progress.length {
            bail!("backup progress exceeds requested length");
        }
        let expected_len = (progress.length - completed).min(progress.block_size);
        if block.offset != completed || block.length != expected_len || block.length == 0 {
            bail!("backup progress contains noncontiguous or invalid blocks");
        }
        let mut bytes = vec![0; block.length];
        file.read_exact(&mut bytes)
            .context("partial backup is shorter than verified progress")?;
        if hex_digest(&bytes) != block.sha256 {
            bail!("partial backup block {index} failed verification");
        }
        completed = completed
            .checked_add(block.length)
            .context("backup progress length overflow")?;
    }
    if completed > progress.length || file_len < completed {
        bail!("backup progress exceeds requested length");
    }
    Ok(completed)
}

fn total_completed(progress: &Progress) -> Result<usize> {
    progress.blocks.iter().try_fold(0usize, |total, block| {
        total
            .checked_add(block.length)
            .context("backup progress length overflow")
    })
}

fn persist_progress(path: &Path, progress: &Progress) -> Result<()> {
    persist_json(path, progress, true)
}

fn persist_json(path: &Path, value: &impl Serialize, replace: bool) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(&mut temporary, value)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    let persisted = if replace {
        temporary.persist(path)
    } else {
        temporary.persist_noclobber(path)
    };
    if let Err(error) = persisted {
        let persistence_error = error.error;
        let recovery = error.file.keep();
        return match recovery {
            Ok((_file, recovery_path)) => Err(persistence_error).with_context(|| {
                format!(
                    "failed to persist {}; recovery data retained at {}",
                    path.display(),
                    recovery_path.display()
                )
            }),
            Err(keep_error) => Err(persistence_error).with_context(|| {
                format!(
                    "failed to persist {} and retain recovery data: {}",
                    path.display(),
                    keep_error.error
                )
            }),
        };
    }
    sync_parent(path)
}

fn write_manifest(
    path: &Path,
    identity: &Identity,
    request: BackupRequest<'_>,
    started_at: &str,
    plaintext_digest: &str,
    output_digest: &str,
) -> Result<()> {
    let completed_at = now();
    let end_exclusive = request
        .start
        .checked_add(u32::try_from(request.length).context("backup length overflow")?)
        .context("backup address overflow")?;
    let file_name = request
        .output
        .file_name()
        .context("backup output must name a file")?
        .to_string_lossy()
        .into_owned();
    let manifest = BackupManifest {
        schema_version: if request.encryption.is_some() {
            ENCRYPTED_MANIFEST_SCHEMA
        } else {
            MANIFEST_SCHEMA
        },
        ecu_identity_hashes: IdentityHashes {
            variant_sha256: hex_digest(identity.variant.as_bytes()),
            hardware_reference_sha256: hex_digest(identity.hardware_reference.as_bytes()),
            software_reference_sha256: hex_digest(identity.software_reference.as_bytes()),
            vin_sha256: request.vin_sha256.into(),
        },
        address_range: AddressRange {
            region: request.region_name,
            start: request.start,
            end_exclusive,
            length: request.length,
        },
        timestamps: Timestamps {
            started_at,
            completed_at: &completed_at,
        },
        binary: Binary {
            file_name,
            length: usize::try_from(std::fs::metadata(request.output)?.len())?,
            sha256: output_digest,
        },
        bridge_version: request.bridge_version,
        cli_version: env!("CARGO_PKG_VERSION"),
        read_parameters: ReadParameters {
            protocol: PROTOCOL_VERSION,
            block_size: MAX_READ,
            timeout_milliseconds: ADAPTER_TIMEOUT.as_millis() as u64,
            passes: READ_PASSES,
        },
        plaintext: request.encryption.map(|_| Plaintext {
            length: request.length,
            sha256: plaintext_digest,
        }),
        encryption: request.encryption.map(|value| Encryption {
            method: "external-command-stdin-stdout",
            command: value.program.to_str().unwrap_or("<non-UTF-8 executable>"),
        }),
    };
    persist_json(path, &manifest, false)
        .with_context(|| format!("failed to write backup manifest {}", path.display()))
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn digest_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    std::io::copy(&mut file, &mut digest)?;
    Ok(format!("{:x}", digest.finalize()))
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sidecar(output: &Path, suffix: &str) -> PathBuf {
    let mut value = output.as_os_str().to_os_string();
    value.push(suffix);
    value.into()
}

pub(crate) fn manifest_path(output: &Path) -> PathBuf {
    sidecar(output, ".manifest.json")
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(())
}
