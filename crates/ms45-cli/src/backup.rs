use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ms45_core::flasher::MemoryRegion;
use ms45_core::read_only::{Identity, ReadOnlyAdapter, MAX_READ};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PROGRESS_SCHEMA: &str = "ms45.backup-progress.v1";

#[derive(Clone, Copy)]
pub(crate) struct BackupRequest<'a> {
    pub region: MemoryRegion,
    pub region_name: &'a str,
    pub start: u32,
    pub length: usize,
    pub output: &'a Path,
    pub vin_sha256: &'a str,
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
    blocks: Vec<VerifiedBlock>,
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
) -> Result<(String, usize)> {
    let partial_path = sidecar(request.output, ".partial");
    let progress_path = sidecar(request.output, ".progress.json");
    let mut progress = load_progress(&progress_path, identity, request)?;
    if !partial_path.exists()
        && request.output.exists()
        && total_completed(&progress)? == request.length
    {
        if usize::try_from(std::fs::metadata(request.output)?.len())? != request.length {
            bail!("finalized backup length does not match verified progress");
        }
        verify_partial(request.output, &progress)
            .context("finalized backup does not match verified progress")?;
        let digest = digest_file(request.output)?;
        std::fs::remove_file(&progress_path)?;
        sync_parent(&progress_path)?;
        return Ok((digest, request.length));
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
    let digest = digest_file(&partial_path)?;
    std::fs::rename(&partial_path, request.output).with_context(|| {
        format!(
            "failed to finalize {} as {}",
            partial_path.display(),
            request.output.display()
        )
    })?;
    sync_parent(request.output)?;
    let verified = digest_file(request.output)?;
    if verified != digest {
        bail!("backup verification failed");
    }
    std::fs::remove_file(&progress_path)?;
    sync_parent(&progress_path)?;
    Ok((digest, completed))
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
        blocks: Vec::new(),
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
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(&mut temporary, progress)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    sync_parent(path)
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

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(())
}
