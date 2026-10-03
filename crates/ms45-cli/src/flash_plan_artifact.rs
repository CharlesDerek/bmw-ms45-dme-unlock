use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SCHEMA_VERSION: &str = "ms45.flash-plan.v1";
const OPERATIONS: [&str; 7] = [
    "identify",
    "request_programming_security_access",
    "erase_segments",
    "write_blocks",
    "verify_block_readback",
    "check_signature",
    "reset",
];

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedFlashPlan {
    pub schema_version: String,
    pub plan: FlashPlanDocument,
    pub signing: Signing,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FlashPlanDocument {
    pub approved_identity: ApprovedIdentity,
    pub block_size: usize,
    pub segments: Vec<Segment>,
    pub intended_operations: Vec<String>,
    pub signature_target: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApprovedIdentity {
    pub variant: String,
    pub hardware_reference: String,
    pub software_reference: String,
    pub vin_sha256: String,
    pub required_programming_status: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Segment {
    pub region: String,
    pub start: u32,
    pub end_exclusive: u32,
    pub length: usize,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Signing {
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

pub(crate) struct CreateRequest<'a> {
    pub variant: &'a str,
    pub hardware_reference: &'a str,
    pub software_reference: &'a str,
    pub vin_sha256: &'a str,
    pub segment_specs: &'a [String],
    pub block_size: usize,
    pub signature_target: &'a str,
    pub signing_key: &'a Path,
}

pub(crate) fn create(request: CreateRequest<'_>) -> Result<SignedFlashPlan> {
    validate_identity(
        request.variant,
        request.hardware_reference,
        request.software_reference,
        request.vin_sha256,
    )?;
    if !(1..=4096).contains(&request.block_size) {
        bail!("block size must be between 1 and 4096 bytes");
    }

    let mut segments = Vec::with_capacity(request.segment_specs.len());
    for spec in request.segment_specs {
        segments.push(load_segment(spec)?);
    }
    validate_segments(&segments)?;

    let plan = FlashPlanDocument {
        approved_identity: ApprovedIdentity {
            variant: request.variant.to_owned(),
            hardware_reference: request.hardware_reference.to_owned(),
            software_reference: request.software_reference.to_owned(),
            vin_sha256: request.vin_sha256.to_ascii_lowercase(),
            required_programming_status: "1".to_owned(),
        },
        block_size: request.block_size,
        segments,
        intended_operations: OPERATIONS.iter().map(|value| (*value).to_owned()).collect(),
        signature_target: request.signature_target.to_owned(),
    };
    let signing_key = read_signing_key(request.signing_key)?;
    let signature = signing_key.sign(&signing_bytes(&plan)?);
    Ok(SignedFlashPlan {
        schema_version: SCHEMA_VERSION.to_owned(),
        plan,
        signing: Signing {
            algorithm: "Ed25519".to_owned(),
            public_key: encode_hex(signing_key.verifying_key().as_bytes()),
            signature: encode_hex(&signature.to_bytes()),
        },
    })
}

pub(crate) fn write(path: &Path, artifact: &SignedFlashPlan) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(artifact)?;
    std::fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

pub(crate) fn read_and_verify(path: &Path, expected_public_key: &str) -> Result<SignedFlashPlan> {
    let bytes =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let artifact: SignedFlashPlan = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid flash plan artifact {}", path.display()))?;
    validate_artifact(&artifact)?;
    if artifact.signing.public_key != expected_public_key.to_ascii_lowercase() {
        bail!("flash plan signer does not match the approved public key");
    }
    let public_key: [u8; 32] = decode_hex(&artifact.signing.public_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 public key must be 32 bytes"))?;
    let signature_bytes: [u8; 64] = decode_hex(&artifact.signing.signature)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 signature must be 64 bytes"))?;
    let key = VerifyingKey::from_bytes(&public_key).context("invalid Ed25519 public key")?;
    let signature = Signature::from_bytes(&signature_bytes);
    key.verify(&signing_bytes(&artifact.plan)?, &signature)
        .context("flash plan signature verification failed")?;
    Ok(artifact)
}

fn validate_artifact(artifact: &SignedFlashPlan) -> Result<()> {
    if artifact.schema_version != SCHEMA_VERSION {
        bail!("unsupported flash plan schema version");
    }
    if artifact.signing.algorithm != "Ed25519" {
        bail!("unsupported flash plan signature algorithm");
    }
    let identity = &artifact.plan.approved_identity;
    validate_identity(
        &identity.variant,
        &identity.hardware_reference,
        &identity.software_reference,
        &identity.vin_sha256,
    )?;
    if identity.required_programming_status != "1" {
        bail!("flash plan must require normal programming status (1)");
    }
    if !(1..=4096).contains(&artifact.plan.block_size) {
        bail!("block size must be between 1 and 4096 bytes");
    }
    if !matches!(
        artifact.plan.signature_target.as_str(),
        "parameter" | "program"
    ) {
        bail!("invalid signature target");
    }
    if artifact.plan.intended_operations != OPERATIONS {
        bail!("flash plan contains unsupported intended operations");
    }
    validate_segments(&artifact.plan.segments)
}

fn validate_identity(variant: &str, hardware: &str, software: &str, vin_hash: &str) -> Result<()> {
    if !matches!(variant, "MS45.0" | "MS45.1") {
        bail!("unsupported expected variant");
    }
    if hardware.trim().is_empty() || software.trim().is_empty() {
        bail!("hardware and software references are required");
    }
    if vin_hash.len() != 64 || !vin_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("expected VIN SHA-256 must be 64 hexadecimal digits");
    }
    Ok(())
}

fn load_segment(spec: &str) -> Result<Segment> {
    let mut fields = spec.splitn(3, ':');
    let region = fields.next().unwrap_or_default();
    let start_text = fields.next().unwrap_or_default();
    let file = fields.next().unwrap_or_default();
    if !matches!(region, "external" | "mpc") || start_text.is_empty() || file.is_empty() {
        bail!("segment must use REGION:START:FILE with REGION external or mpc");
    }
    let start = parse_address(start_text)?;
    let path = PathBuf::from(file);
    let data = std::fs::read(&path)
        .with_context(|| format!("failed to read segment payload {}", path.display()))?;
    if data.is_empty() {
        bail!("segment payload {} is empty", path.display());
    }
    let length = data.len();
    let length_u32 = u32::try_from(length).context("segment is larger than address space")?;
    let end_exclusive = start
        .checked_add(length_u32)
        .context("segment address range overflows")?;
    Ok(Segment {
        region: region.to_owned(),
        start,
        end_exclusive,
        length,
        sha256: encode_hex(&Sha256::digest(data)),
    })
}

fn validate_segments(segments: &[Segment]) -> Result<()> {
    if segments.is_empty() {
        bail!("at least one segment is required");
    }
    for (index, segment) in segments.iter().enumerate() {
        if !matches!(segment.region.as_str(), "external" | "mpc") {
            bail!("segment {index} has an unsupported region");
        }
        let limit = if segment.region == "external" {
            ms45_core::EXTERNAL_FLASH_LEN
        } else {
            ms45_core::MPC_FLASH_LEN
        };
        if segment.length == 0
            || segment.end_exclusive
                != segment
                    .start
                    .checked_add(u32::try_from(segment.length)?)
                    .context("segment address range overflows")?
            || segment.end_exclusive as usize > limit
            || segment.sha256.len() != 64
            || !segment.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("segment {index} has invalid range, length, or SHA-256");
        }
        for (other_index, other) in segments.iter().enumerate().skip(index + 1) {
            if segment.region == other.region
                && segment.start < other.end_exclusive
                && other.start < segment.end_exclusive
            {
                bail!("segments {index} and {other_index} overlap");
            }
        }
    }
    Ok(())
}

fn read_signing_key(path: &Path) -> Result<SigningKey> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read signing key {}", path.display()))?;
    let bytes: [u8; 32] = decode_hex(text.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 signing key seed must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn signing_bytes(plan: &FlashPlanDocument) -> Result<Vec<u8>> {
    let mut bytes = SCHEMA_VERSION.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend(serde_json::to_vec(plan).context("failed to serialize flash plan for signing")?);
    Ok(bytes)
}

fn parse_address(value: &str) -> Result<u32> {
    if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).context("invalid segment start address")
    } else {
        value.parse().context("invalid segment start address")
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("expected even-length hexadecimal data");
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).map_err(Into::into))
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
