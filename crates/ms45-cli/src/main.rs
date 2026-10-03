#[cfg(feature = "live-read")]
use std::ffi::OsString;
#[cfg(feature = "live-read")]
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{error::ErrorKind, Parser, Subcommand};
#[cfg(feature = "live-read")]
use ms45_core::flasher::MemoryRegion;
#[cfg(feature = "live-read")]
use ms45_core::read_only::ReadOnlyAdapter;
use ms45_core::{
    prepare_full_program, prepare_tune, security_access_message, verify_flash_mpc_match,
    verify_parameter_match, verify_program_match,
};
#[cfg(feature = "live-read")]
use sha2::{Digest, Sha256};

#[cfg(feature = "live-read")]
mod backup;
use ms45::flash_plan_artifact;
#[cfg(feature = "live-read")]
use ms45::output::BackupReceipt;
use ms45::output::{CliError, OperationResult};

#[derive(Debug, Parser)]
#[command(name = "ms45", version)]
#[command(about = "Rust tools for BMW MS45 binary validation and flash payload preparation")]
struct Cli {
    /// Emit stable, versioned JSON on stdout and stderr.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a signed, payload-hash-bound flash approval plan.
    CreateFlashPlan {
        #[arg(long)]
        expected_variant: String,
        #[arg(long)]
        expected_hw_ref: String,
        #[arg(long)]
        expected_sw_ref: String,
        #[arg(long)]
        expected_vin_sha256: String,
        /// Segment in REGION:START:FILE form; REGION is external or mpc.
        #[arg(long = "segment", required = true)]
        segments: Vec<String>,
        #[arg(long, default_value_t = 4096)]
        block_size: usize,
        #[arg(long, value_enum)]
        signature_target: SignatureTarget,
        /// File containing a 32-byte Ed25519 seed encoded as 64 hex digits.
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify an offline signed flash approval plan.
    VerifyFlashPlan {
        #[arg(long)]
        input: PathBuf,
        /// Approved Ed25519 public key encoded as 64 hex digits.
        #[arg(long)]
        expected_public_key: String,
    },
    /// Verify and display the exact erase and block-write ranges in a flash plan.
    InspectFlashPlan {
        #[arg(long)]
        input: PathBuf,
        /// Approved Ed25519 public key encoded as 64 hex digits.
        #[arg(long)]
        expected_public_key: String,
    },
    #[cfg(feature = "live-read")]
    /// Report read-only ECU identity and status metadata.
    Probe {
        #[arg(long)]
        adapter: SocketAddr,
    },
    #[cfg(feature = "live-read")]
    /// Read memory through a separately validated read-only ECU job adapter.
    Backup {
        #[arg(long)]
        adapter: SocketAddr,
        #[arg(long)]
        expected_variant: String,
        #[arg(long)]
        expected_hw_ref: String,
        #[arg(long)]
        expected_sw_ref: String,
        #[arg(long)]
        expected_vin_sha256: String,
        /// Version reported by the independently deployed read bridge.
        #[arg(long, value_parser = parse_version_label)]
        bridge_version: String,
        #[arg(long, value_enum)]
        region: BackupRegion,
        #[arg(long)]
        start: u32,
        #[arg(long)]
        length: usize,
        #[arg(long)]
        output: PathBuf,
        /// Executable that reads the verified backup on stdin and writes encrypted bytes to stdout.
        #[arg(long)]
        encrypt_with: Option<PathBuf>,
        /// Argument passed verbatim to --encrypt-with (repeatable; no shell is used).
        #[arg(long, requires = "encrypt_with", allow_hyphen_values = true)]
        encrypt_arg: Vec<OsString>,
    },
    /// Correct checksums/signature and write the parameter payload used by Flash Tune.
    PrepareTune {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Correct checksums/signature and split the full program write payloads.
    PrepareProgram {
        #[arg(long)]
        external: PathBuf,
        #[arg(long)]
        mpc: PathBuf,
        #[arg(long)]
        external_output: PathBuf,
        #[arg(long)]
        mpc_output: PathBuf,
    },
    /// Validate metadata compatibility without modifying files.
    Validate {
        #[arg(long)]
        tune: Option<PathBuf>,
        #[arg(long)]
        sw_ref: Option<String>,
        #[arg(long)]
        external: Option<PathBuf>,
        #[arg(long)]
        mpc: Option<PathBuf>,
        #[arg(long)]
        hw_ref: Option<String>,
    },
    /// Build the Ediabas binary authentication payload from known challenge data.
    SecurityMessage {
        #[arg(long, value_parser = parse_hex_4)]
        user_id: [u8; 4],
        #[arg(long, value_parser = parse_hex_4)]
        serial: [u8; 4],
        #[arg(long)]
        seed: String,
    },
    /// Explain current status of live flashing support in this Rust port.
    LiveStatus,
}

#[cfg(feature = "live-read")]
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum BackupRegion {
    External,
    Mpc,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum SignatureTarget {
    Parameter,
    Program,
}

fn main() -> std::process::ExitCode {
    let json_requested = std::env::args_os().any(|arg| arg == "--json");
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            return std::process::ExitCode::SUCCESS;
        }
        Err(error) => {
            if json_requested {
                print_json_error(
                    None,
                    "invalid_arguments",
                    &anyhow::Error::msg(error.to_string()),
                );
            } else {
                let _ = error.print();
            }
            return std::process::ExitCode::from(2);
        }
    };
    let json = cli.json;
    let operation = cli.command.name();
    match run(cli) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            if json {
                print_json_error(Some(operation), "operation_failed", &error);
            } else {
                eprintln!("Error: {error:#}");
            }
            std::process::ExitCode::FAILURE
        }
    }
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::CreateFlashPlan { .. } => "create-flash-plan",
            Self::VerifyFlashPlan { .. } => "verify-flash-plan",
            Self::InspectFlashPlan { .. } => "inspect-flash-plan",
            #[cfg(feature = "live-read")]
            Self::Probe { .. } => "probe",
            #[cfg(feature = "live-read")]
            Self::Backup { .. } => "backup",
            Self::PrepareTune { .. } => "prepare-tune",
            Self::PrepareProgram { .. } => "prepare-program",
            Self::Validate { .. } => "validate",
            Self::SecurityMessage { .. } => "security-message",
            Self::LiveStatus => "live-status",
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let json = cli.json;

    match cli.command {
        Command::CreateFlashPlan {
            expected_variant,
            expected_hw_ref,
            expected_sw_ref,
            expected_vin_sha256,
            segments,
            block_size,
            signature_target,
            signing_key,
            output,
        } => {
            let artifact = flash_plan_artifact::create(flash_plan_artifact::CreateRequest {
                variant: &expected_variant,
                hardware_reference: &expected_hw_ref,
                software_reference: &expected_sw_ref,
                vin_sha256: &expected_vin_sha256,
                segment_specs: &segments,
                block_size,
                signature_target: match signature_target {
                    SignatureTarget::Parameter => "parameter",
                    SignatureTarget::Program => "program",
                },
                signing_key: &signing_key,
            })?;
            flash_plan_artifact::write(&output, &artifact)?;
            let result = serde_json::json!({"schema_version":"ms45.flash-plan-created.v1","status":"signed","output":output,"segments":artifact.plan.segments.len(),"public_key":artifact.signing.public_key});
            emit(json, "create-flash-plan", &result, &result)?;
        }
        Command::VerifyFlashPlan {
            input,
            expected_public_key,
        } => {
            let artifact = flash_plan_artifact::read_and_verify(&input, &expected_public_key)?;
            let result = serde_json::json!({"schema_version":"ms45.flash-plan-verified.v1","status":"verified","input":input,"segments":artifact.plan.segments.len(),"public_key":artifact.signing.public_key});
            emit(json, "verify-flash-plan", &result, &result)?;
        }
        Command::InspectFlashPlan {
            input,
            expected_public_key,
        } => {
            let artifact = flash_plan_artifact::read_and_verify(&input, &expected_public_key)?;
            let result = serde_json::to_value(flash_plan_artifact::inspect(&artifact))?;
            emit(json, "inspect-flash-plan", &result, &result)?;
        }
        #[cfg(feature = "live-read")]
        Command::Probe { adapter } => {
            let mut session = ReadOnlyAdapter::connect(adapter, backup::ADAPTER_TIMEOUT)?;
            let report = session.probe()?;
            let vin_hash = format!("{:x}", Sha256::digest(report.vin.as_bytes()));
            let result = serde_json::json!({"schema_version":"ms45.hardware-probe.v1","variant":report.variant,"hardware_reference":report.hardware_reference,"software_reference":report.software_reference,"programming_status":report.programming_status,"diagnostic_protocol":report.diagnostic_protocol,"vin_sha256":vin_hash});
            emit(json, "probe", &result, &result)?;
        }
        #[cfg(feature = "live-read")]
        Command::Backup {
            adapter,
            expected_variant,
            expected_hw_ref,
            expected_sw_ref,
            expected_vin_sha256,
            bridge_version,
            region,
            start,
            length,
            output,
            encrypt_with,
            encrypt_arg,
        } => {
            if !matches!(expected_variant.as_str(), "MS45.0" | "MS45.1") {
                anyhow::bail!("unsupported expected variant");
            }
            if length == 0 || length > 0x100000 {
                anyhow::bail!("backup length out of bounds");
            }
            let memory_region = match region {
                BackupRegion::External => MemoryRegion::ExternalFlash,
                BackupRegion::Mpc => MemoryRegion::InternalMpc,
            };
            let limit = match memory_region {
                MemoryRegion::ExternalFlash => ms45_core::EXTERNAL_FLASH_LEN,
                MemoryRegion::InternalMpc => ms45_core::MPC_FLASH_LEN,
            };
            if (start as usize)
                .checked_add(length)
                .is_none_or(|end| end > limit)
            {
                anyhow::bail!("backup range out of bounds");
            }
            let mut session = ReadOnlyAdapter::connect(adapter, backup::ADAPTER_TIMEOUT)?;
            let identity = session.identify()?;
            let vin_hash = format!("{:x}", Sha256::digest(identity.vin.as_bytes()));
            if identity.variant != expected_variant
                || identity.hardware_reference != expected_hw_ref
                || identity.software_reference != expected_sw_ref
                || vin_hash != expected_vin_sha256.to_ascii_lowercase()
            {
                anyhow::bail!("ECU identity does not match pinned identity");
            }
            let region_name = match region {
                BackupRegion::External => "external",
                BackupRegion::Mpc => "mpc",
            };
            let encryption = encrypt_with.map(|program| backup::EncryptionCommand {
                program,
                args: encrypt_arg,
            });
            let outcome = backup::run(
                &mut session,
                &identity,
                backup::BackupRequest {
                    region: memory_region,
                    region_name,
                    start,
                    length,
                    output: &output,
                    vin_sha256: &vin_hash,
                    bridge_version: &bridge_version,
                    encryption: encryption.as_ref(),
                },
            )?;
            let manifest = backup::manifest_path(&output);
            let receipt = BackupReceipt {
                schema_version: ms45::output::BACKUP_RECEIPT_SCHEMA,
                status: "verified",
                variant: &identity.variant,
                hardware_reference: &identity.hardware_reference,
                software_reference: &identity.software_reference,
                vin_sha256: &vin_hash,
                region: region_name,
                start,
                length,
                sha256: &outcome.plaintext_sha256,
                output_sha256: &outcome.output_sha256,
                encrypted: encryption.is_some(),
                read_passes: backup::READ_PASSES,
                resumed_bytes: outcome.resumed_bytes,
                output: &output,
                manifest: &manifest,
            };
            println!("{}", serde_json::to_string(&receipt)?);
        }
        Command::PrepareTune { input, output } => {
            let input_bytes = read(&input)?;
            let payload = prepare_tune(&input_bytes)?;
            std::fs::write(&output, payload.data)
                .with_context(|| format!("failed to write {}", output.display()))?;
            let result = serde_json::json!({"output": output});
            emit(
                json,
                "prepare-tune",
                &result,
                &format!("wrote prepared tune payload to {}", output.display()),
            )?;
        }
        Command::PrepareProgram {
            external,
            mpc,
            external_output,
            mpc_output,
        } => {
            let external_bytes = read(&external)?;
            let mpc_bytes = read(&mpc)?;
            let payload = prepare_full_program(&external_bytes, &mpc_bytes)?;
            std::fs::write(&external_output, payload.external_program)
                .with_context(|| format!("failed to write {}", external_output.display()))?;
            std::fs::write(&mpc_output, payload.mpc_program)
                .with_context(|| format!("failed to write {}", mpc_output.display()))?;
            let result =
                serde_json::json!({"external_output": external_output, "mpc_output": mpc_output});
            emit(
                json,
                "prepare-program",
                &result,
                &format!(
                    "wrote prepared program payloads to {} and {}",
                    external_output.display(),
                    mpc_output.display()
                ),
            )?;
        }
        Command::Validate {
            tune,
            sw_ref,
            external,
            mpc,
            hw_ref,
        } => {
            let mut result = serde_json::Map::new();
            if let (Some(path), Some(sw_ref)) = (tune, sw_ref) {
                let bytes = read(&path)?;
                let matched = verify_parameter_match(&bytes, &sw_ref)?;
                result.insert(
                    "tune_software_reference_match".into(),
                    serde_json::Value::Bool(matched),
                );
                if !json {
                    println!("tune/software reference match: {matched}");
                }
            }

            if let Some(external_path) = external {
                let external_bytes = read(&external_path)?;
                if let Some(hw_ref) = hw_ref {
                    let matched = verify_program_match(&external_bytes, &hw_ref)?;
                    result.insert(
                        "program_hardware_reference_match".into(),
                        serde_json::Value::Bool(matched),
                    );
                    if !json {
                        println!("program/hardware reference match: {matched}");
                    }
                }

                if let Some(mpc_path) = mpc {
                    let mpc_bytes = read(&mpc_path)?;
                    let matched = verify_flash_mpc_match(&external_bytes, &mpc_bytes)?;
                    result.insert(
                        "external_mpc_pair_match".into(),
                        serde_json::Value::Bool(matched),
                    );
                    if !json {
                        println!("external/MPC pair match: {matched}");
                    }
                }
            }
            if json {
                emit(true, "validate", &serde_json::Value::Object(result), &"")?;
            }
        }
        Command::SecurityMessage {
            user_id,
            serial,
            seed,
        } => {
            let seed = parse_hex_bytes(&seed).map_err(|err| anyhow::anyhow!(err))?;
            let message = to_hex(&security_access_message(user_id, serial, seed.as_slice()));
            emit(
                json,
                "security-message",
                &serde_json::json!({"message_hex": message}),
                &message,
            )?;
        }
        Command::LiveStatus => {
            #[cfg(feature = "live-read")]
            let message = "Live DME flashing is unavailable. This build includes the experimental read-only identify and backup commands; live security access, erase, write, and reset are not compiled as CLI operations.";
            #[cfg(not(feature = "live-read"))]
            let message = "Live DME access is unavailable in this build. Rebuild with --features live-read for experimental identify and backup commands; live security access, erase, write, and reset remain unavailable.";
            emit(
                json,
                "live-status",
                &serde_json::json!({"available": false, "message": message}),
                &message,
            )?;
        }
    }

    Ok(())
}

fn emit(
    json: bool,
    operation: &str,
    result: &serde_json::Value,
    legacy: &impl std::fmt::Display,
) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string(&OperationResult::success(operation, result.clone()))?
        );
    } else {
        println!("{legacy}");
    }
    Ok(())
}

fn print_json_error(operation: Option<&str>, code: &str, error: &anyhow::Error) {
    let causes = error.chain().skip(1).map(ToString::to_string).collect();
    let value = CliError::new(operation, code, error.to_string(), causes);
    let json = serde_json::to_string(&value).unwrap_or_else(|_| {
        r#"{"schema_version":"ms45.cli-error.v1","status":"error","operation":null,"code":"serialization_failed","message":"failed to serialize CLI error","causes":[]}"#.to_owned()
    });
    eprintln!("{json}");
}

fn read(path: &PathBuf) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))
}

fn parse_hex_4(input: &str) -> std::result::Result<[u8; 4], String> {
    let bytes = parse_hex_bytes(input)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("expected 4 bytes, got {}", bytes.len()))
}

#[cfg(feature = "live-read")]
fn parse_version_label(input: &str) -> std::result::Result<String, String> {
    if input.is_empty()
        || input.len() > 128
        || !input
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
    {
        return Err("bridge version must be 1-128 printable non-space characters".into());
    }
    Ok(input.into())
}

fn parse_hex_bytes(input: &str) -> std::result::Result<Vec<u8>, String> {
    let compact = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input)
        .replace([' ', ':', '-'], "");

    if !compact.len().is_multiple_of(2) {
        return Err("hex input must contain an even number of digits".to_string());
    }

    (0..compact.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&compact[i..i + 2], 16)
                .map_err(|_| format!("invalid hex byte '{}'", &compact[i..i + 2]))
        })
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}
