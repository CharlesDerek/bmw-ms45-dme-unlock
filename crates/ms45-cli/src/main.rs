use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ms45_core::flasher::MemoryRegion;
use ms45_core::read_only::{ReadOnlyAdapter, MAX_READ};
use ms45_core::{
    prepare_full_program, prepare_tune, security_access_message, verify_flash_mpc_match,
    verify_parameter_match, verify_program_match,
};
use sha2::{Digest, Sha256};

#[derive(Debug, Parser)]
#[command(name = "ms45")]
#[command(about = "Rust tools for BMW MS45 binary validation and flash payload preparation")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
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
        #[arg(long, value_enum)]
        region: BackupRegion,
        #[arg(long)]
        start: u32,
        #[arg(long)]
        length: usize,
        #[arg(long)]
        output: PathBuf,
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

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum BackupRegion {
    External,
    Mpc,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Backup {
            adapter,
            expected_variant,
            expected_hw_ref,
            expected_sw_ref,
            expected_vin_sha256,
            region,
            start,
            length,
            output,
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
            let mut session = ReadOnlyAdapter::connect(adapter, Duration::from_secs(3))?;
            let identity = session.identify()?;
            let vin_hash = format!("{:x}", Sha256::digest(identity.vin.as_bytes()));
            if identity.variant != expected_variant
                || identity.hardware_reference != expected_hw_ref
                || identity.software_reference != expected_sw_ref
                || vin_hash != expected_vin_sha256.to_ascii_lowercase()
            {
                anyhow::bail!("ECU identity does not match pinned identity");
            }
            let mut bytes = Vec::with_capacity(length);
            while bytes.len() < length {
                let block = (length - bytes.len()).min(MAX_READ);
                let address = start
                    .checked_add(bytes.len() as u32)
                    .context("backup address overflow")?;
                bytes.extend_from_slice(&session.read(memory_region, address, block)?);
            }
            let digest = format!("{:x}", Sha256::digest(&bytes));
            let parent = output.parent().unwrap_or_else(|| std::path::Path::new("."));
            let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
            temporary.write_all(&bytes)?;
            temporary.as_file().sync_all()?;
            temporary.persist(&output)?;
            let verified = format!("{:x}", Sha256::digest(std::fs::read(&output)?));
            if verified != digest {
                anyhow::bail!("backup verification failed");
            }
            println!(
                "{}",
                serde_json::json!({"schema_version":"ms45.backup.v1","status":"verified","variant":identity.variant,"hardware_reference":identity.hardware_reference,"software_reference":identity.software_reference,"vin_sha256":vin_hash,"region":format!("{region:?}").to_ascii_lowercase(),"start":start,"length":length,"sha256":digest,"output":output})
            );
        }
        Command::PrepareTune { input, output } => {
            let input_bytes = read(&input)?;
            let payload = prepare_tune(&input_bytes)?;
            std::fs::write(&output, payload.data)
                .with_context(|| format!("failed to write {}", output.display()))?;
            println!("wrote prepared tune payload to {}", output.display());
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
            println!(
                "wrote prepared program payloads to {} and {}",
                external_output.display(),
                mpc_output.display()
            );
        }
        Command::Validate {
            tune,
            sw_ref,
            external,
            mpc,
            hw_ref,
        } => {
            if let (Some(path), Some(sw_ref)) = (tune, sw_ref) {
                let bytes = read(&path)?;
                println!(
                    "tune/software reference match: {}",
                    verify_parameter_match(&bytes, &sw_ref)?
                );
            }

            if let Some(external_path) = external {
                let external_bytes = read(&external_path)?;
                if let Some(hw_ref) = hw_ref {
                    println!(
                        "program/hardware reference match: {}",
                        verify_program_match(&external_bytes, &hw_ref)?
                    );
                }

                if let Some(mpc_path) = mpc {
                    let mpc_bytes = read(&mpc_path)?;
                    println!(
                        "external/MPC pair match: {}",
                        verify_flash_mpc_match(&external_bytes, &mpc_bytes)?
                    );
                }
            }
        }
        Command::SecurityMessage {
            user_id,
            serial,
            seed,
        } => {
            let seed = parse_hex_bytes(&seed).map_err(|err| anyhow::anyhow!(err))?;
            println!(
                "{}",
                to_hex(&security_access_message(user_id, serial, seed.as_slice()))
            );
        }
        Command::LiveStatus => {
            println!(
                "Live DME flashing is not wired in this Rust port yet. The repo now has a FlashBackend trait for a future Ediabas/PRG or native diagnostic backend, while offline binary preparation is implemented and tested."
            );
        }
    }

    Ok(())
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
