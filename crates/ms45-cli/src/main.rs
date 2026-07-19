use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ms45_core::{
    prepare_full_program, prepare_tune, security_access_message, verify_flash_mpc_match,
    verify_parameter_match, verify_program_match,
};

#[derive(Debug, Parser)]
#[command(name = "ms45")]
#[command(about = "Rust tools for BMW MS45 binary validation and flash payload preparation")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
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

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
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
