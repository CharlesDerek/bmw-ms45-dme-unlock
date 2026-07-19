use crate::checksum::{correct_parameter_checksums, correct_program_checksums};
use crate::signature::{sign_ms45_parameters, sign_ms45_program};

pub const TUNE_LEN: usize = 0x1d000;
pub const TUNE_MIN_LEN: usize = 0x1d000;
pub const TUNE_MAX_LEN: usize = 0x20000;
pub const EXTERNAL_FLASH_LEN: usize = 0x100000;
pub const MPC_FLASH_LEN: usize = 0x70000;
pub const EXTERNAL_FLASH_BASE: u32 = 0xfff0_0000;
const FULL_TUNE_OFFSET: usize = 0x40000;
const PROGRAM_PAYLOAD_OFFSET: usize = 0x60000;
const PROGRAM_PAYLOAD_LEN: usize = 0x9ff40;

#[derive(Debug, thiserror::Error)]
pub enum BinaryError {
    #[error("invalid tune length {actual:#x}; expected {TUNE_MIN_LEN:#x}..={TUNE_MAX_LEN:#x}")]
    InvalidTuneLength { actual: usize },
    #[error("invalid external flash length {actual:#x}; expected {EXTERNAL_FLASH_LEN:#x}")]
    InvalidExternalFlashLength { actual: usize },
    #[error("invalid MPC flash length {actual:#x}; expected {MPC_FLASH_LEN:#x}")]
    InvalidMpcFlashLength { actual: usize },
    #[error("binary access out of range at {offset:#x} for {len:#x} bytes")]
    OutOfRange { offset: usize, len: usize },
    #[error("invalid or reversed address range in descriptor")]
    InvalidAddress,
    #[error("ASCII metadata field contains invalid bytes")]
    InvalidAsciiMetadata,
    #[error("ASCII metadata field is not numeric")]
    InvalidNumericMetadata,
    #[error("program flash and MPC metadata do not match")]
    FlashMpcMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunePayload {
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullProgramPayload {
    pub external_program: Vec<u8>,
    pub mpc_program: Vec<u8>,
}

pub fn prepare_tune(input: &[u8]) -> Result<TunePayload, BinaryError> {
    let mut data = if input.len() == EXTERNAL_FLASH_LEN {
        input
            .get(FULL_TUNE_OFFSET..FULL_TUNE_OFFSET + TUNE_LEN)
            .ok_or(BinaryError::OutOfRange {
                offset: FULL_TUNE_OFFSET,
                len: TUNE_LEN,
            })?
            .to_vec()
    } else {
        validate_tune_len(input)?;
        input.to_vec()
    };

    correct_parameter_checksums(&mut data)?;
    sign_ms45_parameters(&mut data)?;
    Ok(TunePayload { data })
}

pub fn prepare_full_program(
    external: &[u8],
    mpc: &[u8],
) -> Result<FullProgramPayload, BinaryError> {
    validate_external_flash_len(external)?;
    validate_mpc_len(mpc)?;
    if !verify_flash_mpc_match(external, mpc)? {
        return Err(BinaryError::FlashMpcMismatch);
    }

    let mut external = external.to_vec();
    correct_program_checksums(&mut external, mpc)?;
    sign_ms45_program(&mut external, mpc)?;

    let external_program = external
        .get(PROGRAM_PAYLOAD_OFFSET..PROGRAM_PAYLOAD_OFFSET + PROGRAM_PAYLOAD_LEN)
        .ok_or(BinaryError::OutOfRange {
            offset: PROGRAM_PAYLOAD_OFFSET,
            len: PROGRAM_PAYLOAD_LEN,
        })?
        .to_vec();

    Ok(FullProgramPayload {
        external_program,
        mpc_program: mpc.to_vec(),
    })
}

pub fn verify_parameter_match(flash: &[u8], sw_ref: &str) -> Result<bool, BinaryError> {
    let bin_ref = ascii_field(flash, 0x10, 0x0c)?;
    Ok(sw_ref.contains(bin_ref.trim_end_matches('\0')))
}

pub fn verify_program_match(flash: &[u8], hw_ref: &str) -> Result<bool, BinaryError> {
    let bin_ref = ascii_field(flash, 0x6031c, 0x0c)?;
    Ok(bin_ref.contains(hw_ref))
}

pub fn verify_flash_mpc_match(flash: &[u8], mpc: &[u8]) -> Result<bool, BinaryError> {
    let flash_ref = ascii_field(flash, 0x60310, 0x0a)?
        .trim_matches(char::from(0))
        .trim()
        .parse::<u64>()
        .map_err(|_| BinaryError::InvalidNumericMetadata)?;
    let mpc_ref = ascii_field(mpc, 0x100, 0x0a)?
        .trim_matches(char::from(0))
        .trim()
        .parse::<u64>()
        .map_err(|_| BinaryError::InvalidNumericMetadata)?;

    Ok(flash_ref.checked_sub(mpc_ref) == Some(500))
}

fn validate_tune_len(input: &[u8]) -> Result<(), BinaryError> {
    if (TUNE_MIN_LEN..=TUNE_MAX_LEN).contains(&input.len()) {
        Ok(())
    } else {
        Err(BinaryError::InvalidTuneLength {
            actual: input.len(),
        })
    }
}

fn validate_external_flash_len(input: &[u8]) -> Result<(), BinaryError> {
    if input.len() == EXTERNAL_FLASH_LEN {
        Ok(())
    } else {
        Err(BinaryError::InvalidExternalFlashLength {
            actual: input.len(),
        })
    }
}

fn validate_mpc_len(input: &[u8]) -> Result<(), BinaryError> {
    if input.len() == MPC_FLASH_LEN {
        Ok(())
    } else {
        Err(BinaryError::InvalidMpcFlashLength {
            actual: input.len(),
        })
    }
}

fn ascii_field(buf: &[u8], offset: usize, len: usize) -> Result<&str, BinaryError> {
    let bytes = buf
        .get(offset..offset + len)
        .ok_or(BinaryError::OutOfRange { offset, len })?;
    std::str::from_utf8(bytes).map_err(|_| BinaryError::InvalidAsciiMetadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_flash_mpc_pair_metadata() {
        let mut flash = vec![0; EXTERNAL_FLASH_LEN];
        let mut mpc = vec![0; MPC_FLASH_LEN];
        flash[0x60310..0x6031a].copy_from_slice(b"0000010500");
        mpc[0x100..0x10a].copy_from_slice(b"0000010000");

        assert!(verify_flash_mpc_match(&flash, &mpc).unwrap());
    }

    #[test]
    fn rejects_flash_mpc_pair_with_wrong_delta() {
        let mut flash = vec![0; EXTERNAL_FLASH_LEN];
        let mut mpc = vec![0; MPC_FLASH_LEN];
        flash[0x60310..0x6031a].copy_from_slice(b"0000010400");
        mpc[0x100..0x10a].copy_from_slice(b"0000010000");

        assert!(!verify_flash_mpc_match(&flash, &mpc).unwrap());
    }

    #[test]
    fn rejects_non_numeric_flash_mpc_metadata() {
        let mut flash = vec![0; EXTERNAL_FLASH_LEN];
        let mut mpc = vec![0; MPC_FLASH_LEN];
        flash[0x60310..0x6031a].copy_from_slice(b"not-a-ref!");
        mpc[0x100..0x10a].copy_from_slice(b"0000010000");

        let err = verify_flash_mpc_match(&flash, &mpc).unwrap_err();
        assert!(matches!(err, BinaryError::InvalidNumericMetadata));
    }

    #[test]
    fn validates_tune_software_reference_metadata() {
        let mut tune = vec![0; TUNE_LEN];
        tune[0x10..0x1c].copy_from_slice(b"7561520\0\0\0\0\0");

        assert!(verify_parameter_match(&tune, "BMW ZB 7561520").unwrap());
        assert!(!verify_parameter_match(&tune, "BMW ZB 7561521").unwrap());
    }

    #[test]
    fn validates_program_hardware_reference_metadata() {
        let mut flash = vec![0; EXTERNAL_FLASH_LEN];
        flash[0x6031c..0x60328].copy_from_slice(b"0044570-0000");

        assert!(verify_program_match(&flash, "0044570").unwrap());
        assert!(!verify_program_match(&flash, "0044571").unwrap());
    }

    #[test]
    fn rejects_bad_tune_length() {
        let err = prepare_tune(&[0xaa; 16]).unwrap_err();
        assert!(matches!(err, BinaryError::InvalidTuneLength { .. }));
    }
}
