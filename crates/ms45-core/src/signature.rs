use md5::{Digest, Md5};
use num_bigint::BigUint;

use crate::binary::BinaryError;
use crate::checksum::{mapped_segment, read_be_u32};

const SECURITY_N: &str = "8972339025878534711764289273376673716657892103603163846525142300863027035823902824753024958104010374518577719658056297243325957293507856591918471309133927";
const SECURITY_D: &str = "3845288153947943447898981117161431592853382330115641648510775271798440158210161294390718397115404567798616968157688687573437683643982238798574542074351303";
const SIGNING_N: &str = "8470472580328006956677424405159809178175955696534718361218518906571634405286747173565502454089691240931470915432212928785673566143706092135925769557255439";
const SIGNING_D: &str = "7260405068852577391437792347279836438436533454172615738187301919918543775959908116508429649500721130520546364846625732843778800986047617824899475327781303";

pub fn security_access_message(user_id: [u8; 4], serial_number: [u8; 4], seed: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(8 + seed.len());
    input.extend_from_slice(&user_id);
    input.extend_from_slice(&serial_number);
    input.extend_from_slice(seed);

    let digest = Md5::digest(input);
    let encrypted = rsa_private(&digest, SECURITY_N, SECURITY_D);
    let mut auth_payload = reorder_words_be_to_le(&encrypted, 65);
    auth_payload[64] = 3;

    let auth_header = [
        0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ];

    [auth_header.as_slice(), auth_payload.as_slice()].concat()
}

pub fn sign_ms45_parameters(bin: &mut [u8]) -> Result<(), BinaryError> {
    let hash = hash_parameter_segments(bin, 0x130, 0x144)?;
    let encrypted = rsa_private(&hash, SIGNING_N, SIGNING_D);
    let signature = reorder_words_be_to_le(&encrypted, 64);
    let dst = bin
        .get_mut(0x174..0x174 + 64)
        .ok_or(BinaryError::OutOfRange {
            offset: 0x174,
            len: 64,
        })?;
    dst.copy_from_slice(&signature);
    Ok(())
}

pub fn sign_ms45_program(flash: &mut [u8], mpc: &[u8]) -> Result<(), BinaryError> {
    let hash = hash_program_segments(flash, mpc, 0x60030, 0x6004c)?;
    let encrypted = rsa_private(&hash, SIGNING_N, SIGNING_D);
    let signature = reorder_words_be_to_le(&encrypted, 64);
    let dst = flash
        .get_mut(0x60074..0x60074 + 64)
        .ok_or(BinaryError::OutOfRange {
            offset: 0x60074,
            len: 64,
        })?;
    dst.copy_from_slice(&signature);
    Ok(())
}

fn hash_parameter_segments(
    bin: &[u8],
    segment_number_offset: usize,
    segment_length_offset: usize,
) -> Result<[u8; 16], BinaryError> {
    let count = read_be_u32(bin, segment_number_offset)? as usize;
    let mut hasher = Md5::new();

    for i in 0..count {
        let start = read_be_u32(bin, segment_number_offset + 4 + (i * 8))?
            .checked_sub(0xfff4_0000)
            .ok_or(BinaryError::InvalidAddress)? as usize;
        let length = read_be_u32(bin, segment_length_offset + (i * 4))? as usize;
        let segment = bin
            .get(start..start + length)
            .ok_or(BinaryError::OutOfRange {
                offset: start,
                len: length,
            })?;
        hasher.update(segment);
    }

    Ok(hasher.finalize().into())
}

fn hash_program_segments(
    flash: &[u8],
    mpc: &[u8],
    segment_number_offset: usize,
    segment_length_offset: usize,
) -> Result<[u8; 16], BinaryError> {
    let count = read_be_u32(flash, segment_number_offset)? as usize;
    let mut hasher = Md5::new();

    for i in 0..count {
        let start = read_be_u32(flash, segment_number_offset + 4 + (i * 8))?;
        let length = read_be_u32(flash, segment_length_offset + (i * 4))?;
        let end = start
            .checked_add(length)
            .and_then(|value| value.checked_sub(1))
            .ok_or(BinaryError::InvalidAddress)?;
        hasher.update(mapped_segment(flash, mpc, start, end)?);
    }

    Ok(hasher.finalize().into())
}

fn rsa_private(message: &[u8], modulus: &str, exponent: &str) -> Vec<u8> {
    let n = BigUint::parse_bytes(modulus.as_bytes(), 10).expect("static modulus is valid");
    let d = BigUint::parse_bytes(exponent.as_bytes(), 10).expect("static exponent is valid");
    BigUint::from_bytes_le(message).modpow(&d, &n).to_bytes_le()
}

fn reorder_words_be_to_le(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut padded = [0; 64];
    let copy_len = input.len().min(64);
    padded[..copy_len].copy_from_slice(&input[..copy_len]);

    let mut out = vec![0; output_len];
    for i in 0..16 {
        out[4 * i] = padded[3 + 4 * i];
        out[1 + 4 * i] = padded[2 + 4 * i];
        out[2 + 4 * i] = padded[1 + 4 * i];
        out[3 + 4 * i] = padded[4 * i];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_access_message_shape_matches_ediabas_payload() {
        let msg = security_access_message([1, 2, 3, 4], [5, 6, 7, 8], &[9, 10, 11, 12]);

        assert_eq!(msg.len(), 90);
        assert_eq!(msg[0], 1);
        assert_eq!(msg[24], 0x10);
        assert_eq!(msg[89], 3);
    }
}
