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
        let entry = segment_number_offset
            .checked_add(4)
            .and_then(|offset| i.checked_mul(8).and_then(|delta| offset.checked_add(delta)))
            .ok_or(BinaryError::OutOfRange {
                offset: segment_number_offset,
                len: bin.len(),
            })?;
        let length_offset = segment_length_offset
            .checked_add(i.checked_mul(4).ok_or(BinaryError::OutOfRange {
                offset: segment_length_offset,
                len: bin.len(),
            })?)
            .ok_or(BinaryError::OutOfRange {
                offset: segment_length_offset,
                len: bin.len(),
            })?;
        let start = read_be_u32(bin, entry)?
            .checked_sub(0xfff4_0000)
            .ok_or(BinaryError::InvalidAddress)? as usize;
        let length = read_be_u32(bin, length_offset)? as usize;
        let end = start.checked_add(length).ok_or(BinaryError::OutOfRange {
            offset: start,
            len: length,
        })?;
        let segment = bin.get(start..end).ok_or(BinaryError::OutOfRange {
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
        let entry = segment_number_offset
            .checked_add(4)
            .and_then(|offset| i.checked_mul(8).and_then(|delta| offset.checked_add(delta)))
            .ok_or(BinaryError::OutOfRange {
                offset: segment_number_offset,
                len: flash.len(),
            })?;
        let length_offset = segment_length_offset
            .checked_add(i.checked_mul(4).ok_or(BinaryError::OutOfRange {
                offset: segment_length_offset,
                len: flash.len(),
            })?)
            .ok_or(BinaryError::OutOfRange {
                offset: segment_length_offset,
                len: flash.len(),
            })?;
        let start = read_be_u32(flash, entry)?;
        let length = read_be_u32(flash, length_offset)?;
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
    use proptest::prelude::*;

    #[test]
    fn security_access_message_shape_matches_ediabas_payload() {
        let msg = security_access_message([1, 2, 3, 4], [5, 6, 7, 8], &[9, 10, 11, 12]);

        assert_eq!(msg.len(), 90);
        assert_eq!(msg[0], 1);
        assert_eq!(msg[24], 0x10);
        assert_eq!(msg[89], 3);
    }

    #[test]
    fn parameter_signatures_are_deterministic_and_cover_described_bytes() {
        let mut first = vec![0; crate::TUNE_LEN];
        first[0x130..0x134].copy_from_slice(&1_u32.to_be_bytes());
        first[0x134..0x138].copy_from_slice(&0xfff4_0000_u32.to_be_bytes());
        first[0x144..0x148].copy_from_slice(&16_u32.to_be_bytes());
        first[..16].copy_from_slice(b"signed parameter");
        let mut identical = first.clone();
        let mut changed = first.clone();
        changed[0] ^= 1;

        sign_ms45_parameters(&mut first).unwrap();
        sign_ms45_parameters(&mut identical).unwrap();
        sign_ms45_parameters(&mut changed).unwrap();

        assert_eq!(&first[0x174..0x1b4], &identical[0x174..0x1b4]);
        assert_ne!(&first[0x174..0x1b4], &changed[0x174..0x1b4]);
    }

    proptest! {
        #[test]
        fn word_reordering_preserves_each_complete_word(input in proptest::collection::vec(any::<u8>(), 0..=64)) {
            let output = reorder_words_be_to_le(&input, 64);
            let mut padded = input;
            padded.resize(64, 0);
            for index in 0..16 {
                let start = index * 4;
                prop_assert_eq!(&output[start..start + 4], padded[start..start + 4].iter().rev().copied().collect::<Vec<_>>());
            }
        }

        #[test]
        fn malformed_parameter_signature_descriptors_are_rejected(mut tune in proptest::collection::vec(any::<u8>(), crate::TUNE_LEN..=crate::TUNE_LEN)) {
            tune[0x130..0x134].copy_from_slice(&u32::MAX.to_be_bytes());
            prop_assert!(sign_ms45_parameters(&mut tune).is_err());
        }
    }
}
