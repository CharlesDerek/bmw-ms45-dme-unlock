use assert_cmd::Command;
use predicates::prelude::*;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpListener;

#[test]
fn security_message_accepts_common_hex_formats() {
    Command::cargo_bin("ms45")
        .unwrap()
        .args([
            "security-message",
            "--user-id",
            "01:02:03:04",
            "--serial",
            "0x05060708",
            "--seed",
            "09-0a-0b-0c",
        ])
        .assert()
        .success()
        .stdout(predicate::str::is_match("^[0-9a-f]{180}\n$").unwrap());
}

#[test]
fn security_message_rejects_odd_length_hex() {
    Command::cargo_bin("ms45")
        .unwrap()
        .args([
            "security-message",
            "--user-id",
            "0102030",
            "--serial",
            "05060708",
            "--seed",
            "090a0b0c",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "hex input must contain an even number of digits",
        ));
}

#[test]
fn validate_reports_tune_reference_match() {
    let temp = tempfile::tempdir().unwrap();
    let tune_path = temp.path().join("tune.bin");
    let mut tune = vec![0; ms45_core::TUNE_LEN];
    tune[0x10..0x1c].copy_from_slice(b"7561520\0\0\0\0\0");
    std::fs::write(&tune_path, tune).unwrap();

    Command::cargo_bin("ms45")
        .unwrap()
        .args([
            "validate",
            "--tune",
            tune_path.to_str().unwrap(),
            "--sw-ref",
            "BMW ZB 7561520",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "tune/software reference match: true",
        ));
}

#[test]
fn backup_pins_identity_and_verifies_saved_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        for payload in [b"MS45.1|HW1|SW1|TESTVIN".as_slice(), &[0x45; 16]] {
            let mut request = [0u8; 22];
            stream.read_exact(&mut request).unwrap();
            let mut response = b"MS45R1".to_vec();
            response.extend_from_slice(&request[6..14]);
            response.push(0);
            response.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            response.extend_from_slice(payload);
            stream.write_all(&response).unwrap();
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("backup.bin");
    let vin_hash = format!("{:x}", Sha256::digest(b"TESTVIN"));
    Command::cargo_bin("ms45")
        .unwrap()
        .args([
            "backup",
            "--adapter",
            &address.to_string(),
            "--expected-variant",
            "MS45.1",
            "--expected-hw-ref",
            "HW1",
            "--expected-sw-ref",
            "SW1",
            "--expected-vin-sha256",
            &vin_hash,
            "--region",
            "external",
            "--start",
            "0",
            "--length",
            "16",
            "--output",
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\":\"verified\""));
    server.join().unwrap();
    assert_eq!(std::fs::read(output).unwrap(), vec![0x45; 16]);
}
