use assert_cmd::Command;
use predicates::prelude::*;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

fn respond(stream: &mut TcpStream, request: &[u8; 22], payload: &[u8]) {
    let mut response = b"MS45R1".to_vec();
    response.extend_from_slice(&request[6..14]);
    response.push(0);
    response.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    response.extend_from_slice(payload);
    stream.write_all(&response).unwrap();
}

fn backup_command(
    address: std::net::SocketAddr,
    output: &std::path::Path,
    length: &str,
) -> Command {
    let vin_hash = format!("{:x}", Sha256::digest(b"TESTVIN"));
    let mut command = Command::cargo_bin("ms45").unwrap();
    command.args([
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
        length,
        "--output",
        output.to_str().unwrap(),
    ]);
    command
}

#[test]
fn version_is_available_for_bench_receipts() {
    Command::cargo_bin("ms45")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::is_match("^ms45 [0-9]+\\.[0-9]+\\.[0-9]+\\n$").unwrap());
}

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
            respond(&mut stream, &request, payload);
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

#[test]
fn backup_resumes_only_verified_blocks_after_disconnect() {
    let first_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let first_address = first_listener.local_addr().unwrap();
    let first_server = std::thread::spawn(move || {
        let (mut stream, _) = first_listener.accept().unwrap();
        let mut request = [0u8; 22];
        stream.read_exact(&mut request).unwrap();
        respond(&mut stream, &request, b"MS45.1|HW1|SW1|TESTVIN");
        stream.read_exact(&mut request).unwrap();
        assert_eq!(u32::from_be_bytes(request[16..20].try_into().unwrap()), 0);
        respond(&mut stream, &request, &[0x45; 4096]);
        // Consume the next request and disconnect without a complete response.
        stream.read_exact(&mut request).unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("backup.bin");
    backup_command(first_address, &output, "5000")
        .assert()
        .failure();
    first_server.join().unwrap();
    assert_eq!(
        std::fs::metadata(output.with_file_name("backup.bin.partial"))
            .unwrap()
            .len(),
        4096
    );
    assert!(output.with_file_name("backup.bin.progress.json").exists());

    let second_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let second_address = second_listener.local_addr().unwrap();
    let second_server = std::thread::spawn(move || {
        let (mut stream, _) = second_listener.accept().unwrap();
        let mut request = [0u8; 22];
        stream.read_exact(&mut request).unwrap();
        respond(&mut stream, &request, b"MS45.1|HW1|SW1|TESTVIN");
        stream.read_exact(&mut request).unwrap();
        assert_eq!(
            u32::from_be_bytes(request[16..20].try_into().unwrap()),
            4096
        );
        assert_eq!(u16::from_be_bytes(request[20..22].try_into().unwrap()), 904);
        respond(&mut stream, &request, &[0x46; 904]);
    });
    backup_command(second_address, &output, "5000")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"resumed_bytes\":4096"));
    second_server.join().unwrap();
    let bytes = std::fs::read(&output).unwrap();
    assert_eq!(&bytes[..4096], &[0x45; 4096]);
    assert_eq!(&bytes[4096..], &[0x46; 904]);
    assert!(!output.with_file_name("backup.bin.partial").exists());
    assert!(!output.with_file_name("backup.bin.progress.json").exists());
}

#[test]
fn backup_rejects_corrupted_verified_progress() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 22];
        stream.read_exact(&mut request).unwrap();
        respond(&mut stream, &request, b"MS45.1|HW1|SW1|TESTVIN");
        stream.read_exact(&mut request).unwrap();
        respond(&mut stream, &request, &[0x45; 4096]);
        stream.read_exact(&mut request).unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("backup.bin");
    backup_command(address, &output, "5000").assert().failure();
    server.join().unwrap();
    let partial = output.with_file_name("backup.bin.partial");
    let mut bytes = std::fs::read(&partial).unwrap();
    bytes[0] ^= 1;
    std::fs::write(&partial, bytes).unwrap();

    let retry_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let retry_address = retry_listener.local_addr().unwrap();
    let retry_server = std::thread::spawn(move || {
        let (mut stream, _) = retry_listener.accept().unwrap();
        let mut request = [0u8; 22];
        stream.read_exact(&mut request).unwrap();
        respond(&mut stream, &request, b"MS45.1|HW1|SW1|TESTVIN");
    });
    backup_command(retry_address, &output, "5000")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "partial backup block 0 failed verification",
        ));
    retry_server.join().unwrap();
}
