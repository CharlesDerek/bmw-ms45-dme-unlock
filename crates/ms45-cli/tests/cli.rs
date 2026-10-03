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
    bridge_version: &str,
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
        "--bridge-version",
        bridge_version,
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
fn probe_reports_hashed_metadata_without_requesting_memory() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 22];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request[..6], b"MS45R1");
        assert_eq!(request[14], 3, "probe must use the metadata-only operation");
        assert_eq!(&request[15..], &[0; 7]);
        respond(
            &mut stream,
            &request,
            b"MS45.1|0044570|7561520|1|BMW-FAST|TESTVIN",
        );
        stream
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .unwrap();
        assert_eq!(stream.read(&mut [0u8; 1]).unwrap_or(0), 0);
    });
    let output = Command::cargo_bin("ms45")
        .unwrap()
        .args(["probe", "--adapter", &address.to_string()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], "ms45.hardware-probe.v1");
    assert_eq!(report["variant"], "MS45.1");
    assert_eq!(report["hardware_reference"], "0044570");
    assert_eq!(report["software_reference"], "7561520");
    assert_eq!(report["programming_status"], "1");
    assert_eq!(report["diagnostic_protocol"], "BMW-FAST");
    assert_eq!(
        report["vin_sha256"],
        format!("{:x}", Sha256::digest(b"TESTVIN"))
    );
    assert!(report.get("vin").is_none());
    server.join().unwrap();
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
fn json_mode_emits_versioned_operation_and_error_documents() {
    let success = Command::cargo_bin("ms45")
        .unwrap()
        .args([
            "--json",
            "security-message",
            "--user-id",
            "01020304",
            "--serial",
            "05060708",
            "--seed",
            "090a0b0c",
        ])
        .output()
        .unwrap();
    assert!(success.status.success());
    let result: serde_json::Value = serde_json::from_slice(&success.stdout).unwrap();
    assert_eq!(result["schema_version"], "ms45.operation-result.v1");
    assert_eq!(result["status"], "success");
    assert_eq!(result["operation"], "security-message");
    assert_eq!(result["result"]["message_hex"].as_str().unwrap().len(), 180);
    assert_eq!(result.as_object().unwrap().len(), 4);

    let failure = Command::cargo_bin("ms45")
        .unwrap()
        .args(["--json", "security-message", "--user-id", "0102030"])
        .output()
        .unwrap();
    assert_eq!(failure.status.code(), Some(2));
    assert!(failure.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&failure.stderr).unwrap();
    assert_eq!(error["schema_version"], "ms45.cli-error.v1");
    assert_eq!(error["status"], "error");
    assert_eq!(error["code"], "invalid_arguments");
    assert!(error["operation"].is_null());
    assert!(error["causes"].is_array());
    assert_eq!(error.as_object().unwrap().len(), 6);

    let runtime_failure = Command::cargo_bin("ms45")
        .unwrap()
        .args([
            "--json",
            "security-message",
            "--user-id",
            "01020304",
            "--serial",
            "05060708",
            "--seed",
            "abc",
        ])
        .output()
        .unwrap();
    assert_eq!(runtime_failure.status.code(), Some(1));
    let error: serde_json::Value = serde_json::from_slice(&runtime_failure.stderr).unwrap();
    assert_eq!(error["code"], "operation_failed");
    assert_eq!(error["operation"], "security-message");
    assert_eq!(
        error["message"],
        "hex input must contain an even number of digits"
    );
}

#[test]
fn checked_in_json_schemas_are_versioned_and_strict() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (path, version) in [
        ("docs/schemas/cli-error-v1.schema.json", "ms45.cli-error.v1"),
        (
            "docs/schemas/operation-result-v1.schema.json",
            "ms45.operation-result.v1",
        ),
        (
            "docs/schemas/backup-receipt-v1.schema.json",
            "ms45.backup-receipt.v1",
        ),
    ] {
        let schema: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join(path)).unwrap()).unwrap();
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["schema_version"]["const"], version);
    }
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
fn creates_and_verifies_a_signed_flash_plan() {
    let dir = tempfile::tempdir().unwrap();
    let payload = dir.path().join("payload.bin");
    let key = dir.path().join("signing-key.hex");
    let plan = dir.path().join("flash-plan.json");
    std::fs::write(&payload, [0x45, 0x46, 0x47, 0x48]).unwrap();
    std::fs::write(
        &key,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
    )
    .unwrap();
    let vin_hash = format!("{:x}", Sha256::digest(b"TESTVIN"));
    let segment = format!("external:0x100:{}", payload.display());
    let output = Command::cargo_bin("ms45")
        .unwrap()
        .args([
            "create-flash-plan",
            "--expected-variant",
            "MS45.1",
            "--expected-hw-ref",
            "0044570",
            "--expected-sw-ref",
            "7561520",
            "--expected-vin-sha256",
            &vin_hash,
            "--segment",
            &segment,
            "--block-size",
            "1024",
            "--signature-target",
            "parameter",
            "--signing-key",
            key.to_str().unwrap(),
            "--output",
            plan.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let artifact: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&plan).unwrap()).unwrap();
    assert_eq!(artifact["schema_version"], "ms45.flash-plan.v1");
    assert_eq!(artifact["plan"]["approved_identity"]["variant"], "MS45.1");
    assert_eq!(
        artifact["plan"]["approved_identity"]["vin_sha256"],
        vin_hash
    );
    assert_eq!(artifact["plan"]["block_size"], 1024);
    assert_eq!(artifact["plan"]["segments"][0]["start"], 256);
    assert_eq!(artifact["plan"]["segments"][0]["end_exclusive"], 260);
    assert_eq!(
        artifact["plan"]["segments"][0]["sha256"],
        format!("{:x}", Sha256::digest([0x45, 0x46, 0x47, 0x48]))
    );
    assert_eq!(artifact["plan"]["intended_operations"][0], "identify");
    let public_key = artifact["signing"]["public_key"].as_str().unwrap();
    assert_eq!(public_key.len(), 64);

    Command::cargo_bin("ms45")
        .unwrap()
        .args([
            "verify-flash-plan",
            "--input",
            plan.to_str().unwrap(),
            "--expected-public-key",
            public_key,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\":\"verified\""));

    let inspection = Command::cargo_bin("ms45")
        .unwrap()
        .args([
            "inspect-flash-plan",
            "--input",
            plan.to_str().unwrap(),
            "--expected-public-key",
            public_key,
        ])
        .output()
        .unwrap();
    assert!(
        inspection.status.success(),
        "{}",
        String::from_utf8_lossy(&inspection.stderr)
    );
    let inspection: serde_json::Value = serde_json::from_slice(&inspection.stdout).unwrap();
    assert_eq!(
        inspection["schema_version"],
        "ms45.flash-plan-inspection.v1"
    );
    assert_eq!(inspection["signature_status"], "verified");
    assert_eq!(inspection["total_bytes"], 4);
    assert_eq!(inspection["erase_ranges"][0]["start"], 256);
    assert_eq!(inspection["erase_ranges"][0]["end_exclusive"], 260);
    assert_eq!(inspection["write_ranges"][0]["start"], 256);
    assert_eq!(inspection["write_ranges"][0]["end_exclusive"], 260);
}

#[test]
fn inspection_lists_each_exact_block_write_range() {
    let dir = tempfile::tempdir().unwrap();
    let payload = dir.path().join("payload.bin");
    let key = dir.path().join("signing-key.hex");
    let plan = dir.path().join("flash-plan.json");
    std::fs::write(&payload, [0x45; 10]).unwrap();
    std::fs::write(
        &key,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    )
    .unwrap();
    let segment = format!("mpc:0x20:{}", payload.display());
    let create = Command::cargo_bin("ms45")
        .unwrap()
        .args([
            "create-flash-plan",
            "--expected-variant",
            "MS45.0",
            "--expected-hw-ref",
            "HW1",
            "--expected-sw-ref",
            "SW1",
            "--expected-vin-sha256",
            &"ab".repeat(32),
            "--segment",
            &segment,
            "--block-size",
            "4",
            "--signature-target",
            "program",
            "--signing-key",
            key.to_str().unwrap(),
            "--output",
            plan.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(create.status.success());
    let created: serde_json::Value = serde_json::from_slice(&create.stdout).unwrap();
    let public_key = created["public_key"].as_str().unwrap();
    let output = Command::cargo_bin("ms45")
        .unwrap()
        .args([
            "inspect-flash-plan",
            "--input",
            plan.to_str().unwrap(),
            "--expected-public-key",
            public_key,
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["erase_ranges"][0]["length"], 10);
    assert_eq!(report["write_ranges"].as_array().unwrap().len(), 3);
    assert_eq!(report["write_ranges"][0]["start"], 0x20);
    assert_eq!(report["write_ranges"][0]["end_exclusive"], 0x24);
    assert_eq!(report["write_ranges"][1]["start"], 0x24);
    assert_eq!(report["write_ranges"][1]["end_exclusive"], 0x28);
    assert_eq!(report["write_ranges"][2]["start"], 0x28);
    assert_eq!(report["write_ranges"][2]["end_exclusive"], 0x2a);
}

#[test]
fn flash_plan_verification_rejects_tampering_and_unapproved_signers() {
    let dir = tempfile::tempdir().unwrap();
    let payload = dir.path().join("payload.bin");
    let key = dir.path().join("signing-key.hex");
    let plan = dir.path().join("flash-plan.json");
    std::fs::write(&payload, [0x45; 16]).unwrap();
    std::fs::write(
        &key,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    )
    .unwrap();
    let segment = format!("external:0:{}", payload.display());
    Command::cargo_bin("ms45")
        .unwrap()
        .args([
            "create-flash-plan",
            "--expected-variant",
            "MS45.0",
            "--expected-hw-ref",
            "HW1",
            "--expected-sw-ref",
            "SW1",
            "--expected-vin-sha256",
            &"ab".repeat(32),
            "--segment",
            &segment,
            "--signature-target",
            "program",
            "--signing-key",
            key.to_str().unwrap(),
            "--output",
            plan.to_str().unwrap(),
        ])
        .assert()
        .success();
    let mut artifact: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&plan).unwrap()).unwrap();
    let public_key = artifact["signing"]["public_key"]
        .as_str()
        .unwrap()
        .to_owned();
    artifact["plan"]["segments"][0]["sha256"] = serde_json::Value::String("cd".repeat(32));
    std::fs::write(&plan, serde_json::to_vec_pretty(&artifact).unwrap()).unwrap();

    Command::cargo_bin("ms45")
        .unwrap()
        .args([
            "verify-flash-plan",
            "--input",
            plan.to_str().unwrap(),
            "--expected-public-key",
            &public_key,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("signature verification failed"));
    Command::cargo_bin("ms45")
        .unwrap()
        .args([
            "verify-flash-plan",
            "--input",
            plan.to_str().unwrap(),
            "--expected-public-key",
            &"00".repeat(32),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("signer does not match"));
}

#[test]
fn backup_pins_identity_and_verifies_saved_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        for payload in [
            b"MS45.1|HW1|SW1|1|BMW-FAST|TESTVIN".as_slice(),
            &[0x45; 16],
            &[0x45; 16],
        ] {
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
            "--bridge-version",
            "1.0.0",
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
        .stdout(predicate::str::contains("\"status\":\"verified\""))
        .stdout(predicate::str::contains("\"read_passes\":2"));
    server.join().unwrap();
    assert_eq!(std::fs::read(output).unwrap(), vec![0x45; 16]);
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dir.path().join("backup.bin.manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["schema_version"], "ms45.backup-manifest.v1");
    assert_eq!(manifest["bridge_version"], "1.0.0");
    assert_eq!(manifest["address_range"]["end_exclusive"], 16);
    assert_eq!(manifest["binary"]["length"], 16);
    assert_eq!(
        manifest["binary"]["sha256"],
        format!("{:x}", Sha256::digest([0x45; 16]))
    );
    assert_eq!(manifest["read_parameters"]["block_size"], 4096);
    assert_eq!(manifest["read_parameters"]["timeout_milliseconds"], 3000);
    assert_eq!(manifest["read_parameters"]["passes"], 2);
    assert!(manifest["timestamps"]["started_at"]
        .as_str()
        .unwrap()
        .ends_with('Z'));
    assert_eq!(
        manifest["ecu_identity_hashes"]["vin_sha256"],
        format!("{:x}", Sha256::digest(b"TESTVIN"))
    );
    assert!(
        manifest["ecu_identity_hashes"]["hardware_reference_sha256"]
            .as_str()
            .unwrap()
            .len()
            == 64
    );
}

#[test]
fn backup_can_publish_only_operator_encrypted_output() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        for payload in [
            b"MS45.1|HW1|SW1|1|BMW-FAST|TESTVIN".as_slice(),
            &[0x45; 16],
            &[0x45; 16],
        ] {
            let mut request = [0u8; 22];
            stream.read_exact(&mut request).unwrap();
            respond(&mut stream, &request, payload);
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("backup.enc");
    let command_output = backup_command(address, &output, "16", "1.0.0")
        .args([
            "--encrypt-with",
            "/usr/bin/tr",
            "--encrypt-arg",
            "E",
            "--encrypt-arg",
            "X",
        ])
        .output()
        .unwrap();
    assert!(
        command_output.status.success(),
        "{}",
        String::from_utf8_lossy(&command_output.stderr)
    );
    server.join().unwrap();

    assert_eq!(std::fs::read(&output).unwrap(), vec![b'X'; 16]);
    assert!(!output.with_file_name("backup.enc.partial").exists());
    assert!(!output.with_file_name("backup.enc.progress.json").exists());
    let receipt: serde_json::Value = serde_json::from_slice(&command_output.stdout).unwrap();
    assert_eq!(receipt["schema_version"], "ms45.backup-receipt.v1");
    assert_eq!(receipt["encrypted"], true);
    assert_eq!(
        receipt["sha256"],
        format!("{:x}", Sha256::digest([b'E'; 16]))
    );
    assert_eq!(
        receipt["output_sha256"],
        format!("{:x}", Sha256::digest([b'X'; 16]))
    );
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(output.with_file_name("backup.enc.manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["schema_version"], "ms45.backup-manifest.v2");
    assert_eq!(manifest["binary"]["sha256"], receipt["output_sha256"]);
    assert_eq!(manifest["plaintext"]["sha256"], receipt["sha256"]);
    assert_eq!(
        manifest["encryption"]["method"],
        "external-command-stdin-stdout"
    );
    assert_eq!(manifest["encryption"]["command"], "/usr/bin/tr");
}

#[test]
fn failed_encryption_retains_verified_plaintext_recovery_without_output() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        for payload in [
            b"MS45.1|HW1|SW1|1|BMW-FAST|TESTVIN".as_slice(),
            &[0x45; 16],
            &[0x45; 16],
        ] {
            let mut request = [0u8; 22];
            stream.read_exact(&mut request).unwrap();
            respond(&mut stream, &request, payload);
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("backup.enc");
    backup_command(address, &output, "16", "1.0.0")
        .args(["--encrypt-with", "/bin/false"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "encryption command /bin/false failed",
        ));
    server.join().unwrap();

    assert!(!output.exists());
    assert!(!output.with_file_name("backup.enc.manifest.json").exists());
    assert_eq!(
        std::fs::read(output.with_file_name("backup.enc.partial")).unwrap(),
        vec![0x45; 16]
    );
    assert!(output.with_file_name("backup.enc.progress.json").exists());
}

#[test]
fn backup_refuses_to_overwrite_an_existing_output() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 22];
        stream.read_exact(&mut request).unwrap();
        respond(&mut stream, &request, b"MS45.1|HW1|SW1|1|BMW-FAST|TESTVIN");
        stream
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .unwrap();
        assert_eq!(stream.read(&mut [0u8; 1]).unwrap_or(0), 0);
    });
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("backup.bin");
    std::fs::write(&output, b"keep this backup").unwrap();

    backup_command(address, &output, "16", "1.0.0")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "refusing to overwrite existing backup output",
        ));

    server.join().unwrap();
    assert_eq!(std::fs::read(&output).unwrap(), b"keep this backup");
    assert!(!output.with_file_name("backup.bin.partial").exists());
}

#[test]
fn backup_retains_verified_files_when_manifest_persistence_fails() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("backup.bin");
    let manifest = output.with_file_name("backup.bin.manifest.json");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let blocked_manifest = manifest.clone();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        for (index, payload) in [
            b"MS45.1|HW1|SW1|1|BMW-FAST|TESTVIN".as_slice(),
            &[0x45; 16],
            &[0x45; 16],
        ]
        .into_iter()
        .enumerate()
        {
            let mut request = [0u8; 22];
            stream.read_exact(&mut request).unwrap();
            if index == 2 {
                std::fs::create_dir(&blocked_manifest).unwrap();
            }
            respond(&mut stream, &request, payload);
        }
    });

    backup_command(address, &output, "16", "1.0.0")
        .assert()
        .failure()
        .stderr(predicate::str::contains("recovery data retained at"));
    server.join().unwrap();

    let partial = output.with_file_name("backup.bin.partial");
    let progress = output.with_file_name("backup.bin.progress.json");
    assert_eq!(std::fs::read(&output).unwrap(), vec![0x45; 16]);
    assert_eq!(std::fs::read(&partial).unwrap(), vec![0x45; 16]);
    assert!(progress.exists());

    std::fs::remove_dir(&manifest).unwrap();
    let retry_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let retry_address = retry_listener.local_addr().unwrap();
    let retry_server = std::thread::spawn(move || {
        let (mut stream, _) = retry_listener.accept().unwrap();
        for payload in [b"MS45.1|HW1|SW1|1|BMW-FAST|TESTVIN".as_slice(), &[0x45; 16]] {
            let mut request = [0u8; 22];
            stream.read_exact(&mut request).unwrap();
            respond(&mut stream, &request, payload);
        }
    });
    backup_command(retry_address, &output, "16", "1.0.0")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"resumed_bytes\":16"));
    retry_server.join().unwrap();
    assert!(!partial.exists());
    assert!(!progress.exists());
    assert!(manifest.is_file());
}

#[test]
fn backup_rejects_unsafe_programming_state_before_reading_memory() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 22];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(request[14], 3);
        respond(&mut stream, &request, b"MS45.1|HW1|SW1|7|BMW-FAST|TESTVIN");
        stream
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .unwrap();
        assert_eq!(stream.read(&mut [0u8; 1]).unwrap_or(0), 0);
    });
    let dir = tempfile::tempdir().unwrap();
    backup_command(address, &dir.path().join("backup.bin"), "16", "1.2.0")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "programming state 7 is not supported",
        ));
    server.join().unwrap();
}

#[test]
fn backup_resumes_only_verified_blocks_after_disconnect() {
    let first_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let first_address = first_listener.local_addr().unwrap();
    let first_server = std::thread::spawn(move || {
        let (mut stream, _) = first_listener.accept().unwrap();
        let mut request = [0u8; 22];
        stream.read_exact(&mut request).unwrap();
        respond(&mut stream, &request, b"MS45.1|HW1|SW1|1|BMW-FAST|TESTVIN");
        stream.read_exact(&mut request).unwrap();
        assert_eq!(u32::from_be_bytes(request[16..20].try_into().unwrap()), 0);
        respond(&mut stream, &request, &[0x45; 4096]);
        // Consume the next request and disconnect without a complete response.
        stream.read_exact(&mut request).unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("backup.bin");
    backup_command(first_address, &output, "5000", "1.0.0")
        .assert()
        .failure();
    first_server.join().unwrap();
    assert_eq!(
        std::fs::metadata(output.with_file_name("backup.bin.partial"))
            .unwrap()
            .len(),
        4096
    );
    let progress_path = output.with_file_name("backup.bin.progress.json");
    let started_at =
        serde_json::from_slice::<serde_json::Value>(&std::fs::read(&progress_path).unwrap())
            .unwrap()["started_at"]
            .as_str()
            .unwrap()
            .to_owned();

    let second_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let second_address = second_listener.local_addr().unwrap();
    let second_server = std::thread::spawn(move || {
        let (mut stream, _) = second_listener.accept().unwrap();
        let mut request = [0u8; 22];
        stream.read_exact(&mut request).unwrap();
        respond(&mut stream, &request, b"MS45.1|HW1|SW1|1|BMW-FAST|TESTVIN");
        drop(stream);

        let (mut stream, _) = second_listener.accept().unwrap();
        stream.read_exact(&mut request).unwrap();
        respond(&mut stream, &request, b"MS45.1|HW1|SW1|1|BMW-FAST|TESTVIN");
        stream.read_exact(&mut request).unwrap();
        assert_eq!(
            u32::from_be_bytes(request[16..20].try_into().unwrap()),
            4096
        );
        assert_eq!(u16::from_be_bytes(request[20..22].try_into().unwrap()), 904);
        respond(&mut stream, &request, &[0x46; 904]);
        stream.read_exact(&mut request).unwrap();
        assert_eq!(u32::from_be_bytes(request[16..20].try_into().unwrap()), 0);
        assert_eq!(
            u16::from_be_bytes(request[20..22].try_into().unwrap()),
            4096
        );
        respond(&mut stream, &request, &[0x45; 4096]);
        stream.read_exact(&mut request).unwrap();
        assert_eq!(
            u32::from_be_bytes(request[16..20].try_into().unwrap()),
            4096
        );
        assert_eq!(u16::from_be_bytes(request[20..22].try_into().unwrap()), 904);
        respond(&mut stream, &request, &[0x46; 904]);
    });
    backup_command(second_address, &output, "5000", "2.0.0")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "backup progress does not match ECU identity or requested range",
        ));
    backup_command(second_address, &output, "5000", "1.0.0")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"resumed_bytes\":4096"));
    second_server.join().unwrap();
    let bytes = std::fs::read(&output).unwrap();
    assert_eq!(&bytes[..4096], &[0x45; 4096]);
    assert_eq!(&bytes[4096..], &[0x46; 904]);
    assert!(!output.with_file_name("backup.bin.partial").exists());
    assert!(!progress_path.exists());
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(output.with_file_name("backup.bin.manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["timestamps"]["started_at"], started_at);
}

#[test]
fn backup_rejects_mismatched_independent_read_passes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        for payload in [
            b"MS45.1|HW1|SW1|1|BMW-FAST|TESTVIN".as_slice(),
            &[0x45; 16],
            &[0x46; 16],
        ] {
            let mut request = [0u8; 22];
            stream.read_exact(&mut request).unwrap();
            respond(&mut stream, &request, payload);
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("backup.bin");
    backup_command(address, &output, "16", "1.0.0")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "independent read pass hashes do not match",
        ));
    server.join().unwrap();
    assert!(!output.exists());
    assert!(!output.with_file_name("backup.bin.manifest.json").exists());
    assert!(output.with_file_name("backup.bin.partial").exists());
    assert!(output.with_file_name("backup.bin.progress.json").exists());
}

#[test]
fn backup_rejects_corrupted_verified_progress() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 22];
        stream.read_exact(&mut request).unwrap();
        respond(&mut stream, &request, b"MS45.1|HW1|SW1|1|BMW-FAST|TESTVIN");
        stream.read_exact(&mut request).unwrap();
        respond(&mut stream, &request, &[0x45; 4096]);
        stream.read_exact(&mut request).unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("backup.bin");
    backup_command(address, &output, "5000", "1.0.0")
        .assert()
        .failure();
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
        respond(&mut stream, &request, b"MS45.1|HW1|SW1|1|BMW-FAST|TESTVIN");
    });
    backup_command(retry_address, &output, "5000", "1.0.0")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "partial backup block 0 failed verification",
        ));
    retry_server.join().unwrap();
}
