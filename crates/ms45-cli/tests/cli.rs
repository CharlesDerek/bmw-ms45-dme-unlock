use assert_cmd::Command;
use predicates::prelude::*;

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
