use ms45_core::{
    prepare_tune, verify_flash_mpc_match, verify_parameter_match, FlashPlan, FlashSegment,
    MemoryRegion, EXTERNAL_FLASH_LEN, MPC_FLASH_LEN, TUNE_LEN,
};

#[test]
fn synthetic_compatibility_corpus_matches_expected_outcomes() {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("../../../fixtures/compatibility/v1.json")).unwrap();
    assert_eq!(
        manifest["schema_version"],
        "ms45.synthetic-compatibility.v1"
    );
    let cases = manifest["cases"].as_array().unwrap();
    assert!(cases.len() >= 8);
    for case in cases {
        let recipe = case["recipe"].as_str().unwrap();
        let accepted = match recipe {
            "tune_valid" | "tune_nonnumeric" | "tune_embedded_reference" => {
                let mut tune = vec![0u8; TUNE_LEN];
                tune[0x10..0x1c].copy_from_slice(if recipe == "tune_nonnumeric" {
                    b"not-numeric!"
                } else {
                    b"7561520\0\0\0\0\0"
                });
                verify_parameter_match(
                    &tune,
                    if recipe == "tune_embedded_reference" {
                        "17561520"
                    } else {
                        "7561520"
                    },
                )
                .unwrap_or(false)
            }
            "tune_truncated" => prepare_tune(&vec![0u8; TUNE_LEN - 1]).is_ok(),
            "pair_valid" | "pair_mismatch" => {
                let mut flash = vec![0u8; EXTERNAL_FLASH_LEN];
                let mut mpc = vec![0u8; MPC_FLASH_LEN];
                flash[0x60310..0x6031a].copy_from_slice(if recipe == "pair_valid" {
                    b"0000010500"
                } else {
                    b"0000010400"
                });
                mpc[0x100..0x10a].copy_from_slice(b"0000010000");
                verify_flash_mpc_match(&flash, &mpc).unwrap_or(false)
            }
            "overlap" => FlashPlan::new(
                "HW1",
                None,
                vec![
                    FlashSegment {
                        region: MemoryRegion::ExternalFlash,
                        start: 0,
                        data: vec![1; 8],
                    },
                    FlashSegment {
                        region: MemoryRegion::ExternalFlash,
                        start: 4,
                        data: vec![2; 8],
                    },
                ],
                4,
                false,
            )
            .is_ok(),
            _ => panic!("unknown corpus recipe"),
        };
        assert_eq!(
            accepted,
            case["accept"].as_bool().unwrap(),
            "{}: {}",
            case["id"],
            case["reason"]
        );
    }
}
