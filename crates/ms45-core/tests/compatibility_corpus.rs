use std::collections::{HashMap, HashSet};

use ms45_core::{
    prepare_tune, verify_flash_mpc_match, verify_parameter_match, verify_program_match, FlashPlan,
    FlashSegment, MemoryRegion, EXTERNAL_FLASH_LEN, MPC_FLASH_LEN, TUNE_LEN,
};
use serde_json::Value;

const MANIFEST: &str = include_str!("../../../fixtures/compatibility/v1.json");

fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field]
        .as_str()
        .unwrap_or_else(|| panic!("fixture field {field} must be a string"))
}

fn write_field(target: &mut [u8], offset: usize, value: &str, length: usize) {
    assert_eq!(value.len(), length, "invalid sanitized fixture field");
    target[offset..offset + length].copy_from_slice(value.as_bytes());
}

fn materialize(layout: &Value) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut tune = vec![0u8; TUNE_LEN];
    let mut external = vec![0u8; EXTERNAL_FLASH_LEN];
    let mut mpc = vec![0u8; MPC_FLASH_LEN];

    let software = format!("{:<12}", text(layout, "software_reference"));
    write_field(&mut tune, 0x10, &software, 0x0c);
    write_field(
        &mut external,
        0x60310,
        text(layout, "external_pair_reference"),
        0x0a,
    );
    write_field(
        &mut external,
        0x6031c,
        text(layout, "program_hardware_field"),
        0x0c,
    );
    write_field(&mut mpc, 0x100, text(layout, "mpc_pair_reference"), 0x0a);
    (tune, external, mpc)
}

#[test]
fn sanitized_layouts_are_distinct_redistributable_structures() {
    let manifest: Value = serde_json::from_str(MANIFEST).unwrap();
    assert_eq!(manifest["license"], "CC0-1.0");
    assert!(text(&manifest, "source").contains("no ECU code"));

    let layouts = manifest["layouts"].as_array().unwrap();
    assert_eq!(layouts.len(), 4);
    let variants: HashSet<_> = layouts
        .iter()
        .map(|layout| text(layout, "variant"))
        .collect();
    assert_eq!(variants, HashSet::from(["MS45.0", "MS45.1"]));
    let identities: HashSet<_> = layouts
        .iter()
        .map(|layout| {
            (
                text(layout, "software_reference"),
                text(layout, "program_hardware_field"),
                text(layout, "external_pair_reference"),
            )
        })
        .collect();
    assert_eq!(identities.len(), layouts.len());
}

#[test]
fn synthetic_compatibility_corpus_matches_expected_outcomes() {
    let manifest: Value = serde_json::from_str(MANIFEST).unwrap();
    assert_eq!(
        manifest["schema_version"],
        "ms45.synthetic-compatibility.v1"
    );
    let layouts: HashMap<_, _> = manifest["layouts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|layout| (text(layout, "id"), layout))
        .collect();
    let cases = manifest["cases"].as_array().unwrap();
    assert!(cases.len() >= 10);

    for case in cases {
        let layout = layouts[text(case, "layout")];
        let (mut tune, mut external, mpc) = materialize(layout);
        let accepted = match text(case, "recipe") {
            "known_layout" => {
                verify_parameter_match(&tune, text(layout, "software_reference")).unwrap()
                    && verify_program_match(&external, text(layout, "hardware_reference")).unwrap()
                    && verify_flash_mpc_match(&external, &mpc).unwrap()
            }
            "tune_truncated" => prepare_tune(&tune[..TUNE_LEN - 1]).is_ok(),
            "tune_nonnumeric" => {
                tune[0x10..0x1c].copy_from_slice(b"not-numeric!");
                verify_parameter_match(&tune, text(layout, "software_reference")).unwrap_or(false)
            }
            "tune_embedded_reference" => {
                verify_parameter_match(&tune, &format!("1{}", text(layout, "software_reference")))
                    .unwrap_or(false)
            }
            "hardware_mismatch" => verify_program_match(&external, "9999999").unwrap_or(false),
            "pair_mismatch" => {
                external[0x60310..0x6031a].copy_from_slice(b"0000099999");
                verify_flash_mpc_match(&external, &mpc).unwrap_or(false)
            }
            "overlap" => FlashPlan::new(
                text(layout, "hardware_reference"),
                Some(text(layout, "software_reference").to_owned()),
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
            recipe => panic!("unknown corpus recipe {recipe}"),
        };
        assert_eq!(
            accepted,
            case["accept"].as_bool().unwrap(),
            "{}: {}",
            text(case, "id"),
            text(case, "reason")
        );
    }
}
