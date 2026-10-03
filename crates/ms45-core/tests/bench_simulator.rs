use ms45_core::{
    BenchFault, BenchOperation, BenchOutcome, BenchSimulator, DmeIdentity, FaultPoint, FlashError,
    FlashPlan, FlashSegment, MemoryRegion,
};
use std::time::Duration;

const START: u32 = 0x1000;

fn identity() -> DmeIdentity {
    DmeIdentity {
        vin: "SIMULATEDVIN".into(),
        hardware_reference: "HW-45".into(),
        software_reference: "SW-1".into(),
        programming_status: "1".into(),
        diag_protocol: "simulated".into(),
    }
}

fn plan() -> FlashPlan {
    FlashPlan::new(
        "HW-45",
        Some("SW-1".into()),
        vec![FlashSegment {
            region: MemoryRegion::ExternalFlash,
            start: START,
            data: (0..10).collect(),
        }],
        4,
        false,
    )
    .unwrap()
}

fn assert_reset_fenced(simulator: &BenchSimulator) {
    assert!(!simulator
        .events()
        .iter()
        .any(|event| event.operation == BenchOperation::Reset));
}

#[test]
fn successful_run_is_repeatable_and_records_the_workflow() {
    let mut first = BenchSimulator::new(identity());
    let mut second = first.clone();
    let first_receipt = plan().execute(&mut first, &mut |_| {}).unwrap();
    let second_receipt = plan().execute(&mut second, &mut |_| {}).unwrap();

    assert_eq!(first_receipt.bytes_written, 10);
    assert_eq!(first_receipt, second_receipt);
    assert_eq!(first.snapshot(START, 10), (0..10).collect::<Vec<_>>());
    assert_eq!(first.events(), second.events());
    assert_eq!(first.snapshot(START, 10), second.snapshot(START, 10));
}

#[test]
fn timing_failure_advances_only_virtual_time_and_fences_reset() {
    let mut simulator = BenchSimulator::new(identity());
    simulator
        .add_fault(BenchFault::Timeout {
            at: FaultPoint::new(BenchOperation::Erase, 1),
            elapsed: Duration::from_secs(2),
        })
        .unwrap();

    assert!(matches!(
        plan().execute(&mut simulator, &mut |_| {}),
        Err(FlashError::Backend(message)) if message.contains("timed out")
    ));
    assert_eq!(simulator.elapsed(), Duration::from_secs(2));
    assert_reset_fenced(&simulator);
}

#[test]
fn voltage_loss_is_persistent_until_explicitly_restored() {
    let mut simulator = BenchSimulator::new(identity());
    simulator
        .add_fault(BenchFault::VoltageLoss {
            at: FaultPoint::new(BenchOperation::Write, 2),
        })
        .unwrap();

    assert!(plan().execute(&mut simulator, &mut |_| {}).is_err());
    assert!(!simulator.is_powered());
    assert!(matches!(
        ms45_core::FlashBackend::identify(&mut simulator),
        Err(FlashError::Backend(message)) if message.contains("voltage loss")
    ));
    simulator.restore_voltage();
    assert!(ms45_core::FlashBackend::identify(&mut simulator).is_ok());
    assert_reset_fenced(&simulator);
}

#[test]
fn rejected_security_access_stops_before_erase() {
    let mut simulator = BenchSimulator::new(identity());
    simulator
        .add_fault(BenchFault::SecurityAccessRejected { occurrence: 1 })
        .unwrap();

    assert!(matches!(
        plan().execute(&mut simulator, &mut |_| {}),
        Err(FlashError::SecurityDenied)
    ));
    assert_eq!(
        simulator.events().last().unwrap().outcome,
        BenchOutcome::SecurityRejected
    );
    assert!(!simulator
        .events()
        .iter()
        .any(|event| event.operation == BenchOperation::Erase));
}

#[test]
fn partial_erase_preserves_its_partial_memory_effect() {
    let mut simulator = BenchSimulator::new(identity());
    simulator.load(START, &[0; 10]);
    simulator
        .add_fault(BenchFault::PartialErase {
            occurrence: 1,
            bytes_erased: 3,
        })
        .unwrap();

    assert!(plan().execute(&mut simulator, &mut |_| {}).is_err());
    assert_eq!(
        simulator.snapshot(START, 10),
        [vec![0xff; 3], vec![0; 7]].concat()
    );
    assert_reset_fenced(&simulator);
}

#[test]
fn corrupted_readback_is_detected_before_the_next_write() {
    let mut simulator = BenchSimulator::new(identity());
    simulator
        .add_fault(BenchFault::CorruptedRead {
            occurrence: 2,
            byte_offset: 1,
        })
        .unwrap();

    assert!(matches!(
        plan().execute(&mut simulator, &mut |_| {}),
        Err(FlashError::ReadbackMismatch { address: 0x1004 })
    ));
    assert_eq!(
        simulator
            .events()
            .iter()
            .filter(|event| event.operation == BenchOperation::Write)
            .count(),
        2
    );
    assert_reset_fenced(&simulator);
}

#[test]
fn disconnect_at_a_selected_occurrence_is_reproducible() {
    let mut simulator = BenchSimulator::new(identity());
    simulator
        .add_fault(BenchFault::Disconnect {
            at: FaultPoint::new(BenchOperation::Read, 1),
        })
        .unwrap();

    assert!(matches!(
        plan().execute(&mut simulator, &mut |_| {}),
        Err(FlashError::Backend(message)) if message.contains("disconnected")
    ));
    assert_eq!(
        simulator.events().last().unwrap().outcome,
        BenchOutcome::Disconnected
    );
    assert_reset_fenced(&simulator);
}

#[test]
fn invalid_or_ambiguous_fault_schedules_are_rejected() {
    let mut simulator = BenchSimulator::new(identity());
    let fault = BenchFault::Disconnect {
        at: FaultPoint::new(BenchOperation::Read, 0),
    };
    assert!(simulator.add_fault(fault).is_err());
    simulator
        .add_fault(BenchFault::Disconnect {
            at: FaultPoint::new(BenchOperation::Read, 1),
        })
        .unwrap();
    assert!(simulator
        .add_fault(BenchFault::CorruptedRead {
            occurrence: 1,
            byte_offset: 0,
        })
        .is_err());
}

#[test]
fn cancellation_is_observed_only_after_verified_blocks() {
    let mut simulator = BenchSimulator::new(identity());
    let mut checkpoints = Vec::new();
    let failure = plan()
        .execute_cancellable(&mut simulator, &mut |_| {}, &mut |state| {
            checkpoints.push(state);
            state.completed_bytes >= 8
        })
        .unwrap_err();

    assert!(matches!(failure.error, FlashError::Cancelled));
    assert_eq!(failure.state.completed_bytes, 8);
    assert!(!failure.state.reset_permitted);
    assert_eq!(checkpoints[0].completed_bytes, 0);
    assert_eq!(checkpoints[1].completed_bytes, 4);
    assert_eq!(checkpoints[2].completed_bytes, 8);
    assert_eq!(
        simulator
            .events()
            .iter()
            .filter(|event| event.operation == BenchOperation::Write)
            .count(),
        2
    );
    assert_reset_fenced(&simulator);
}

#[test]
fn low_voltage_prevents_erase() {
    let mut simulator = BenchSimulator::new(identity());
    simulator.set_voltage_readings([13_800, 11_900, 13_800]);

    assert!(matches!(
        plan().execute(&mut simulator, &mut |_| {}),
        Err(FlashError::BatteryVoltageOutOfRange {
            measured_mv: 11_900,
            ..
        })
    ));
    assert!(!simulator
        .events()
        .iter()
        .any(|event| event.operation == BenchOperation::Erase));
    assert_eq!(
        simulator.events().last().unwrap().outcome,
        BenchOutcome::VoltageMeasured { millivolts: 11_900 }
    );
}

#[test]
fn acceptable_but_unstable_voltage_prevents_erase() {
    let mut simulator = BenchSimulator::new(identity());
    simulator.set_voltage_readings([12_500, 13_800, 12_500]);

    assert!(matches!(
        plan().execute(&mut simulator, &mut |_| {}),
        Err(FlashError::BatteryVoltageUnstable { .. })
    ));
    assert!(!simulator
        .events()
        .iter()
        .any(|event| event.operation == BenchOperation::Erase));
}

#[test]
fn voltage_dip_during_writes_stops_before_the_next_operation() {
    let mut simulator = BenchSimulator::new(identity());
    // Three stable pre-erase samples, write 1, read 1, then reject write 2.
    simulator.set_voltage_readings([13_800, 13_810, 13_790, 13_800, 13_800, 11_500]);

    let failure = plan()
        .execute_cancellable(&mut simulator, &mut |_| {}, &mut |_| false)
        .unwrap_err();
    assert!(matches!(
        failure.error,
        FlashError::BatteryVoltageOutOfRange {
            measured_mv: 11_500,
            ..
        }
    ));
    assert_eq!(failure.state.completed_bytes, 4);
    assert!(!failure.state.reset_permitted);
    assert_eq!(
        simulator
            .events()
            .iter()
            .filter(|event| event.operation == BenchOperation::Write)
            .count(),
        1
    );
    assert_reset_fenced(&simulator);
}
