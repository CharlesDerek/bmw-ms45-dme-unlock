use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmeIdentity {
    pub vin: String,
    pub hardware_reference: String,
    pub software_reference: String,
    pub programming_status: String,
    pub diag_protocol: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadKind {
    Tune,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    Programming,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRegion {
    ExternalFlash,
    InternalMpc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlashProgress {
    pub completed: usize,
    pub total: usize,
}

/// The last boundary reached by a flash execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashPhase {
    Preflight,
    SecurityAccessGranted,
    Erasing,
    Writing,
    BetweenBlocks,
    CheckingSignature,
    SignatureVerified,
    Resetting,
}

/// A fail-closed snapshot of an interrupted or failed flash execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlashExecutionState {
    pub phase: FlashPhase,
    pub completed_bytes: usize,
    pub total_bytes: usize,
    /// Whether the plan has established that issuing reset is safe.
    ///
    /// This becomes false before the first erase is attempted and becomes true
    /// again only after the ECU accepts the signature check.
    pub reset_permitted: bool,
}

impl std::fmt::Display for FlashExecutionState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "phase={:?}, verified_bytes={}/{}, reset_permitted={}",
            self.phase, self.completed_bytes, self.total_bytes, self.reset_permitted
        )
    }
}

#[derive(Debug, Error)]
#[error("flash execution failed ({state}): {error}")]
pub struct FlashExecutionFailure {
    pub error: FlashError,
    pub state: FlashExecutionState,
}

#[derive(Debug, Error)]
pub enum FlashError {
    #[error("backend does not implement live DME access yet")]
    UnsupportedBackend,
    #[error("security access was denied")]
    SecurityDenied,
    #[error("backend operation failed: {0}")]
    Backend(String),
    #[error("unsafe flash plan: {0}")]
    InvalidPlan(String),
    #[error("connected DME identity does not match the approved flash plan: {0}")]
    IdentityMismatch(String),
    #[error("connected DME programming state {0} is not supported; expected normal operation (1)")]
    ProgrammingState(String),
    #[error("flash readback differs from approved payload at address {address:#x}")]
    ReadbackMismatch { address: u32 },
    #[error("flash execution was cancelled at a block boundary")]
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashSegment {
    pub region: MemoryRegion,
    pub start: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashPlan {
    expected_hardware_reference: String,
    expected_software_reference: Option<String>,
    expected_vin: Option<String>,
    segments: Vec<FlashSegment>,
    block_size: usize,
    program_signature: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashReceipt {
    pub identity: DmeIdentity,
    pub segments_written: usize,
    pub bytes_written: usize,
}

impl FlashPlan {
    pub fn new(
        expected_hardware_reference: impl Into<String>,
        expected_software_reference: Option<String>,
        segments: Vec<FlashSegment>,
        block_size: usize,
        program_signature: bool,
    ) -> Result<Self, FlashError> {
        let expected_hardware_reference = expected_hardware_reference.into();
        if expected_hardware_reference.trim().is_empty() {
            return Err(FlashError::InvalidPlan(
                "expected hardware reference is required".to_string(),
            ));
        }
        if !(1..=0x1000).contains(&block_size) {
            return Err(FlashError::InvalidPlan(
                "block size must be between 1 and 4096 bytes".to_string(),
            ));
        }
        if segments.is_empty() {
            return Err(FlashError::InvalidPlan(
                "at least one flash segment is required".to_string(),
            ));
        }

        for (index, segment) in segments.iter().enumerate() {
            if segment.data.is_empty() {
                return Err(FlashError::InvalidPlan(format!(
                    "segment {index} has no payload"
                )));
            }
            let segment_len = u32::try_from(segment.data.len()).map_err(|_| {
                FlashError::InvalidPlan(format!("segment {index} is larger than address space"))
            })?;
            let end = segment.start.checked_add(segment_len).ok_or_else(|| {
                FlashError::InvalidPlan(format!("segment {index} address range overflows"))
            })?;
            for (other_index, other) in segments.iter().enumerate().skip(index + 1) {
                if segment.region != other.region {
                    continue;
                }
                let other_len = u32::try_from(other.data.len()).map_err(|_| {
                    FlashError::InvalidPlan(format!(
                        "segment {other_index} is larger than address space"
                    ))
                })?;
                let other_end = other.start.checked_add(other_len).ok_or_else(|| {
                    FlashError::InvalidPlan(format!(
                        "segment {other_index} address range overflows"
                    ))
                })?;
                if segment.start < other_end && other.start < end {
                    return Err(FlashError::InvalidPlan(format!(
                        "segments {index} and {other_index} overlap"
                    )));
                }
            }
        }

        Ok(Self {
            expected_hardware_reference,
            expected_software_reference,
            expected_vin: None,
            segments,
            block_size,
            program_signature,
        })
    }

    pub fn with_expected_vin(mut self, vin: impl Into<String>) -> Result<Self, FlashError> {
        let vin = vin.into();
        if vin.trim().is_empty() {
            return Err(FlashError::InvalidPlan(
                "expected VIN must not be blank".to_string(),
            ));
        }
        self.expected_vin = Some(vin);
        Ok(self)
    }

    pub fn execute(
        &self,
        backend: &mut dyn FlashBackend,
        progress: &mut dyn FnMut(FlashProgress),
    ) -> Result<FlashReceipt, FlashError> {
        self.execute_cancellable(backend, progress, &mut |_| false)
            .map_err(|failure| failure.error)
    }

    /// Execute a plan while allowing cancellation at preflight and between
    /// fully written, read-back-verified blocks.
    ///
    /// `cancel` is never called during an ECU operation. A true result stops
    /// without checking the signature or resetting and returns the exact
    /// fail-closed state so the caller can report whether reset is permitted.
    pub fn execute_cancellable(
        &self,
        backend: &mut dyn FlashBackend,
        progress: &mut dyn FnMut(FlashProgress),
        cancel: &mut dyn FnMut(FlashExecutionState) -> bool,
    ) -> Result<FlashReceipt, FlashExecutionFailure> {
        let total = self.segments.iter().map(|segment| segment.data.len()).sum();
        let mut state = FlashExecutionState {
            phase: FlashPhase::Preflight,
            completed_bytes: 0,
            total_bytes: total,
            reset_permitted: true,
        };
        let fail = |error, state| FlashExecutionFailure { error, state };

        let identity = backend.identify().map_err(|error| fail(error, state))?;
        if identity.programming_status != "1" {
            return Err(fail(
                FlashError::ProgrammingState(identity.programming_status.clone()),
                state,
            ));
        }
        if identity.hardware_reference != self.expected_hardware_reference {
            return Err(fail(
                FlashError::IdentityMismatch(format!(
                    "hardware reference expected {}, found {}",
                    self.expected_hardware_reference, identity.hardware_reference
                )),
                state,
            ));
        }
        if let Some(expected) = &self.expected_software_reference {
            if identity.software_reference != *expected {
                return Err(fail(
                    FlashError::IdentityMismatch(format!(
                        "software reference expected {expected}, found {}",
                        identity.software_reference
                    )),
                    state,
                ));
            }
        }
        if let Some(expected) = &self.expected_vin {
            if identity.vin != *expected {
                return Err(fail(
                    FlashError::IdentityMismatch("VIN differs from approved plan".to_string()),
                    state,
                ));
            }
        }

        if cancel(state) {
            return Err(fail(FlashError::Cancelled, state));
        }
        backend
            .request_security_access(SecurityLevel::Programming)
            .map_err(|error| fail(error, state))?;
        state.phase = FlashPhase::SecurityAccessGranted;
        let mut completed = 0usize;
        for segment in &self.segments {
            state.phase = FlashPhase::Erasing;
            state.reset_permitted = false;
            backend
                .erase(segment.start, segment.data.len())
                .map_err(|error| fail(error, state))?;
            for (block_index, block) in segment.data.chunks(self.block_size).enumerate() {
                state.phase = FlashPhase::Writing;
                let offset = block_index.checked_mul(self.block_size).ok_or_else(|| {
                    fail(
                        FlashError::InvalidPlan("block offset overflowed".to_string()),
                        state,
                    )
                })?;
                let offset = u32::try_from(offset).map_err(|_| {
                    fail(
                        FlashError::InvalidPlan("block offset exceeded address space".to_string()),
                        state,
                    )
                })?;
                let address = segment.start.checked_add(offset).ok_or_else(|| {
                    fail(
                        FlashError::InvalidPlan("block address overflowed".to_string()),
                        state,
                    )
                })?;
                backend
                    .write_block(address, block, &mut |_| {})
                    .map_err(|error| fail(error, state))?;
                let readback = backend
                    .read_memory(segment.region, address, block.len(), &mut |_| {})
                    .map_err(|error| fail(error, state))?;
                if readback != block {
                    return Err(fail(FlashError::ReadbackMismatch { address }, state));
                }
                completed += block.len();
                state.phase = FlashPhase::BetweenBlocks;
                state.completed_bytes = completed;
                progress(FlashProgress { completed, total });
                if cancel(state) {
                    return Err(fail(FlashError::Cancelled, state));
                }
            }
        }
        state.phase = FlashPhase::CheckingSignature;
        backend
            .check_signature(self.program_signature)
            .map_err(|error| fail(error, state))?;
        state.phase = FlashPhase::SignatureVerified;
        state.reset_permitted = true;
        state.phase = FlashPhase::Resetting;
        backend.reset().map_err(|error| fail(error, state))?;

        Ok(FlashReceipt {
            identity,
            segments_written: self.segments.len(),
            bytes_written: total,
        })
    }
}

pub trait FlashBackend {
    fn identify(&mut self) -> Result<DmeIdentity, FlashError>;
    fn request_security_access(&mut self, level: SecurityLevel) -> Result<(), FlashError>;
    fn read_memory(
        &mut self,
        region: MemoryRegion,
        start: u32,
        len: usize,
        progress: &mut dyn FnMut(FlashProgress),
    ) -> Result<Vec<u8>, FlashError>;
    fn erase(&mut self, start: u32, len: usize) -> Result<(), FlashError>;
    fn write_block(
        &mut self,
        start: u32,
        data: &[u8],
        progress: &mut dyn FnMut(FlashProgress),
    ) -> Result<(), FlashError>;
    fn check_signature(&mut self, program: bool) -> Result<(), FlashError>;
    fn reset(&mut self) -> Result<(), FlashError>;
}

#[derive(Debug, Default)]
pub struct UnsupportedLiveBackend;

impl FlashBackend for UnsupportedLiveBackend {
    fn identify(&mut self) -> Result<DmeIdentity, FlashError> {
        Err(FlashError::UnsupportedBackend)
    }

    fn request_security_access(&mut self, _level: SecurityLevel) -> Result<(), FlashError> {
        Err(FlashError::UnsupportedBackend)
    }

    fn read_memory(
        &mut self,
        _region: MemoryRegion,
        _start: u32,
        _len: usize,
        _progress: &mut dyn FnMut(FlashProgress),
    ) -> Result<Vec<u8>, FlashError> {
        Err(FlashError::UnsupportedBackend)
    }

    fn erase(&mut self, _start: u32, _len: usize) -> Result<(), FlashError> {
        Err(FlashError::UnsupportedBackend)
    }

    fn write_block(
        &mut self,
        _start: u32,
        _data: &[u8],
        _progress: &mut dyn FnMut(FlashProgress),
    ) -> Result<(), FlashError> {
        Err(FlashError::UnsupportedBackend)
    }

    fn check_signature(&mut self, _program: bool) -> Result<(), FlashError> {
        Err(FlashError::UnsupportedBackend)
    }

    fn reset(&mut self) -> Result<(), FlashError> {
        Err(FlashError::UnsupportedBackend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct RecordingBackend {
        operations: Vec<String>,
        fail_write_at: Option<u32>,
        corrupt_read_at: Option<u32>,
        programming_status: Option<String>,
        memory: BTreeMap<u32, u8>,
    }

    impl FlashBackend for RecordingBackend {
        fn identify(&mut self) -> Result<DmeIdentity, FlashError> {
            self.operations.push("identify".into());
            Ok(DmeIdentity {
                vin: "TESTVIN".into(),
                hardware_reference: "HW-45".into(),
                software_reference: "SW-1".into(),
                programming_status: self
                    .programming_status
                    .clone()
                    .unwrap_or_else(|| "1".into()),
                diag_protocol: "test".into(),
            })
        }
        fn request_security_access(&mut self, _: SecurityLevel) -> Result<(), FlashError> {
            self.operations.push("security".into());
            Ok(())
        }
        fn read_memory(
            &mut self,
            _: MemoryRegion,
            start: u32,
            len: usize,
            _: &mut dyn FnMut(FlashProgress),
        ) -> Result<Vec<u8>, FlashError> {
            self.operations.push(format!("read:{start:x}:{len}"));
            let mut data = (0..len)
                .map(|offset| self.memory[&(start + offset as u32)])
                .collect::<Vec<_>>();
            if self.corrupt_read_at == Some(start) {
                data[0] ^= 1;
            }
            Ok(data)
        }
        fn erase(&mut self, start: u32, len: usize) -> Result<(), FlashError> {
            self.operations.push(format!("erase:{start:x}:{len}"));
            Ok(())
        }
        fn write_block(
            &mut self,
            start: u32,
            data: &[u8],
            _: &mut dyn FnMut(FlashProgress),
        ) -> Result<(), FlashError> {
            self.operations
                .push(format!("write:{start:x}:{}", data.len()));
            if self.fail_write_at == Some(start) {
                return Err(FlashError::Backend("injected write failure".into()));
            }
            for (offset, byte) in data.iter().enumerate() {
                self.memory.insert(start + offset as u32, *byte);
            }
            Ok(())
        }
        fn check_signature(&mut self, program: bool) -> Result<(), FlashError> {
            self.operations.push(format!("signature:{program}"));
            Ok(())
        }
        fn reset(&mut self) -> Result<(), FlashError> {
            self.operations.push("reset".into());
            Ok(())
        }
    }

    fn plan() -> FlashPlan {
        FlashPlan::new(
            "HW-45",
            Some("SW-1".into()),
            vec![FlashSegment {
                region: MemoryRegion::ExternalFlash,
                start: 0x1000,
                data: vec![1; 10],
            }],
            4,
            false,
        )
        .unwrap()
    }

    #[test]
    fn executes_validated_plan_in_fail_safe_order() {
        let mut backend = RecordingBackend::default();
        let mut progress = Vec::new();
        let receipt = plan()
            .execute(&mut backend, &mut |value| progress.push(value))
            .unwrap();
        assert_eq!(receipt.bytes_written, 10);
        assert_eq!(
            progress.last(),
            Some(&FlashProgress {
                completed: 10,
                total: 10
            })
        );
        assert_eq!(
            backend.operations,
            vec![
                "identify",
                "security",
                "erase:1000:10",
                "write:1000:4",
                "read:1000:4",
                "write:1004:4",
                "read:1004:4",
                "write:1008:2",
                "read:1008:2",
                "signature:false",
                "reset"
            ]
        );
    }

    #[test]
    fn rejects_overlap_before_contacting_backend() {
        let error = FlashPlan::new(
            "HW",
            None,
            vec![
                FlashSegment {
                    region: MemoryRegion::ExternalFlash,
                    start: 10,
                    data: vec![0; 5],
                },
                FlashSegment {
                    region: MemoryRegion::ExternalFlash,
                    start: 14,
                    data: vec![0; 2],
                },
            ],
            4,
            false,
        )
        .unwrap_err();
        assert!(matches!(error, FlashError::InvalidPlan(_)));
    }

    #[test]
    fn identity_mismatch_prevents_unlock_and_erase() {
        let mut backend = RecordingBackend::default();
        let mismatched = FlashPlan::new(
            "OTHER",
            None,
            vec![FlashSegment {
                region: MemoryRegion::ExternalFlash,
                start: 0,
                data: vec![1],
            }],
            1,
            false,
        )
        .unwrap();
        assert!(matches!(
            mismatched.execute(&mut backend, &mut |_| {}),
            Err(FlashError::IdentityMismatch(_))
        ));
        assert_eq!(backend.operations, vec!["identify"]);
    }

    #[test]
    fn unexpected_programming_state_prevents_unlock_and_erase() {
        let mut backend = RecordingBackend {
            programming_status: Some("7".into()),
            ..Default::default()
        };
        assert!(matches!(
            plan().execute(&mut backend, &mut |_| {}),
            Err(FlashError::ProgrammingState(state)) if state == "7"
        ));
        assert_eq!(backend.operations, vec!["identify"]);
    }

    #[test]
    fn write_failure_never_checks_signature_or_resets() {
        let mut backend = RecordingBackend {
            fail_write_at: Some(0x1004),
            ..Default::default()
        };
        assert!(plan().execute(&mut backend, &mut |_| {}).is_err());
        assert!(!backend
            .operations
            .iter()
            .any(|operation| operation.starts_with("signature") || operation == "reset"));
    }

    #[test]
    fn readback_mismatch_stops_before_next_write_and_reset() {
        let mut backend = RecordingBackend {
            corrupt_read_at: Some(0x1004),
            ..Default::default()
        };
        assert!(matches!(
            plan().execute(&mut backend, &mut |_| {}),
            Err(FlashError::ReadbackMismatch { address: 0x1004 })
        ));
        assert!(!backend
            .operations
            .iter()
            .any(|operation| operation == "write:1008:2" || operation == "reset"));
    }

    #[test]
    fn vin_pin_stops_before_security_access() {
        let mut backend = RecordingBackend::default();
        let pinned = plan().with_expected_vin("DIFFERENTVIN").unwrap();
        assert!(matches!(
            pinned.execute(&mut backend, &mut |_| {}),
            Err(FlashError::IdentityMismatch(_))
        ));
        assert_eq!(backend.operations, vec!["identify"]);
    }

    #[test]
    fn cancellation_before_security_leaves_reset_permitted() {
        let mut backend = RecordingBackend::default();
        let failure = plan()
            .execute_cancellable(&mut backend, &mut |_| {}, &mut |_| true)
            .unwrap_err();

        assert!(matches!(failure.error, FlashError::Cancelled));
        assert_eq!(failure.state.phase, FlashPhase::Preflight);
        assert_eq!(failure.state.completed_bytes, 0);
        assert!(failure.state.reset_permitted);
        assert_eq!(backend.operations, vec!["identify"]);
    }

    #[test]
    fn cancellation_after_verified_block_is_fail_closed_and_stops_cleanly() {
        let mut backend = RecordingBackend::default();
        let failure = plan()
            .execute_cancellable(&mut backend, &mut |_| {}, &mut |state| {
                state.completed_bytes == 4
            })
            .unwrap_err();

        assert!(matches!(failure.error, FlashError::Cancelled));
        assert_eq!(failure.state.phase, FlashPhase::BetweenBlocks);
        assert_eq!(failure.state.completed_bytes, 4);
        assert_eq!(failure.state.total_bytes, 10);
        assert!(!failure.state.reset_permitted);
        assert!(failure.to_string().contains("reset_permitted=false"));
        assert_eq!(
            backend.operations,
            vec![
                "identify",
                "security",
                "erase:1000:10",
                "write:1000:4",
                "read:1000:4"
            ]
        );
    }
}
