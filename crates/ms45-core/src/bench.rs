//! Deterministic, stateful bench simulation for flash workflow tests.
use crate::flasher::{
    DmeIdentity, FlashBackend, FlashError, FlashProgress, MemoryRegion, SecurityLevel,
};
use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BenchOperation {
    Identify,
    VoltageRead,
    SecurityAccess,
    Erase,
    Write,
    Read,
    CheckSignature,
    Reset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultPoint {
    pub operation: BenchOperation,
    /// One-based invocation number for this operation.
    pub occurrence: usize,
}

impl FaultPoint {
    pub const fn new(operation: BenchOperation, occurrence: usize) -> Self {
        Self {
            operation,
            occurrence,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BenchFault {
    Timeout {
        at: FaultPoint,
        elapsed: Duration,
    },
    VoltageLoss {
        at: FaultPoint,
    },
    SecurityAccessRejected {
        occurrence: usize,
    },
    PartialErase {
        occurrence: usize,
        bytes_erased: usize,
    },
    CorruptedRead {
        occurrence: usize,
        byte_offset: usize,
    },
    Disconnect {
        at: FaultPoint,
    },
}

impl BenchFault {
    fn point(&self) -> FaultPoint {
        match self {
            Self::Timeout { at, .. } | Self::VoltageLoss { at } | Self::Disconnect { at } => *at,
            Self::SecurityAccessRejected { occurrence } => {
                FaultPoint::new(BenchOperation::SecurityAccess, *occurrence)
            }
            Self::PartialErase { occurrence, .. } => {
                FaultPoint::new(BenchOperation::Erase, *occurrence)
            }
            Self::CorruptedRead { occurrence, .. } => {
                FaultPoint::new(BenchOperation::Read, *occurrence)
            }
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BenchConfigurationError {
    #[error("fault occurrence must be at least one")]
    ZeroOccurrence,
    #[error("a fault is already scheduled at {operation:?} occurrence {occurrence}")]
    DuplicateFault {
        operation: BenchOperation,
        occurrence: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenchOutcome {
    Completed,
    VoltageMeasured { millivolts: u16 },
    TimedOut,
    VoltageLost,
    SecurityRejected,
    PartiallyErased { bytes: usize },
    CorruptedRead { byte_offset: usize },
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BenchEvent {
    pub operation: BenchOperation,
    pub occurrence: usize,
    pub outcome: BenchOutcome,
}

/// An in-memory flash backend whose faults are selected by operation and
/// one-based occurrence. It never sleeps or touches physical hardware.
#[derive(Debug, Clone)]
pub struct BenchSimulator {
    identity: DmeIdentity,
    memory: BTreeMap<u32, u8>,
    faults: Vec<BenchFault>,
    counts: BTreeMap<BenchOperation, usize>,
    events: Vec<BenchEvent>,
    elapsed: Duration,
    powered: bool,
    voltage_readings_mv: VecDeque<u16>,
    last_voltage_mv: u16,
}

impl BenchSimulator {
    pub fn new(identity: DmeIdentity) -> Self {
        Self {
            identity,
            memory: BTreeMap::new(),
            faults: Vec::new(),
            counts: BTreeMap::new(),
            events: Vec::new(),
            elapsed: Duration::ZERO,
            powered: true,
            voltage_readings_mv: VecDeque::new(),
            last_voltage_mv: 13_800,
        }
    }

    pub fn add_fault(&mut self, fault: BenchFault) -> Result<(), BenchConfigurationError> {
        let point = fault.point();
        if point.occurrence == 0 {
            return Err(BenchConfigurationError::ZeroOccurrence);
        }
        if self.faults.iter().any(|existing| existing.point() == point) {
            return Err(BenchConfigurationError::DuplicateFault {
                operation: point.operation,
                occurrence: point.occurrence,
            });
        }
        self.faults.push(fault);
        Ok(())
    }

    /// Seed memory without generating a simulated ECU operation.
    pub fn load(&mut self, start: u32, data: &[u8]) {
        for (offset, byte) in data.iter().copied().enumerate() {
            if let Some(address) = start.checked_add(offset as u32) {
                self.memory.insert(address, byte);
            }
        }
    }

    /// Inspect memory without consuming a fault or adding a trace event.
    pub fn snapshot(&self, start: u32, len: usize) -> Vec<u8> {
        (0..len)
            .map(|offset| {
                start
                    .checked_add(offset as u32)
                    .and_then(|address| self.memory.get(&address).copied())
                    .unwrap_or(0xff)
            })
            .collect()
    }

    pub fn events(&self) -> &[BenchEvent] {
        &self.events
    }

    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    pub fn is_powered(&self) -> bool {
        self.powered
    }

    /// Queue voltage samples. Once exhausted, the final sample is held.
    pub fn set_voltage_readings(&mut self, readings_mv: impl IntoIterator<Item = u16>) {
        self.voltage_readings_mv = readings_mv.into_iter().collect();
        if let Some(last) = self.voltage_readings_mv.back() {
            self.last_voltage_mv = *last;
        }
    }

    /// Simulate restoring bench voltage. Faults already triggered stay consumed.
    pub fn restore_voltage(&mut self) {
        self.powered = true;
    }

    fn begin(&mut self, operation: BenchOperation) -> (usize, Option<BenchFault>) {
        let occurrence = self.counts.entry(operation).or_default();
        *occurrence += 1;
        let occurrence = *occurrence;
        if !self.powered {
            self.events.push(BenchEvent {
                operation,
                occurrence,
                outcome: BenchOutcome::VoltageLost,
            });
            return (
                occurrence,
                Some(BenchFault::VoltageLoss {
                    at: FaultPoint::new(operation, occurrence),
                }),
            );
        }
        let position = self
            .faults
            .iter()
            .position(|fault| fault.point() == FaultPoint::new(operation, occurrence));
        (occurrence, position.map(|index| self.faults.remove(index)))
    }

    fn complete(&mut self, operation: BenchOperation, occurrence: usize, outcome: BenchOutcome) {
        self.events.push(BenchEvent {
            operation,
            occurrence,
            outcome,
        });
    }

    fn apply_common_fault(
        &mut self,
        operation: BenchOperation,
        occurrence: usize,
        fault: Option<&BenchFault>,
    ) -> Result<(), FlashError> {
        match fault {
            Some(BenchFault::Timeout { elapsed, .. }) => {
                self.elapsed += *elapsed;
                self.complete(operation, occurrence, BenchOutcome::TimedOut);
                Err(FlashError::Backend("simulated operation timed out".into()))
            }
            Some(BenchFault::VoltageLoss { .. }) => {
                self.powered = false;
                self.complete(operation, occurrence, BenchOutcome::VoltageLost);
                Err(FlashError::Backend("simulated bench voltage loss".into()))
            }
            Some(BenchFault::Disconnect { .. }) => {
                self.complete(operation, occurrence, BenchOutcome::Disconnected);
                Err(FlashError::Backend(
                    "simulated transport disconnected".into(),
                ))
            }
            _ => Ok(()),
        }
    }

    fn finish_simple(&mut self, operation: BenchOperation) -> Result<(), FlashError> {
        let (occurrence, fault) = self.begin(operation);
        self.apply_common_fault(operation, occurrence, fault.as_ref())?;
        self.complete(operation, occurrence, BenchOutcome::Completed);
        Ok(())
    }
}

impl FlashBackend for BenchSimulator {
    fn identify(&mut self) -> Result<DmeIdentity, FlashError> {
        self.finish_simple(BenchOperation::Identify)?;
        Ok(self.identity.clone())
    }

    fn battery_voltage_mv(&mut self) -> Result<u16, FlashError> {
        let operation = BenchOperation::VoltageRead;
        let (occurrence, fault) = self.begin(operation);
        self.apply_common_fault(operation, occurrence, fault.as_ref())?;
        let measured = if self.powered {
            self.voltage_readings_mv
                .pop_front()
                .unwrap_or(self.last_voltage_mv)
        } else {
            0
        };
        self.last_voltage_mv = measured;
        self.complete(
            operation,
            occurrence,
            BenchOutcome::VoltageMeasured {
                millivolts: measured,
            },
        );
        Ok(measured)
    }

    fn request_security_access(&mut self, _: SecurityLevel) -> Result<(), FlashError> {
        let operation = BenchOperation::SecurityAccess;
        let (occurrence, fault) = self.begin(operation);
        self.apply_common_fault(operation, occurrence, fault.as_ref())?;
        if matches!(fault, Some(BenchFault::SecurityAccessRejected { .. })) {
            self.complete(operation, occurrence, BenchOutcome::SecurityRejected);
            return Err(FlashError::SecurityDenied);
        }
        self.complete(operation, occurrence, BenchOutcome::Completed);
        Ok(())
    }

    fn read_memory(
        &mut self,
        _: MemoryRegion,
        start: u32,
        len: usize,
        progress: &mut dyn FnMut(FlashProgress),
    ) -> Result<Vec<u8>, FlashError> {
        let operation = BenchOperation::Read;
        let (occurrence, fault) = self.begin(operation);
        self.apply_common_fault(operation, occurrence, fault.as_ref())?;
        let mut data = self.snapshot(start, len);
        if let Some(BenchFault::CorruptedRead { byte_offset, .. }) = fault {
            let byte = data.get_mut(byte_offset).ok_or_else(|| {
                FlashError::Backend("simulated corrupted-read offset is out of range".into())
            })?;
            *byte ^= 1;
            self.complete(
                operation,
                occurrence,
                BenchOutcome::CorruptedRead { byte_offset },
            );
        } else {
            self.complete(operation, occurrence, BenchOutcome::Completed);
        }
        progress(FlashProgress {
            completed: len,
            total: len,
        });
        Ok(data)
    }

    fn erase(&mut self, start: u32, len: usize) -> Result<(), FlashError> {
        let operation = BenchOperation::Erase;
        let (occurrence, fault) = self.begin(operation);
        self.apply_common_fault(operation, occurrence, fault.as_ref())?;
        if let Some(BenchFault::PartialErase { bytes_erased, .. }) = fault {
            let affected = bytes_erased.min(len);
            self.load(start, &vec![0xff; affected]);
            self.complete(
                operation,
                occurrence,
                BenchOutcome::PartiallyErased { bytes: affected },
            );
            return Err(FlashError::Backend("simulated partial erase".into()));
        }
        self.load(start, &vec![0xff; len]);
        self.complete(operation, occurrence, BenchOutcome::Completed);
        Ok(())
    }

    fn write_block(
        &mut self,
        start: u32,
        data: &[u8],
        progress: &mut dyn FnMut(FlashProgress),
    ) -> Result<(), FlashError> {
        let operation = BenchOperation::Write;
        let (occurrence, fault) = self.begin(operation);
        self.apply_common_fault(operation, occurrence, fault.as_ref())?;
        self.load(start, data);
        self.complete(operation, occurrence, BenchOutcome::Completed);
        progress(FlashProgress {
            completed: data.len(),
            total: data.len(),
        });
        Ok(())
    }

    fn check_signature(&mut self, _: bool) -> Result<(), FlashError> {
        self.finish_simple(BenchOperation::CheckSignature)
    }

    fn reset(&mut self) -> Result<(), FlashError> {
        self.finish_simple(BenchOperation::Reset)
    }
}
