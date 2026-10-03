//! Model-specific ECU operations and validation shared by all job backends.
use crate::diagnostic::{DiagnosticError, DiagnosticJobs, MAX_JOB_PAYLOAD};
use crate::flasher::{
    DmeIdentity, FlashBackend, FlashError, FlashProgress, MemoryRegion, SecurityLevel,
};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EcuError {
    #[error(transparent)]
    Diagnostic(#[from] DiagnosticError),
    #[error("ECU identity or variant rejected")]
    Identity,
    #[error("ECU response was malformed")]
    Malformed,
    #[error("address range rejected")]
    Range,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcuIdentity {
    pub variant: String,
    pub hardware_reference: String,
    pub software_reference: String,
    pub vin: String,
}

pub struct EcuOperations<J> {
    jobs: J,
}

impl<J> EcuOperations<J> {
    pub fn new(jobs: J) -> Self {
        Self { jobs }
    }
    pub fn into_inner(self) -> J {
        self.jobs
    }
}

impl<J: DiagnosticJobs> EcuOperations<J> {
    pub fn identify(&mut self) -> Result<EcuIdentity, EcuError> {
        let bytes = self.jobs.identify()?;
        let text = std::str::from_utf8(&bytes).map_err(|_| EcuError::Malformed)?;
        let fields = text.split('|').collect::<Vec<_>>();
        if fields.len() != 4
            || fields.iter().any(|field| {
                field.is_empty()
                    || field.len() > 64
                    || !field
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
            })
        {
            return Err(EcuError::Malformed);
        }
        if !matches!(fields[0], "MS45.0" | "MS45.1") {
            return Err(EcuError::Identity);
        }
        Ok(EcuIdentity {
            variant: fields[0].into(),
            hardware_reference: fields[1].into(),
            software_reference: fields[2].into(),
            vin: fields[3].into(),
        })
    }

    pub fn read(
        &mut self,
        region: MemoryRegion,
        start: u32,
        len: usize,
    ) -> Result<Vec<u8>, EcuError> {
        let limit = match region {
            MemoryRegion::ExternalFlash => crate::EXTERNAL_FLASH_LEN,
            MemoryRegion::InternalMpc => crate::MPC_FLASH_LEN,
        };
        if len == 0
            || len > MAX_JOB_PAYLOAD
            || (start as usize)
                .checked_add(len)
                .is_none_or(|end| end > limit)
        {
            return Err(EcuError::Range);
        }
        let data = self.jobs.read_memory(region, start, len)?;
        if data.len() != len {
            return Err(EcuError::Malformed);
        }
        Ok(data)
    }
}

impl<J: DiagnosticJobs> FlashBackend for EcuOperations<J> {
    fn identify(&mut self) -> Result<DmeIdentity, FlashError> {
        let identity = EcuOperations::identify(self).map_err(flash_error)?;
        Ok(DmeIdentity {
            vin: identity.vin,
            hardware_reference: identity.hardware_reference,
            software_reference: identity.software_reference,
            programming_status: "reported-by-diagnostic-jobs".into(),
            diag_protocol: identity.variant,
        })
    }

    fn request_security_access(&mut self, level: SecurityLevel) -> Result<(), FlashError> {
        self.jobs
            .request_security_access(level)
            .map_err(flash_error)
    }

    fn read_memory(
        &mut self,
        region: MemoryRegion,
        start: u32,
        len: usize,
        progress: &mut dyn FnMut(FlashProgress),
    ) -> Result<Vec<u8>, FlashError> {
        let data = self.read(region, start, len).map_err(flash_error)?;
        progress(FlashProgress {
            completed: data.len(),
            total: len,
        });
        Ok(data)
    }

    fn erase(&mut self, start: u32, len: usize) -> Result<(), FlashError> {
        validate_address_len(start, len).map_err(flash_error)?;
        self.jobs.erase(start, len).map_err(flash_error)
    }

    fn write_block(
        &mut self,
        start: u32,
        data: &[u8],
        progress: &mut dyn FnMut(FlashProgress),
    ) -> Result<(), FlashError> {
        validate_address_len(start, data.len()).map_err(flash_error)?;
        if data.len() > MAX_JOB_PAYLOAD {
            return Err(FlashError::InvalidPlan(
                "write block exceeds diagnostic job limit".into(),
            ));
        }
        self.jobs.write_memory(start, data).map_err(flash_error)?;
        progress(FlashProgress {
            completed: data.len(),
            total: data.len(),
        });
        Ok(())
    }

    fn check_signature(&mut self, program: bool) -> Result<(), FlashError> {
        self.jobs.check_signature(program).map_err(flash_error)
    }

    fn reset(&mut self) -> Result<(), FlashError> {
        self.jobs.reset().map_err(flash_error)
    }
}

fn validate_address_len(start: u32, len: usize) -> Result<(), EcuError> {
    if len == 0
        || u32::try_from(len)
            .ok()
            .and_then(|value| start.checked_add(value))
            .is_none()
    {
        return Err(EcuError::Range);
    }
    Ok(())
}

fn flash_error(error: impl std::fmt::Display) -> FlashError {
    FlashError::Backend(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Jobs {
        identity: Vec<u8>,
        reads: VecDeque<Vec<u8>>,
        calls: usize,
    }
    impl DiagnosticJobs for Jobs {
        fn identify(&mut self) -> Result<Vec<u8>, DiagnosticError> {
            self.calls += 1;
            Ok(self.identity.clone())
        }
        fn read_memory(
            &mut self,
            _: MemoryRegion,
            _: u32,
            _: usize,
        ) -> Result<Vec<u8>, DiagnosticError> {
            self.calls += 1;
            Ok(self.reads.pop_front().unwrap())
        }
    }

    #[test]
    fn shared_operations_validate_jobs_and_ranges() {
        let jobs = Jobs {
            identity: b"MS45.1|HW1|SW1|TESTVIN".to_vec(),
            reads: [vec![0x45; 4]].into(),
            calls: 0,
        };
        let mut ecu = EcuOperations::new(jobs);
        assert_eq!(ecu.identify().unwrap().variant, "MS45.1");
        assert_eq!(
            ecu.read(MemoryRegion::ExternalFlash, 0, 4).unwrap(),
            vec![0x45; 4]
        );
        assert_eq!(
            ecu.read(MemoryRegion::ExternalFlash, 0, 0),
            Err(EcuError::Range)
        );
        assert_eq!(ecu.into_inner().calls, 2);
    }

    #[test]
    fn shared_operations_reject_bad_identity_and_short_result() {
        let jobs = Jobs {
            identity: b"MS44|HW1|SW1|TESTVIN".to_vec(),
            reads: VecDeque::new(),
            calls: 0,
        };
        assert_eq!(EcuOperations::new(jobs).identify(), Err(EcuError::Identity));
        let jobs = Jobs {
            identity: Vec::new(),
            reads: [vec![0; 3]].into(),
            calls: 0,
        };
        assert_eq!(
            EcuOperations::new(jobs).read(MemoryRegion::ExternalFlash, 0, 4),
            Err(EcuError::Malformed)
        );
    }

    #[test]
    fn read_only_jobs_fail_closed_for_flash_operations() {
        let jobs = Jobs {
            identity: Vec::new(),
            reads: VecDeque::new(),
            calls: 0,
        };
        let mut ecu = EcuOperations::new(jobs);
        assert!(matches!(
            FlashBackend::request_security_access(&mut ecu, SecurityLevel::Programming),
            Err(FlashError::Backend(message)) if message.contains("rejected")
        ));
        assert!(matches!(
            FlashBackend::write_block(&mut ecu, 0, &vec![0; MAX_JOB_PAYLOAD + 1], &mut |_| {}),
            Err(FlashError::InvalidPlan(_))
        ));
    }
}
