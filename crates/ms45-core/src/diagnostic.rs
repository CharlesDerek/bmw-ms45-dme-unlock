//! Diagnostic-job boundary and MS45R1 protocol framing.
use crate::flasher::{MemoryRegion, SecurityLevel};
use crate::transport::{EcuTransport, TransportError};
use rand::RngCore;
use thiserror::Error;

const MAGIC: &[u8; 6] = b"MS45R1";
pub const MAX_JOB_PAYLOAD: usize = 4096;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DiagnosticError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("diagnostic response was malformed or replayed")]
    Protocol,
    #[error("diagnostic address was rejected")]
    Range,
    #[error("diagnostic job was rejected")]
    Rejected,
}

/// ECU jobs after protocol framing, but before model-specific safety checks.
/// Ediabas adapters implement this directly; native protocols compose it with
/// an [`EcuTransport`].
pub trait DiagnosticJobs {
    fn identify(&mut self) -> Result<Vec<u8>, DiagnosticError>;
    /// Read identity and status metadata without reading memory or changing ECU state.
    fn probe(&mut self) -> Result<Vec<u8>, DiagnosticError> {
        Err(DiagnosticError::Rejected)
    }
    fn read_memory(
        &mut self,
        region: MemoryRegion,
        start: u32,
        len: usize,
    ) -> Result<Vec<u8>, DiagnosticError>;
    /// Read the DME supply voltage in integer millivolts.
    fn battery_voltage_mv(&mut self) -> Result<u16, DiagnosticError> {
        Err(DiagnosticError::Rejected)
    }
    fn request_security_access(&mut self, _level: SecurityLevel) -> Result<(), DiagnosticError> {
        Err(DiagnosticError::Rejected)
    }
    fn erase(&mut self, _start: u32, _len: usize) -> Result<(), DiagnosticError> {
        Err(DiagnosticError::Rejected)
    }
    fn write_memory(&mut self, _start: u32, _data: &[u8]) -> Result<(), DiagnosticError> {
        Err(DiagnosticError::Rejected)
    }
    fn check_signature(&mut self, _program: bool) -> Result<(), DiagnosticError> {
        Err(DiagnosticError::Rejected)
    }
    fn reset(&mut self) -> Result<(), DiagnosticError> {
        Err(DiagnosticError::Rejected)
    }
}

pub struct Ms45R1Jobs<T> {
    transport: T,
}

impl<T> Ms45R1Jobs<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
    pub fn into_inner(self) -> T {
        self.transport
    }
}

impl<T: EcuTransport> Ms45R1Jobs<T> {
    fn exchange(
        &mut self,
        op: u8,
        region: u8,
        start: u32,
        len: u16,
    ) -> Result<Vec<u8>, DiagnosticError> {
        let nonce = rand::thread_rng().next_u64();
        let mut request = Vec::with_capacity(22);
        request.extend_from_slice(MAGIC);
        request.extend_from_slice(&nonce.to_be_bytes());
        request.push(op);
        request.push(region);
        request.extend_from_slice(&start.to_be_bytes());
        request.extend_from_slice(&len.to_be_bytes());
        self.transport.send(&request)?;
        let mut header = [0; 17];
        self.transport.receive_exact(&mut header)?;
        if &header[..6] != MAGIC || header[6..14] != nonce.to_be_bytes() {
            return Err(DiagnosticError::Protocol);
        }
        let size = u16::from_be_bytes([header[15], header[16]]) as usize;
        if size > MAX_JOB_PAYLOAD {
            return Err(DiagnosticError::Protocol);
        }
        let mut payload = vec![0; size];
        self.transport.receive_exact(&mut payload)?;
        match header[14] {
            0 => Ok(payload),
            1 => Err(DiagnosticError::Range),
            2 => Err(DiagnosticError::Rejected),
            _ => Err(DiagnosticError::Protocol),
        }
    }
}

impl<T: EcuTransport> DiagnosticJobs for Ms45R1Jobs<T> {
    fn identify(&mut self) -> Result<Vec<u8>, DiagnosticError> {
        self.exchange(1, 0, 0, 0)
    }

    fn probe(&mut self) -> Result<Vec<u8>, DiagnosticError> {
        self.exchange(3, 0, 0, 0)
    }

    fn read_memory(
        &mut self,
        region: MemoryRegion,
        start: u32,
        len: usize,
    ) -> Result<Vec<u8>, DiagnosticError> {
        let region = match region {
            MemoryRegion::ExternalFlash => 1,
            MemoryRegion::InternalMpc => 2,
        };
        self.exchange(
            2,
            region,
            start,
            u16::try_from(len).map_err(|_| DiagnosticError::Range)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::SimulatedTransport;
    use proptest::prelude::*;

    #[derive(Default)]
    struct StaleResponseTransport {
        request: Vec<u8>,
    }

    impl EcuTransport for StaleResponseTransport {
        fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
            self.request = bytes.to_vec();
            Ok(())
        }

        fn receive_exact(&mut self, bytes: &mut [u8]) -> Result<(), TransportError> {
            assert_eq!(bytes.len(), 17);
            bytes[..6].copy_from_slice(MAGIC);
            bytes[6..14].copy_from_slice(&self.request[6..14]);
            bytes[6] ^= 1;
            Ok(())
        }
    }

    #[test]
    fn simulated_transport_exercises_framing_and_nonce_validation() {
        let mut jobs = Ms45R1Jobs::new(StaleResponseTransport::default());
        assert_eq!(jobs.identify(), Err(DiagnosticError::Protocol));
        assert_eq!(jobs.into_inner().request.len(), 22);

        let mut simulation = SimulatedTransport::new(Vec::new());
        simulation.send(b"request").unwrap();
        assert_eq!(simulation.sent(), b"request");
        assert_eq!(
            simulation.receive_exact(&mut [0]),
            Err(TransportError::Disconnected)
        );
    }

    #[derive(Default)]
    struct EchoNonceTransport {
        request: Vec<u8>,
        response: std::collections::VecDeque<u8>,
        status: u8,
        payload: Vec<u8>,
    }

    impl EchoNonceTransport {
        fn new(status: u8, payload: Vec<u8>) -> Self {
            Self {
                status,
                payload,
                ..Self::default()
            }
        }
    }

    impl EcuTransport for EchoNonceTransport {
        fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
            self.request = bytes.to_vec();
            let mut response = Vec::new();
            response.extend_from_slice(MAGIC);
            response.extend_from_slice(&bytes[6..14]);
            response.push(self.status);
            response.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
            response.extend_from_slice(&self.payload);
            self.response = response.into();
            Ok(())
        }

        fn receive_exact(&mut self, bytes: &mut [u8]) -> Result<(), TransportError> {
            if self.response.len() < bytes.len() {
                return Err(TransportError::Disconnected);
            }
            for byte in bytes {
                *byte = self.response.pop_front().unwrap();
            }
            Ok(())
        }
    }

    proptest! {
        #[test]
        fn valid_frames_round_trip_arbitrary_payloads(payload in proptest::collection::vec(any::<u8>(), 0..=MAX_JOB_PAYLOAD)) {
            let mut jobs = Ms45R1Jobs::new(EchoNonceTransport::new(0, payload.clone()));
            prop_assert_eq!(jobs.identify().unwrap(), payload);
            let request = jobs.into_inner().request;
            prop_assert_eq!(&request[..6], MAGIC);
            prop_assert_eq!(request.len(), 22);
        }

        #[test]
        fn arbitrary_response_headers_fail_closed(mut header in proptest::array::uniform17(any::<u8>())) {
            // Force a magic mismatch while fuzzing every other header byte.
            header[0] = !MAGIC[0];
            let mut jobs = Ms45R1Jobs::new(SimulatedTransport::new(header.to_vec()));
            prop_assert!(jobs.identify().is_err());
        }

        #[test]
        fn protocol_status_mapping_is_total(status: u8) {
            let mut jobs = Ms45R1Jobs::new(EchoNonceTransport::new(status, Vec::new()));
            let result = jobs.identify();
            match status {
                0 => prop_assert_eq!(result, Ok(Vec::new())),
                1 => prop_assert_eq!(result, Err(DiagnosticError::Range)),
                2 => prop_assert_eq!(result, Err(DiagnosticError::Rejected)),
                _ => prop_assert_eq!(result, Err(DiagnosticError::Protocol)),
            }
        }
    }
}
