//! Compatibility facade for the read-only MS45R1 TCP adapter.
use crate::diagnostic::{DiagnosticError, Ms45R1Jobs};
use crate::ecu::{EcuError, EcuOperations};
use crate::flasher::MemoryRegion;
use crate::transport::TcpTransport;
use std::net::SocketAddr;
use std::time::Duration;

pub use crate::diagnostic::MAX_JOB_PAYLOAD as MAX_READ;
pub use crate::ecu::EcuIdentity as Identity;
pub use crate::ecu::HardwareProbe;
pub type ReadError = EcuError;

pub struct ReadOnlyAdapter {
    ecu: EcuOperations<Ms45R1Jobs<TcpTransport>>,
}

impl ReadOnlyAdapter {
    pub fn connect(address: SocketAddr, timeout: Duration) -> Result<Self, ReadError> {
        let transport = TcpTransport::connect(address, timeout)
            .map_err(DiagnosticError::from)
            .map_err(EcuError::from)?;
        Ok(Self {
            ecu: EcuOperations::new(Ms45R1Jobs::new(transport)),
        })
    }

    pub fn identify(&mut self) -> Result<Identity, ReadError> {
        self.ecu.identify()
    }

    pub fn probe(&mut self) -> Result<HardwareProbe, ReadError> {
        self.ecu.probe()
    }

    pub fn read(
        &mut self,
        region: MemoryRegion,
        start: u32,
        len: usize,
    ) -> Result<Vec<u8>, ReadError> {
        self.ecu.read(region, start, len)
    }
}
