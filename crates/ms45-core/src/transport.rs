//! Byte transport boundary for ECU protocols.
#[cfg(feature = "live-read")]
use std::io::{Read, Write};
#[cfg(feature = "live-read")]
use std::net::{SocketAddr, TcpStream};
#[cfg(feature = "live-read")]
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    #[error("transport timed out")]
    Timeout,
    #[error("transport disconnected")]
    Disconnected,
    #[error("transport I/O failed")]
    Io,
}

/// An ordered, reliable byte stream used by a diagnostic protocol framer.
pub trait EcuTransport {
    fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError>;
    fn receive_exact(&mut self, bytes: &mut [u8]) -> Result<(), TransportError>;
}

#[cfg(feature = "live-read")]
pub struct TcpTransport {
    stream: TcpStream,
}

#[cfg(feature = "live-read")]
impl TcpTransport {
    pub fn connect(address: SocketAddr, timeout: Duration) -> Result<Self, TransportError> {
        let stream = TcpStream::connect_timeout(&address, timeout).map_err(classify_io)?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(classify_io)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(classify_io)?;
        Ok(Self { stream })
    }
}

#[cfg(feature = "live-read")]
impl EcuTransport for TcpTransport {
    fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.stream.write_all(bytes).map_err(classify_io)
    }

    fn receive_exact(&mut self, bytes: &mut [u8]) -> Result<(), TransportError> {
        self.stream.read_exact(bytes).map_err(classify_io)
    }
}

#[cfg(feature = "live-read")]
fn classify_io(error: std::io::Error) -> TransportError {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => TransportError::Timeout,
        std::io::ErrorKind::UnexpectedEof
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::BrokenPipe => TransportError::Disconnected,
        _ => TransportError::Io,
    }
}

/// Deterministic in-memory byte stream for protocol tests.
#[derive(Debug, Default)]
pub struct SimulatedTransport {
    responses: std::collections::VecDeque<u8>,
    sent: Vec<u8>,
}

impl SimulatedTransport {
    pub fn new(responses: impl Into<Vec<u8>>) -> Self {
        Self {
            responses: responses.into().into(),
            sent: Vec::new(),
        }
    }

    pub fn sent(&self) -> &[u8] {
        &self.sent
    }
}

impl EcuTransport for SimulatedTransport {
    fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.sent.extend_from_slice(bytes);
        Ok(())
    }

    fn receive_exact(&mut self, bytes: &mut [u8]) -> Result<(), TransportError> {
        if self.responses.len() < bytes.len() {
            return Err(TransportError::Disconnected);
        }
        for byte in bytes {
            *byte = self.responses.pop_front().expect("response length checked");
        }
        Ok(())
    }
}
