//! Read-only bridge protocol for an independently validated ECU job adapter.
//! This protocol does not implement BMW diagnostic jobs or authorize writes.
use crate::flasher::MemoryRegion;
use rand::RngCore;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
use thiserror::Error;

const MAGIC: &[u8; 6] = b"MS45R1";
pub const MAX_READ: usize = 4096;

#[derive(Debug, Error)]
pub enum ReadError {
    #[error("adapter connection or read timeout")]
    Timeout,
    #[error("adapter disconnected")]
    Disconnected,
    #[error("adapter protocol response malformed or replayed")]
    Protocol,
    #[error("ECU identity or variant rejected")]
    Identity,
    #[error("address range rejected")]
    Range,
    #[error("adapter refused read operation")]
    Rejected,
    #[error("adapter I/O failure")]
    Io,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub variant: String,
    pub hardware_reference: String,
    pub software_reference: String,
    pub vin: String,
}

pub struct ReadOnlyAdapter {
    stream: TcpStream,
}

impl ReadOnlyAdapter {
    pub fn connect(address: SocketAddr, timeout: Duration) -> Result<Self, ReadError> {
        let stream = TcpStream::connect_timeout(&address, timeout).map_err(classify_io)?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(classify_io)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(classify_io)?;
        Ok(Self { stream })
    }

    fn exchange(&mut self, op: u8, region: u8, start: u32, len: u16) -> Result<Vec<u8>, ReadError> {
        let nonce = rand::thread_rng().next_u64();
        let mut request = Vec::with_capacity(22);
        request.extend_from_slice(MAGIC);
        request.extend_from_slice(&nonce.to_be_bytes());
        request.push(op);
        request.push(region);
        request.extend_from_slice(&start.to_be_bytes());
        request.extend_from_slice(&len.to_be_bytes());
        self.stream.write_all(&request).map_err(classify_io)?;
        let mut header = [0u8; 17];
        self.stream.read_exact(&mut header).map_err(classify_io)?;
        if &header[..6] != MAGIC || header[6..14] != nonce.to_be_bytes() {
            return Err(ReadError::Protocol);
        }
        let size = u16::from_be_bytes([header[15], header[16]]) as usize;
        if size > MAX_READ {
            return Err(ReadError::Protocol);
        }
        let mut payload = vec![0u8; size];
        self.stream.read_exact(&mut payload).map_err(classify_io)?;
        match header[14] {
            0 => Ok(payload),
            1 => Err(ReadError::Range),
            2 => Err(ReadError::Rejected),
            _ => Err(ReadError::Protocol),
        }
    }

    pub fn identify(&mut self) -> Result<Identity, ReadError> {
        let bytes = self.exchange(1, 0, 0, 0)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| ReadError::Protocol)?;
        let fields = text.split('|').collect::<Vec<_>>();
        if fields.len() != 4
            || fields.iter().any(|f| {
                f.is_empty()
                    || f.len() > 64
                    || !f
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
            })
        {
            return Err(ReadError::Protocol);
        }
        if !matches!(fields[0], "MS45.0" | "MS45.1") {
            return Err(ReadError::Identity);
        }
        Ok(Identity {
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
    ) -> Result<Vec<u8>, ReadError> {
        let limit = match region {
            MemoryRegion::ExternalFlash => crate::EXTERNAL_FLASH_LEN,
            MemoryRegion::InternalMpc => crate::MPC_FLASH_LEN,
        };
        if len == 0
            || len > MAX_READ
            || (start as usize)
                .checked_add(len)
                .is_none_or(|end| end > limit)
        {
            return Err(ReadError::Range);
        }
        let data = self.exchange(
            2,
            match region {
                MemoryRegion::ExternalFlash => 1,
                MemoryRegion::InternalMpc => 2,
            },
            start,
            len as u16,
        )?;
        if data.len() != len {
            return Err(ReadError::Protocol);
        }
        Ok(data)
    }
}

fn classify_io(error: std::io::Error) -> ReadError {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => ReadError::Timeout,
        std::io::ErrorKind::UnexpectedEof
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::BrokenPipe => ReadError::Disconnected,
        _ => ReadError::Io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn fixture(identity: &'static str, fault: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            loop {
                let mut request = [0u8; 22];
                if stream.read_exact(&mut request).is_err() {
                    break;
                }
                if fault == "disconnect" {
                    break;
                }
                if fault == "timeout" {
                    std::thread::sleep(Duration::from_millis(200));
                    break;
                }
                let payload = if request[14] == 1 {
                    identity.as_bytes().to_vec()
                } else {
                    vec![0x45; u16::from_be_bytes([request[20], request[21]]) as usize]
                };
                let mut response = Vec::new();
                response.extend_from_slice(MAGIC);
                response.extend_from_slice(&request[6..14]);
                if fault == "replay" {
                    response[6] ^= 1;
                }
                response.push(if fault == "address" { 1 } else { 0 });
                response.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                if fault == "short" && request[14] == 2 {
                    response.extend_from_slice(&payload[..payload.len().saturating_sub(1)]);
                } else {
                    response.extend_from_slice(&payload);
                }
                if stream.write_all(&response).is_err() {
                    break;
                }
                if fault == "short" && request[14] == 2 {
                    break;
                }
            }
        });
        address
    }

    #[test]
    fn identity_and_bounded_read() {
        let address = fixture("MS45.1|HW1|SW1|TESTVIN", "");
        let mut adapter = ReadOnlyAdapter::connect(address, Duration::from_secs(1)).unwrap();
        assert_eq!(adapter.identify().unwrap().variant, "MS45.1");
        assert_eq!(
            adapter.read(MemoryRegion::ExternalFlash, 0, 16).unwrap(),
            vec![0x45; 16]
        );
        assert!(matches!(
            adapter.read(MemoryRegion::ExternalFlash, 0, MAX_READ + 1),
            Err(ReadError::Range)
        ));
    }

    #[test]
    fn wrong_variant_replay_short_read_and_disconnect_fail_closed() {
        let mut wrong =
            ReadOnlyAdapter::connect(fixture("MS44|HW1|SW1|TESTVIN", ""), Duration::from_secs(1))
                .unwrap();
        assert!(matches!(wrong.identify(), Err(ReadError::Identity)));
        let mut replay = ReadOnlyAdapter::connect(
            fixture("MS45.0|HW1|SW1|TESTVIN", "replay"),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(matches!(replay.identify(), Err(ReadError::Protocol)));
        let mut short = ReadOnlyAdapter::connect(
            fixture("MS45.0|HW1|SW1|TESTVIN", "short"),
            Duration::from_secs(1),
        )
        .unwrap();
        short.identify().unwrap();
        assert!(matches!(
            short.read(MemoryRegion::ExternalFlash, 0, 16),
            Err(ReadError::Disconnected)
        ));
        let mut gone = ReadOnlyAdapter::connect(
            fixture("MS45.0|HW1|SW1|TESTVIN", "disconnect"),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(matches!(gone.identify(), Err(ReadError::Disconnected)));
        let mut timeout = ReadOnlyAdapter::connect(
            fixture("MS45.0|HW1|SW1|TESTVIN", "timeout"),
            Duration::from_millis(50),
        )
        .unwrap();
        assert!(matches!(timeout.identify(), Err(ReadError::Timeout)));
        let mut address = ReadOnlyAdapter::connect(
            fixture("MS45.0|HW1|SW1|TESTVIN", "address"),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(matches!(address.identify(), Err(ReadError::Range)));
    }
}
