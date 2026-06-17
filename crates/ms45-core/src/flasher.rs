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

#[derive(Debug, Error)]
pub enum FlashError {
    #[error("backend does not implement live DME access yet")]
    UnsupportedBackend,
    #[error("security access was denied")]
    SecurityDenied,
    #[error("backend operation failed: {0}")]
    Backend(String),
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
