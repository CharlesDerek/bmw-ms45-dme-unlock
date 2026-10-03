use std::path::Path;

use serde::Serialize;
use serde_json::Value;

pub const CLI_ERROR_SCHEMA: &str = "ms45.cli-error.v1";
pub const OPERATION_RESULT_SCHEMA: &str = "ms45.operation-result.v1";
pub const BACKUP_RECEIPT_SCHEMA: &str = "ms45.backup-receipt.v1";

#[derive(Debug, Serialize)]
pub struct CliError<'a> {
    pub schema_version: &'static str,
    pub status: &'static str,
    pub operation: Option<&'a str>,
    pub code: &'a str,
    pub message: String,
    pub causes: Vec<String>,
}

impl<'a> CliError<'a> {
    pub fn new(
        operation: Option<&'a str>,
        code: &'a str,
        message: String,
        causes: Vec<String>,
    ) -> Self {
        Self {
            schema_version: CLI_ERROR_SCHEMA,
            status: "error",
            operation,
            code,
            message,
            causes,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct OperationResult<'a> {
    pub schema_version: &'static str,
    pub status: &'static str,
    pub operation: &'a str,
    pub result: Value,
}

impl<'a> OperationResult<'a> {
    pub fn success(operation: &'a str, result: Value) -> Self {
        Self {
            schema_version: OPERATION_RESULT_SCHEMA,
            status: "success",
            operation,
            result,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BackupReceipt<'a> {
    pub schema_version: &'static str,
    pub status: &'static str,
    pub variant: &'a str,
    pub hardware_reference: &'a str,
    pub software_reference: &'a str,
    pub vin_sha256: &'a str,
    pub region: &'a str,
    pub start: u32,
    pub length: usize,
    pub sha256: &'a str,
    pub output_sha256: &'a str,
    pub encrypted: bool,
    pub read_passes: usize,
    pub resumed_bytes: usize,
    pub output: &'a Path,
    pub manifest: &'a Path,
}
