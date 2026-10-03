# Versioned CLI JSON

Pass the global `--json` option to receive one JSON object on stdout for a
successful operation and one JSON object on stderr for a failure. Scripts must
select fields by name and reject unsupported `schema_version` values. New
optional fields may be introduced only in a new schema version because the
checked-in schemas intentionally reject unknown fields.

Successful non-backup commands use `ms45.operation-result.v1`. The `operation`
field is the CLI subcommand name and command-specific values are nested in
`result`. A successful backup uses `ms45.backup-receipt.v1` directly so the
receipt can be archived without an envelope. Backup receipts contain a VIN hash,
never the VIN.

Runtime and validation failures use `ms45.cli-error.v1` on stderr. `code` is
`invalid_arguments` for command-line parsing failures and `operation_failed`
after a command has started. `operation` is null when command-line parsing
cannot identify a subcommand. The top-level message is stable in location, but
its prose and the ordered `causes` strings are diagnostic text rather than
machine-readable error identifiers.

The authoritative JSON Schema draft 2020-12 documents are:

- [`cli-error-v1.schema.json`](schemas/cli-error-v1.schema.json)
- [`operation-result-v1.schema.json`](schemas/operation-result-v1.schema.json)
- [`backup-receipt-v1.schema.json`](schemas/backup-receipt-v1.schema.json)

Help and version output remain text, even when `--json` is present, because
they are terminal metadata requests rather than operations.
