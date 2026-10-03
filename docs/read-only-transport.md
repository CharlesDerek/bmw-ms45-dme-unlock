# Read-only adapter boundary

The Rust client is composed as `TcpTransport` (`EcuTransport`) →
`Ms45R1Jobs` (`DiagnosticJobs`) → `EcuOperations`. Framing and nonce checks are
therefore independent of ECU identity/range/result validation. Future serial
protocols can reuse `EcuOperations`; an Ediabas binding can implement
`DiagnosticJobs` directly and reuse the same checks.

`ms45 probe` and `ms45 backup` connect to an operator-supplied TCP endpoint.
The endpoint must be a separately validated bridge to BMW diagnostic jobs;
the included EdiabasTest bridge is not a claim of hardware compatibility. Bind
a bridge to loopback or an authenticated tunnel. The protocol itself has no
encryption or authentication, so an untrusted network endpoint must not be
used.

Each request is 22 bytes: `MS45R1` (6), random nonce (8), operation (1),
region (1), big-endian start (4), big-endian length (2). Operation 1 identifies
the ECU, operation 2 reads memory, and operation 3 performs a metadata-only
hardware probe. Regions 1 and 2 select external and MPC flash. Probe requests
require zero region, start, and length. A response contains `MS45R1` (6), the
same nonce (8), status (1), big-endian payload length (2), then payload. Status
0 succeeds, 1 rejects the address, and 2 rejects the operation. Identity payload is ASCII
`variant|hardware_reference|software_reference|VIN`.

Probe payload is ASCII
`variant|hardware_reference|software_reference|programming_status|diagnostic_protocol|VIN`.
`programming_status` is the decimal `FLASH_PROGRAMMIER_STATUS` value, not its
localized display text. ECU identification uses this probe payload and accepts
only state `1` (normal operation); every other, malformed, or unknown state is
rejected before a memory read or future security-access request.
The CLI emits `ms45.hardware-probe.v1` JSON with a SHA-256 VIN hash instead of
the raw VIN. The loopback bridge serves it with identification/status jobs
only; it does not call the memory-read job, and MS45R1 defines no
security-access operation.

The client accepts only MS45.0 or MS45.1 identities, checks all pinned fields
including a SHA-256 of the expected VIN, and limits one read to 4096 bytes.
It rejects a mismatched nonce, malformed frame, short read, out-of-range
address, timeout, or disconnect. It does not retry a read after an ambiguous
partial response. Completed blocks are synced, reread from disk, and recorded
with SHA-256 hashes in an atomically replaced progress manifest. On a later run
with the same output path, the client re-identifies the ECU, requires the
manifest's identity and requested range to match, and verifies every persisted
block before requesting the first missing block. Uncheckpointed trailing bytes
are truncated and reread; malformed, noncontiguous, missing, or hash-mismatched
progress fails closed. This prevents a short or interrupted response from being
accepted as completed data.

While a backup is incomplete, `<output>.partial` contains its data and
`<output>.progress.json` contains the `ms45.backup-progress.v2` checkpoint. Keep
the pair together and repeat the identical command to resume. After all blocks
are durable, the partial file is hashed from disk and a second complete read is
requested from the adapter. Only matching first- and second-pass SHA-256 hashes
allow the file to be finalized, the checkpoint to be removed, and a `verified`
receipt to be printed. A failed or mismatched verification pass leaves the
partial file and checkpoint available for a retry. The receipt's
`resumed_bytes` reports how much previously verified data was reused. The
command cannot issue write operations. Finalization creates the requested
output without replacing an existing file, syncs its parent directory, and
keeps the verified partial and checkpoint until the permanent manifest is also
durable. If final persistence fails, remove only the reported obstruction and
repeat the identical command; a fully verified recovery state is recognized,
while an unrelated existing output, manifest, or orphaned partial is rejected.
Serialized JSON that cannot be moved into its final path is retained at the
recovery path printed in the error.

Every successful backup also has a permanent `<output>.manifest.json` sidecar.
Its `ms45.backup-manifest.v1` schema records SHA-256 hashes of each ECU identity
field (never the VIN itself), the half-open address range, UTC start and
completion timestamps, the binary's name, size and SHA-256, the pinned bridge
version, CLI version, protocol, block size, timeout, and two-pass count. Both the
binary and manifest are synced, their parent directory entries are synced, and
neither permanent file is replaced. Keep them together; verify the binary
against `binary.sha256` before use. The required
`--bridge-version` value is operator-pinned because MS45R1 deliberately does
not expose host metadata; obtain it from the deployed bridge's `--version`.

Optional encrypted publication is enabled only when the operator supplies
`--encrypt-with PROGRAM`. Each repeatable `--encrypt-arg VALUE` is passed
verbatim; the CLI does not invoke a shell. After both ECU read passes match, the
program reads plaintext from stdin and writes its encrypted container to stdout.
The CLI requires a successful exit and nonempty output, syncs and atomically
publishes it without overwriting, and records both the plaintext SHA-256 and the
encrypted artifact SHA-256 in `ms45.backup-manifest.v2`. Arguments are omitted
from the manifest because they may disclose recipient or configuration data.
Use the encryption tool's key files, environment, hardware token, or agent for
credentials rather than putting a passphrase in an argument. Validate encryption
and decryption with the exact operator-selected tool and key setup before the
first hardware backup.

Encryption occurs after verification, so resumable `.partial` data is plaintext.
It is removed only after the encrypted output and manifest are durable; failures
retain it and the progress file for retry. Place the working directory on
appropriately protected storage and account for filesystem remnants when
applying a secure-deletion policy.

The loopback fixture in Rust tests implements this protocol and injects
identity, replay, short-read, and disconnect faults. CLI tests also interrupt a
multi-block backup, confirm that only verified blocks are resumed, and reject a
corrupted partial file. Hardware acceptance still requires an adapter
implementing the actual MS45.0/MS45.1 diagnostic jobs and bench verification of
the address map, identity mapping, resume behavior, and backup contents.
The probe's remaining external gate is to run it against both MS45.0 and MS45.1
hardware, compare every reported field with an independent diagnostic tool,
confirm both report programming state `1` in normal operation, and capture
bridge logs showing that no memory-read or security-access job ran.

## EdiabasTest bridge

`scripts/ms45_read_bridge.py` is a loopback-only MS45R1 server that invokes an
operator-installed EdiabasTest executable for identification and memory reads.
It never accepts write, erase, reset, or security-access requests. Configure it
with a local JSON file (keep the file and any PRG assets out of Git):

```json
{
  "profile": "legacy-ms45",
  "command": ["/path/to/EdiabasTest.exe"],
  "sgbd": "D_MOTOR.GRP",
  "ecu_path": "/path/to/Ediabas/Ecu",
  "port": "COM4",
  "ifh": "STD:OBD",
  "adapter": {
    "manufacturer": "ACTUAL_MANUFACTURER",
    "model": "ACTUAL_MODEL",
    "interface": "ACTUAL_INTERFACE_AND_DRIVER",
    "firmware": "ACTUAL_FIRMWARE",
    "serial": "PRIVATE_SERIAL"
  }
}
```

The `legacy-ms45` profile uses the `aif_lesen`, `hardware_referenz_lesen`,
`daten_referenz_lesen`, `flash_programmier_status_lesen`, and
`DIAGNOSEPROTOKOLL_LESEN` metadata jobs from the [original C# branch](https://github.com/CharlesDerek/bmw-ms45-dme-unlock/blob/lts/MS45%20Flasher/MainWindow.xaml.cs). It maps
hardware references `0044560` and `0044570` to MS45.0 and MS45.1, and reads
`ROMX` or `LAR` with `speicher_lesen_ascii` in 254-byte chunks. Validate this
mapping against the installed PRG and ECU before use. The bridge
requires `JOB_STATUS: OKAY`, an exact read length, and a supported identity;
unexpected output causes a rejected response. Start it with:

```bash
python scripts/ms45_read_bridge.py --config /private/path/ms45-bridge.json
```

Then run `ms45 backup` against `127.0.0.1:4581` with the pinned identity.
The bridge uses EdiabasTest's [documented command-line arguments](https://uholeschak.github.io/ediabaslib/docs/EdiabasTest_parameters.html)
(`--sgbd`, `--port`, `--ifh`, and `--job`). It is an executable integration boundary, but the repo has no
observed physical ECU backup yet. The original C# code sometimes performed
security access before reading; this bridge deliberately does not. A DME that
requires security access will refuse the read.

The complete two-variant hardware gate, repeat-read hash checks, tool-version
capture, and redacted evidence rules are in [bench acceptance](bench-acceptance.md).
`--inventory` hashes the private configuration and adapter serial and captures
the actual EdiabasTest version without printing the serial. The checked-in
[first receipt](receipts/first-read-only-backup.json) remains pending until
those physical tests are performed.
