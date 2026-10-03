![Alt text](assets/M3-GTR.jpg?raw=true "M3 GTR")

# BMW MS45 Flasher

Rust tooling for BMW MS45.0/MS45.1 binary validation, checksum correction, signing, and flash-payload preparation.

This development branch has removed the legacy C# WPF application. The project is now a Rust workspace with a reusable core library, a command-line tool, a native desktop GUI, and a browser-based web UI.

## Status

Implemented:

* Offline tune preparation from a tune file or full external flash.
* Offline full-program payload preparation from external flash and MPC flash files.
* MS45 checksum correction and RSA signing.
* Security access payload generation.
* A fail-closed live-flash execution plan with identity pinning, overlap and
  address validation, bounded block writes, aggregate progress, signature
  verification, per-block readback, and fencing of reset after any failed
  operation. The plan can also pin the expected VIN before security access.
* Metadata validation for tune/software reference, program/hardware reference, and external/MPC pairing.
* Exact numeric reference matching that rejects blank or malformed binary
  metadata and avoids accepting a shorter reference embedded in a longer one.
* Native desktop GUI.
* Local web-server GUI.
* A layered ECU boundary: `EcuTransport` moves opaque bytes, `DiagnosticJobs`
  owns protocol/job mapping, and `EcuOperations` applies shared identity,
  address, result-length, and write-block safety checks before the existing
  flash plan can run. TCP and deterministic simulation transports are included;
  serial and Ediabas implementations remain external acceptance work.
* A deterministic, stateful bench simulator for the complete flash-plan
  boundary. Tests inject operation-specific timeouts, voltage loss, rejected
  security access, partial erases, corrupted readback, and disconnects without
  sleeping or claiming physical-hardware coverage. See
  [bench simulator](docs/bench-simulator.md).
* A read-only TCP job-adapter protocol with nonce-bound responses, strict
  identity parsing, fail-closed normal programming-state validation, a
  metadata-only hardware probe, bounded reads, and a
  verified, resumable backup CLI. Its
  tests exercise wrong variants, stale responses, short reads, disconnects,
  interrupted backup recovery, and tampered progress.
* A versioned, CC0 synthetic compatibility manifest covering multiple
  sanitized MS45.0/MS45.1 software, hardware-revision, and pairing structures,
  plus metadata mismatch and overlap rejection, exercised by the Rust test
  suite. See [the fixture notes](fixtures/compatibility/README.md).
* Versioned Ed25519-signed flash-plan artifacts that bind an approved ECU
  identity to payload hashes, address ranges, block size, signature target,
  and the exact intended operation sequence. See
  [signed flash plans](docs/signed-flash-plans.md).
* CLI, native GUI, and web GUI inspection of verified flash plans, including
  exact erase ranges and every block-write range before execution.
* A loopback-only read-only EdiabasTest job bridge that can serve the backup
  CLI after its PRG job/result mapping is independently validated on hardware.

Not implemented yet:

* Direct MS45 diagnostic job communication and physical adapter validation.
* Live DME write/erase/reset from Rust.
* Native Ediabas/PRG job execution.

Live flashing is intentionally behind layered Rust boundaries. The original application used EdiabasLib and BMW `.prg` files for hardware communication; this Rust branch needs either a validated `DiagnosticJobs` implementation backed by Ediabas or a serial `EcuTransport` plus native protocol/job implementation before it should write to an ECU.

## Build

```bash
cargo build --workspace
```

Run tests:

```bash
cargo test --workspace
```

Run lint checks:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Validate the OpenTofu Kubernetes module:

```bash
scripts/ci/opentofu-validate.sh
```

## Desktop GUI

```bash
cargo run -p ms45-gui -- desktop
```

The desktop GUI lets you choose local binary files, validate metadata, and write prepared tune/program payloads.

## Web GUI

```bash
cargo run -p ms45-gui -- server --host 127.0.0.1 --port 4580
```

Then open:

```text
http://127.0.0.1:4580
```

The web UI runs locally and sends uploaded files to the Rust server for validation and payload generation.

## CLI

Prepare a tune payload:

```bash
cargo run -p ms45 -- prepare-tune --input tune.bin --output tune.prepared.bin
```

Prepare full-program payloads:

```bash
cargo run -p ms45 -- prepare-program \
  --external full_flash.bin \
  --mpc mpc.bin \
  --external-output external_program.prepared.bin \
  --mpc-output mpc_program.prepared.bin
```

Validate metadata:

```bash
cargo run -p ms45 -- validate --tune tune.bin --sw-ref 7561520
cargo run -p ms45 -- validate --external full_flash.bin --mpc mpc.bin --hw-ref 0044570
```

Inspect the exact erase and write ranges in a signed flash plan:

```bash
cargo run -p ms45 -- inspect-flash-plan \
  --input approved-flash-plan.json \
  --expected-public-key APPROVED_ED25519_PUBLIC_KEY
```

The command verifies the signer and signature before reporting any ranges. The
desktop and web GUIs expose the same verification and inspection workflow.

Generate a security access message from known challenge data:

```bash
cargo run -p ms45 -- security-message --user-id 01020304 --serial 05060708 --seed 090a0b0c
```

Probe ECU metadata without reading flash or requesting security access:

```bash
cargo run -p ms45 -- probe --adapter 127.0.0.1:4581
```

The command prints `ms45.hardware-probe.v1` JSON containing the variant,
hardware and software references, programming status, diagnostic protocol,
and SHA-256 of the VIN. It never prints the VIN itself.
Programming status is the numeric BMW job result; only state `1` (normal
operation) is accepted when identifying an ECU for backup or future flashing.
The probe command still reports other well-formed states to aid diagnosis.

Read a bounded region through an independently implemented read-only adapter:

```bash
cargo run -p ms45 -- backup --adapter 127.0.0.1:4581 \
  --expected-variant MS45.1 --expected-hw-ref HW1 --expected-sw-ref SW1 \
  --expected-vin-sha256 SHA256_OF_APPROVED_VIN \
  --bridge-version 1.1.0 \
  --region external --start 0 --length 4096 --output backup.bin
```

The command checkpoints each verified 4096-byte block, safely resumes the same
output after interruption, and hashes the first pass from disk. It then performs
a second complete adapter read and requires both SHA-256 hashes to match before
finalizing the file and printing a verified JSON receipt with the VIN hash only.
Resume progress is stored beside the requested output as `<output>.partial` and
`<output>.progress.json`; keep both files together and rerun the identical
command. The progress file binds block hashes to the exact ECU identity,
bridge version, region, start, and length. Do not edit it. On completion,
`<output>.manifest.json` is written atomically beside the backup using the
versioned `ms45.backup-manifest.v1` format. It records hashed ECU identity
fields, the address range, UTC start/completion timestamps, binary length and
SHA-256, bridge and CLI versions, and effective read parameters including the
two-pass count. Supply the
version printed by `scripts/ms45_read_bridge.py --version` to
`--bridge-version`. The adapter wire format is
documented in [read-only transport](docs/read-only-transport.md). This is an
interface for a future Ediabas/PRG job bridge, not an observed hardware backup.
No CLI command grants security access, erases, writes, or resets an ECU.
The [bench acceptance procedure](docs/bench-acceptance.md) defines full,
repeatable MS45.0/MS45.1 reads, adapter and tool-version capture, and redacted
receipts. Its first receipt is pending because no hardware run was available.

## Workspace

* `crates/ms45-core`: headless binary logic and flashing backend traits.
* `crates/ms45-cli`: command-line interface.
* `crates/ms45-gui`: native desktop GUI and local web server.
* `infra/opentofu`: OpenTofu Kubernetes deployment/service module for the web GUI.
* `scripts/ci`: local scripts used by GitHub Actions.
* `docs/rust-port.md`: porting notes and live-flashing boundary.

## Safety

Bad binaries can render a DME unbootable. Make full backups before flashing with any tool. This Rust branch currently prepares files offline and does not perform live ECU writes.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
