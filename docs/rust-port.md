# Rust Port Status

This repository now contains a Rust workspace. The original WPF/C# application has been removed on this development branch.

Implemented:

- `ms45-core`: pure Rust checksum, signature, security-message, metadata validation, and payload preparation logic.
- `ms45`: a CLI for offline binary validation and generating corrected flash payloads.
- `ms45-gui`: a native desktop GUI and local web-server GUI over the same Rust core.
- Layered live-access boundaries: `EcuTransport` for reliable bytes,
  `DiagnosticJobs` for protocol framing and PRG/native job mapping, and
  `EcuOperations` for model safety checks. `EcuOperations` implements the
  existing `FlashBackend`, so transport choices cannot bypass the flash plan.
- An offline-testable `FlashPlan` that validates segment layout and connected
  identity, then checks every written block through `read_memory` before
  signature verification and reset. No live transport implementation is
  provided, so this is a safety contract rather than a live flashing feature.

Not implemented yet:

- A validated Ediabas `DiagnosticJobs` implementation or native serial
  `EcuTransport` plus diagnostic protocol/job implementation.
- Live read, erase, write, reset, and signature-check commands against an actual DME.

The old C# app delegates communication to EdiabasLib and BMW `.prg` job files.
An Ediabas integration belongs at `DiagnosticJobs`, because Ediabas owns its
wire framing. A native implementation composes a serial `EcuTransport` with a
protocol framer/job mapper. Both then use `EcuOperations` and `FlashPlan` for
the same identity pinning, bounds, readback, and reset fencing. The included
`SimulatedTransport` is deterministic test support, not an ECU emulator.

Hardware acceptance still requires validating the installed PRG result names,
serial timing/framing, address maps, security access, erase/write/readback,
signature checking, and reset behavior on both MS45 variants. No physical
hardware validation is claimed by this repository.

## Build

```bash
cargo build
```

## GUI

Run the desktop app:

```bash
cargo run -p ms45-gui -- desktop
```

Run the local web UI:

```bash
cargo run -p ms45-gui -- server --host 127.0.0.1 --port 4580
```

## Examples

Prepare a tune payload:

```bash
cargo run -p ms45 -- prepare-tune --input tune.bin --output tune.prepared.bin
```

Prepare full program payloads:

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
