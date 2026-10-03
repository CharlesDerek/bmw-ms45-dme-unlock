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
  signature verification and reset. Its cancellable execution API checks for
  cancellation before security access and between complete, read-back-verified
  blocks, never during a backend operation. An interrupted execution returns a
  `FlashExecutionState` that reports its phase, verified byte count, and whether
  reset is permitted. Reset permission is fail-closed before attempting erase
  and is restored only after signature verification succeeds. No live transport
  implementation is provided, so this is a safety contract rather than a live
  flashing feature.
- Battery voltage is an explicit `FlashBackend` measurement in millivolts. The
  flash plan requires a stable window of acceptable readings before its first
  erase and rechecks the acceptable range before each later erase, write,
  readback, signature check, and reset. Read-only diagnostic jobs reject the
  measurement by default, so a future write backend must deliberately implement
  and validate the model-specific voltage job.
- A stateful `BenchSimulator` implementing `FlashBackend`. Its deterministic
  fault schedule covers virtual timeouts, persistent voltage loss, security
  rejection, partial erase state, corrupted reads, and disconnects. See
  [bench simulator](bench-simulator.md).

Not implemented yet:

- A validated Ediabas `DiagnosticJobs` implementation or native serial
  `EcuTransport` plus diagnostic protocol/job implementation.
- Hardware-accepted live access. Experimental identify and bounded reads are
  available only in builds made with `--features live-read`; erase, write,
  security access, reset, and signature-check commands remain unavailable.

The old C# app delegates communication to EdiabasLib and BMW `.prg` job files.
An Ediabas integration belongs at `DiagnosticJobs`, because Ediabas owns its
wire framing. A native implementation composes a serial `EcuTransport` with a
protocol framer/job mapper. Both then use `EcuOperations` and `FlashPlan` for
the same identity pinning, bounds, readback, and reset fencing. The included
`SimulatedTransport` is deterministic byte-stream test support. The
`BenchSimulator` models memory and flash-plan failures, but is not an electrical
or protocol-level ECU emulator.

Hardware acceptance still requires validating the installed PRG result names,
serial timing/framing, address maps, security access, erase/write/readback,
signature checking, cancellation latency between real diagnostic jobs, and
reset behavior on both MS45 variants. It must also compare reported voltage to
a calibrated external meter under load and exercise threshold crossings on both
MS45 variants. No physical hardware validation is claimed by this repository.

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
