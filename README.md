
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
* Metadata validation for tune/software reference, program/hardware reference, and external/MPC pairing.
* Native desktop GUI.
* Local web-server GUI.

Not implemented yet:

* Live DME read/write/erase/reset from Rust.
* Native Ediabas/PRG job execution.

Live flashing is intentionally behind a Rust backend boundary. The original application used EdiabasLib and BMW `.prg` files for hardware communication; this Rust branch needs either a binding to an Ediabas-compatible backend or a native PRG/job implementation before it should write to an ECU.

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

Generate a security access message from known challenge data:

```bash
cargo run -p ms45 -- security-message --user-id 01020304 --serial 05060708 --seed 090a0b0c
```

## Workspace

* `crates/ms45-core`: headless binary logic and flashing backend traits.
* `crates/ms45-cli`: command-line interface.
* `crates/ms45-gui`: native desktop GUI and local web server.
* `docs/rust-port.md`: porting notes and live-flashing boundary.

## Safety

Bad binaries can render a DME unbootable. Make full backups before flashing with any tool. This Rust branch currently prepares files offline and does not perform live ECU writes.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
