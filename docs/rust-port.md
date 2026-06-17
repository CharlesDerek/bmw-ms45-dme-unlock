# Rust Port Status

This repository now contains a Rust workspace. The original WPF/C# application has been removed on this development branch.

Implemented:

- `ms45-core`: pure Rust checksum, signature, security-message, metadata validation, and payload preparation logic.
- `ms45`: a CLI for offline binary validation and generating corrected flash payloads.
- `ms45-gui`: a native desktop GUI and local web-server GUI over the same Rust core.
- A `FlashBackend` trait that captures the live flashing boundary without tying the core binary logic to a specific transport.

Not implemented yet:

- A native replacement for EdiabasLib's PRG interpreter and serial transport.
- Live read, erase, write, reset, and signature-check commands against an actual DME.

The old C# app delegates communication to EdiabasLib and BMW `.prg` job files. Porting the binary algorithms is straightforward and testable. Porting live flashing requires either binding to an existing Ediabas implementation or implementing enough PRG/job execution natively to run jobs such as `speicher_lesen_ascii`, `flash_schreiben`, `flash_loeschen`, and `authentisierung_start`.

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
