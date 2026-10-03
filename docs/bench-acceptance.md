# Read-only bench acceptance

No physical MS45 hardware was available while this procedure was added. The
first acceptance record is therefore deliberately `pending_hardware`; unit and
loopback tests are not hardware evidence.

## Supported bench

Run this procedure once on a known MS45.0 (`0044560`) and once on a known
MS45.1 (`0044570`). Use a regulated 13.5 V supply with current limiting, a
fused bench harness, ignition control, and an independently verified
K-line-capable adapter. Record the adapter manufacturer, model, electrical
interface, firmware, and serial in the private bridge configuration. Do not
put the VIN, adapter serial, PRG files, or customer binaries in Git.

Add this object to the bridge configuration shown in
[read-only transport](read-only-transport.md):

```json
"adapter": {
  "manufacturer": "ACTUAL_MANUFACTURER",
  "model": "ACTUAL_MODEL",
  "interface": "ACTUAL_INTERFACE_AND_DRIVER",
  "firmware": "ACTUAL_FIRMWARE",
  "serial": "PRIVATE_SERIAL"
},
"version_args": ["--version"]
```

## Procedure

1. Inspect the DME label and privately record its part number and VIN. Compute
   the VIN pin locally. Avoid putting the VIN in shell history; for example,
   read it silently and pipe it to `sha256sum`.
2. With the DME disconnected, confirm the harness pinout, fuse, ground, supply
   current limit, and that only the diagnostic K-line is attached. Power it and
   abort on unexpected current draw or heat.
3. Capture versions and redacted adapter details before starting the server:
   `python scripts/ms45_read_bridge.py --config /private/ms45.json --inventory`.
   Save its JSON output. Start the bridge normally in a second terminal.
4. Build the pinned CLI (`cargo build --release -p ms45`) and record
   `target/release/ms45 --version` and `git rev-parse HEAD`.
5. Run two complete reads, using the exact identity returned by the independently
   checked label/job mapping:

   ```text
   target/release/ms45 backup --adapter 127.0.0.1:4581 --expected-variant VARIANT --expected-hw-ref HW_REF --expected-sw-ref SW_REF --expected-vin-sha256 VIN_SHA256 --region external --start 0 --length 1048576 --output external.bin
   target/release/ms45 backup --adapter 127.0.0.1:4581 --expected-variant VARIANT --expected-hw-ref HW_REF --expected-sw-ref SW_REF --expected-vin-sha256 VIN_SHA256 --region mpc --start 0 --length 458752 --output mpc.bin
   ```

6. Power-cycle the DME and repeat both reads to new files. Require each repeated
   file to have the same SHA-256 as its first read (`sha256sum -c`). A mismatch,
   short read, identity change, timeout, or bridge error fails acceptance.
7. Copy the four CLI JSON receipts, inventory JSON, CLI version, commit, supply
   voltage/current, and UTC timestamps into the private test log. Fill the
   redacted checked-in receipt with only hashes and non-identifying hardware
   details. Set a variant to `passed` only after both full ranges repeat exactly.
   Keep raw backups offline and access-controlled.

Acceptance is complete only when both variants are `passed`. This procedure
does not authorize security access, erase, write, or reset.
