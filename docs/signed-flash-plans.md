# Signed flash plans

`ms45 create-flash-plan` creates an offline `ms45.flash-plan.v1` JSON artifact.
It binds the approved MS45 variant, hardware and software references, hashed
VIN, required normal programming state, each payload's region/range/length and
SHA-256, the write block size, signature target, and intended operation order.
The schema version and complete `plan` object are signed with Ed25519. Payload
bytes and the private key are not embedded.

Create a plan with a separately managed 32-byte Ed25519 seed encoded as 64 hex
digits. Keep this key outside the repository and restrict its file permissions:

```bash
cargo run -p ms45 -- create-flash-plan \
  --expected-variant MS45.1 \
  --expected-hw-ref 0044570 \
  --expected-sw-ref 7561520 \
  --expected-vin-sha256 SHA256_OF_APPROVED_VIN \
  --segment external:0x0:external_program.prepared.bin \
  --segment mpc:0x0:mpc_program.prepared.bin \
  --block-size 4096 --signature-target program \
  --signing-key /secure/path/ms45-ed25519-seed.hex \
  --output approved-flash-plan.json
```

Addresses accept decimal or a `0x` prefix. Segment paths may contain colons
after the second separator. Generation rejects empty payloads, invalid or
overflowing ranges, region bounds violations, and overlaps within a region.

Before use, pin the public key shown by the creation command through a trusted
channel and verify the artifact:

```bash
cargo run -p ms45 -- verify-flash-plan \
  --input approved-flash-plan.json \
  --expected-public-key APPROVED_ED25519_PUBLIC_KEY
```

Verification checks the schema and all safety invariants as well as signer
identity and signature. It does not currently execute a flash. A future live
backend must also hash the supplied payload files and compare them to the plan,
then pin the connected ECU identity before security access. Physical-hardware
acceptance of that path remains outstanding; this command neither accesses nor
claims validation on an ECU.
