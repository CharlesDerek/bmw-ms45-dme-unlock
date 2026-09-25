# Read-only adapter boundary

`ms45 backup` connects to an operator-supplied TCP endpoint. The endpoint must
be a separately validated bridge to BMW diagnostic jobs; this repository does
not yet contain that bridge or claim hardware compatibility. Bind a bridge to
loopback or an authenticated tunnel. The protocol itself has no encryption or
authentication, so an untrusted network endpoint must not be used.

Each request is 22 bytes: `MS45R1` (6), random nonce (8), operation (1),
region (1), big-endian start (4), big-endian length (2). Operation 1 identifies
the ECU; operation 2 reads memory. Regions 1 and 2 select external and MPC
flash. A response contains `MS45R1` (6), the same nonce (8), status (1),
big-endian payload length (2), then payload. Status 0 succeeds, 1 rejects the
address, and 2 rejects the operation. Identity payload is ASCII
`variant|hardware_reference|software_reference|VIN`.

The client accepts only MS45.0 or MS45.1 identities, checks all pinned fields
including a SHA-256 of the expected VIN, and limits one read to 4096 bytes.
It rejects a mismatched nonce, malformed frame, short read, out-of-range
address, timeout, or disconnect. It does not retry a read after an ambiguous
partial response. Backup files are verified on disk before a JSON receipt is
emitted. The command cannot issue write operations.

The loopback fixture in Rust tests implements this protocol and injects
identity, replay, short-read, and disconnect faults. Hardware acceptance still
requires an adapter implementing the actual MS45.0/MS45.1 diagnostic jobs and
bench verification of the address map, identity mapping, and backup contents.
