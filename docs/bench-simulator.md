# Deterministic bench simulator

`ms45_core::BenchSimulator` is an in-memory `FlashBackend` for repeatable flash
workflow tests. It models an identity, byte-addressed flash (erased bytes read
as `0xff`), persistent voltage state, virtual elapsed time, and a trace of every
attempted operation. It performs no I/O, never sleeps, and cannot access a DME.

Faults are scheduled at a `FaultPoint`, which pairs an operation with its
one-based occurrence. Specialized faults select their operation implicitly:

- `Timeout` adds only the configured duration to the simulator's virtual clock.
- `VoltageLoss` fails the selected operation and all later operations until
  `restore_voltage` is called.
- `SecurityAccessRejected` returns `FlashError::SecurityDenied` before erase.
- `PartialErase` changes the requested prefix to `0xff`, then reports failure.
- `CorruptedRead` flips one returned bit without changing stored memory.
- `Disconnect` reports a backend transport failure at the selected operation.

Only one fault may occupy a given point, which avoids order-dependent scenarios.
The simulator consumes a triggered fault, and cloning it before execution gives
an identical scenario, memory image, and event trace.

```rust
use ms45_core::{
    BenchFault, BenchOperation, BenchSimulator, DmeIdentity, FaultPoint,
};
use std::time::Duration;

let identity = DmeIdentity {
    vin: "SIMULATEDVIN".into(),
    hardware_reference: "HW-45".into(),
    software_reference: "SW-1".into(),
    programming_status: "bench-ready".into(),
    diag_protocol: "simulated".into(),
};
let mut bench = BenchSimulator::new(identity);
bench.add_fault(BenchFault::Timeout {
    at: FaultPoint::new(BenchOperation::Erase, 1),
    elapsed: Duration::from_secs(2),
})?;
# Ok::<(), ms45_core::BenchConfigurationError>(())
```

The integration suite runs each requested failure through the real `FlashPlan`
and verifies that signature checking/reset remain fenced after a failure. It
also cancels a run between read-back-verified blocks and checks the returned
execution state: reset remains forbidden because erase has begun and signature
verification has not succeeded.

## External acceptance remains required

Simulation is not evidence for K-line framing, PRG job/result mappings, adapter
timing, supply transients, flash electrical behavior, or recovery of an actual
MS45.0/MS45.1 DME. Those require a fused, current-limited physical bench and an
independently validated write-capable adapter. The existing
[read-only bench procedure](bench-acceptance.md) does not authorize destructive
testing; a separately reviewed write/recovery procedure is required before
running these scenarios against hardware.
