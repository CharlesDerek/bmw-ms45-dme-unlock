# Sanitized compatibility fixtures

`v1.json` describes project-authored, synthetic MS45 structures. The test
suite expands each description into correctly sized, zero-filled tune,
external-flash, and MPC buffers and writes only the metadata fields exercised
by the validators. It contains no copied executable code, calibration data,
VIN, keys, signatures, or customer data.

The layout records cover both supported hardware references and multiple
software/pairing revisions for MS45.0 and MS45.1. Reference values after the
first baseline are deliberately synthetic: they test compatibility behavior
and must not be interpreted as evidence that a particular BMW release or ECU
has been validated. The fixture descriptions are released as CC0-1.0 so they
can be redistributed independently of proprietary DME images.

Each case names its expected acceptance result and reason. Adding a layout
requires a distinct software reference, hardware revision field, and
external/MPC pairing reference; negative cases should reuse a layout and alter
only the structure relevant to the rejection under test.

Physical acceptance remains separate: run the procedure in
[`docs/bench-acceptance.md`](../../docs/bench-acceptance.md) on noncritical
MS45.0 and MS45.1 hardware before making any hardware-compatibility claim.
