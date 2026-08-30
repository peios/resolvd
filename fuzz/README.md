# Fuzzing resolvd

The parsers that read bytes a stranger chose: `dns` (every upstream reply
and every stub-door query) and `libresolv` (the native channel). Each has
two harnesses:

- **libFuzzer targets here** (`cargo +nightly fuzz run dns_decode`,
  `resolv_wire`), the real campaign — coverage-guided, run for as long as
  you like. Artefacts land in `fuzz/artifacts/`.
- **Stable-toolchain harnesses** in the crates (`cargo test fuzz_`), a
  deterministic structure-aware generator with the same invariants, so a
  regression is caught in an ordinary test run. `DNS_FUZZ_ITERS` /
  `RESOLV_FUZZ_ITERS` raise the count for a release-mode soak.

Invariants checked: never panic; whatever decodes re-encodes and decodes to
the same value; our own encoding always decodes; names round-trip.

The DHCP client's equivalent lives in `netd/fuzz/` and `netd/dhcp4/src/fuzz_tests.rs`.
