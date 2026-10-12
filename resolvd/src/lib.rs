//! The parts of resolvd that decide answers, as a library: the engine, its
//! cache, and the DNS rendering of the stub door. No sockets or registry
//! access; query entropy is injected by the caller so tests and fuzzers
//! can drive a deterministic system. The binary (`main.rs`) supplies I/O
//! and kernel randomness.

pub mod cache;
pub mod engine;
pub mod log;
pub mod stub;
