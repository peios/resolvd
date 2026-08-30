//! The parts of resolvd that decide answers, as a library: the engine, its
//! cache, and the DNS rendering of the stub door. Pure — no sockets, no
//! registry — so the fuzz targets in `fuzz/` and the tests can drive them
//! as a whole system. The binary (`main.rs`) adds the I/O.

pub mod cache;
pub mod engine;
pub mod log;
pub mod stub;
