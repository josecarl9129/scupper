//! Command-line interface for a fail-closed VPN gateway.

pub use scupper_core::{parse, rules, verdict};
pub use scupper_sys::{apply, canon, check, probe, system, topology};

pub mod cli;
