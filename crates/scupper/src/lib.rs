//! Command-line interface for a fail-closed VPN gateway.

pub use scupper_core::{parse, rules, verdict};
#[cfg(target_os = "linux")]
pub use scupper_sys::{canon, system};

#[cfg(target_os = "linux")]
pub mod cli;
#[cfg(not(target_os = "linux"))]
#[path = "portable_cli.rs"]
pub mod cli;
pub mod deploy;
mod deploy_process;
#[cfg(target_os = "linux")]
pub mod remote;

// Compile the operator parser in Linux unit tests as well as on macOS.
#[cfg(all(test, target_os = "linux"))]
#[path = "portable_cli.rs"]
mod portable_cli_test;

mod mac_app;
