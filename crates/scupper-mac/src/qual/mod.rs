//! Disposable-runner qualification, compiled only with `qualification`.
//!
//! Environment checks are an accident guard, not a security property. The
//! bootstrap commands preflight/arm cannot require the acknowledgement they
//! create; run/capture require a fresh acknowledgement from a separate launchd
//! job. Restore remains available after expiry. This bootstrap has no network
//! writers: it never loads pf rules or changes DNS, routes or pf enablement.

#[cfg(any(target_os = "macos", test))]
mod guard;
mod model;
#[cfg(any(target_os = "macos", test))]
mod restore_check;
pub use model::{Case, CaseResult, Evidence, Manifest, Verdict, redact};

#[cfg(any(target_os = "macos", test))]
mod command;
#[cfg(target_os = "macos")]
mod native;

/// Dispatch the qualification CLI, returning an exit code.
#[must_use]
pub fn main_entry() -> u8 {
    #[cfg(target_os = "macos")]
    {
        match native::dispatch(&std::env::args().skip(1).collect::<Vec<_>>()) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!(
                    "qualification refused/failed: {}",
                    redact(&error.to_string())
                );
                1
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        eprintln!(
            "qualification refused: native qualification requires macOS on a disposable GitHub-hosted runner"
        );
        1
    }
}
