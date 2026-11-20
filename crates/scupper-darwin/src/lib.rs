//! Typed, owned Darwin system interfaces. Empty on other operating systems.
//! All foreign calls are confined to the private `sys` module (ADR 0034).

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod sys;

#[cfg(target_os = "macos")]
pub use sys::sysctl_string;
