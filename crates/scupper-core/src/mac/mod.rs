//! Pure, fail-closed macOS policy decisions. No host observations are made here.
//!
//! Qualification inputs are evidence supplied by the caller, not claims that a
//! particular OS build has been qualified. Captured text is always untrusted.

pub mod lifecycle;
pub mod parse;
pub mod policy;
pub mod verify;

pub use policy::{AnchorText, render_joined, render_pre_tunnel};

mod types;
pub use types::*;
