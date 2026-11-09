//! Pure health decisions for the host (v1) and namespace (v2) layouts.
//!
//! The root exports preserve the M1 API and CLI behavior.

pub mod v1;
pub mod v2;

pub use v1::*;
