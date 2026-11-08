//! Linux execution, filesystem, network and health observation adapters.

pub use scupper_core::{parse, rules, verdict};

pub mod apply;
pub mod canon;
pub mod check;
pub mod probe;
pub mod system;
pub mod topology;
