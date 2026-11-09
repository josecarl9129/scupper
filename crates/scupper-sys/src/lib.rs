//! Linux execution, filesystem, network and health observation adapters.

pub use scupper_core::{parse, rules, verdict};

pub mod apply;
pub mod canon;
pub mod check;
pub mod check_v2;
pub mod cmd;
pub mod collect;
pub mod netns;
pub mod probe;
pub mod probe_child;
pub mod system;
pub mod topology;

pub mod lock;
pub mod secrets;
pub mod state;
pub mod store;
