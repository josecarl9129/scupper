//! Linux execution, filesystem, network and health observation adapters.

pub use scupper_core::{parse, rules, verdict};

pub mod alerts;
pub mod boot;
pub mod bundle;
pub mod canon;
pub mod check_v2;
pub mod cmd;
pub mod collect;
pub mod fs;
pub mod heartbeat;
pub mod netns;
pub mod probe;
pub mod probe_child;
pub mod provider;
pub mod system;
pub mod v1_detect;

pub mod events;
pub mod lock;
pub mod secrets;
pub mod state;
pub mod store;

pub mod reconcile;

pub mod daemon;
