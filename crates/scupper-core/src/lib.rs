//! Pure configuration, rendering, parsing and health decisions for a fail-closed VPN gateway.

#![deny(clippy::disallowed_types, clippy::disallowed_methods)]

#[cfg(all(feature = "lab-mutation", not(debug_assertions)))]
compile_error!("lab-mutation is restricted to debug lab builds");

pub mod alerts;
pub mod canon;
pub mod config;
pub mod dns;
pub mod failover;
pub mod heartbeat;
pub mod lab_mutation;
pub mod parse;
pub mod planner;
pub mod render;
pub mod rules;
pub mod verdict;
