//! Pure configuration, rendering, parsing and health decisions for a fail-closed VPN gateway.

#![deny(clippy::disallowed_types, clippy::disallowed_methods)]

pub mod canon;
pub mod config;
pub mod parse;
pub mod rules;
pub mod verdict;
