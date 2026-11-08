//! Pure configuration and rendering for a fail-closed VPN gateway.
//!
//! The v1 ruleset is a lab-only parity port: kernel forwarding policy is its
//! barrier against sending client plaintext through the host uplink.

pub mod parse;
pub mod rules;
