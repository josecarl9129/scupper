//! Development-only, pure uplink capture oracle for the namespace leak suite.

pub mod pcap;

#[cfg(target_os = "linux")]
pub mod lab;
