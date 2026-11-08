//! Development-only capture classifier and disposable namespace lab.
use clap::{Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf, process::ExitCode};
use xtask::pcap::{Policy, classify};

#[derive(Parser)]
#[command(about = "scupper development tasks")]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Check every uplink packet against an explicit allow-list.
    Classify {
        file: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        /// Maximum number of detailed violations in the report.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Run the reference topology on a disposable Linux machine (root required).
    Leaktest {
        #[arg(long, default_value = "lab-out")]
        artifacts: PathBuf,
        #[arg(long)]
        capture_fixtures: Option<PathBuf>,
    },
    /// Namespace-local canary sink (used by leaktest).
    #[command(hide = true)]
    Sink {
        #[arg(long)]
        protocol: String,
        #[arg(long)]
        bind: SocketAddr,
        #[arg(long)]
        log: PathBuf,
    },
    /// Namespace-local canary sender (used by leaktest).
    #[command(hide = true)]
    Probe {
        #[arg(long)]
        protocol: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        port: u16,
        #[arg(long)]
        marker: String,
        #[arg(long)]
        ipv6: bool,
        #[arg(long, default_value_t = 0)]
        source_port: u16,
    },
    /// Deliberately inject a spoofed packet for the uplink positive control.
    #[command(hide = true)]
    Inject {
        #[arg(long)]
        marker: String,
    },
}
fn run() -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    match Args::parse().command {
        Command::Classify {
            file,
            policy,
            limit,
        } => {
            let policy = Policy::from_toml(&std::fs::read_to_string(policy)?)?;
            let report = classify(&std::fs::read(file)?, &policy, limit)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(report.violation_count == 0)
        }
        #[cfg(target_os = "linux")]
        Command::Leaktest {
            artifacts,
            capture_fixtures,
        } => {
            xtask::lab::run(&artifacts, capture_fixtures.as_deref())?;
            Ok(true)
        }
        #[cfg(target_os = "linux")]
        Command::Sink {
            protocol,
            bind,
            log,
        } => {
            xtask::lab::sink(&protocol, bind, &log)?;
            Ok(true)
        }
        #[cfg(target_os = "linux")]
        Command::Probe {
            protocol,
            target,
            port,
            marker,
            ipv6,
            source_port,
        } => {
            xtask::lab::probe(&protocol, &target, port, &marker, ipv6, source_port)?;
            Ok(true)
        }
        #[cfg(target_os = "linux")]
        Command::Inject { marker } => {
            xtask::lab::inject(&marker)?;
            Ok(true)
        }
        #[cfg(not(target_os = "linux"))]
        _ => Err("namespace lab commands require root on Linux".into()),
    }
}
fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
