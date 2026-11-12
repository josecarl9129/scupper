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
    /// L19 namespace policy drift check (lab only).
    #[command(hide = true)]
    RouteCheck { root: PathBuf, binary: PathBuf },
    /// Namespace-local raw datagram used by fault trials.
    #[command(hide = true)]
    SendPacket {
        #[arg(long)]
        interface: String,
        #[arg(long)]
        file: PathBuf,
    },
    /// Continuous namespace-local fault canary.
    #[command(hide = true)]
    Flow {
        #[arg(long)]
        mode: String,
        #[arg(long)]
        address: SocketAddr,
        #[arg(long)]
        marker: String,
        #[arg(long)]
        log: PathBuf,
        #[arg(long, default_value_t = 90)]
        seconds: u64,
    },
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
        #[arg(long)]
        shard: Option<String>,
        #[arg(long)]
        list: bool,
        /// Run a historical fault and require a named, expected catch.
        #[arg(long, conflicts_with_all = ["shard", "list", "case", "capture_fixtures", "durations"])]
        mutation: Option<scupper_core::lab_mutation::Mutation>,
        /// Run one catalog case.
        #[arg(long, conflicts_with = "shard")]
        case: Option<String>,
        /// Shared previous results.tsv; use the same file for every shard.
        #[arg(long)]
        durations: Option<PathBuf>,
    },
    /// Run installed units with real systemd on an ephemeral CI runner.
    SystemdLab {
        #[arg(long, default_value = "systemd-lab-out")]
        artifacts: PathBuf,
        #[arg(long)]
        binaries: PathBuf,
        #[arg(long, value_parser = ["L9", "L10", "L14", "L44", "V-13"])]
        case: String,
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
        #[arg(long)]
        source: Option<std::net::IpAddr>,
    },
    /// Deliberately inject a spoofed packet for the uplink positive control.
    #[command(hide = true)]
    Inject {
        #[arg(long)]
        marker: String,
    },
}
#[allow(clippy::too_many_lines)] // Keep the platform-gated command dispatch together.
fn run(command: Command) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    match command {
        Command::RouteCheck { .. } => Err("route-check requires Linux".into()),
        #[cfg(target_os = "linux")]
        Command::SendPacket { interface, file } => {
            xtask::lab::send_packet(&interface, &file)?;
            Ok(true)
        }
        #[cfg(target_os = "linux")]
        Command::Flow {
            mode,
            address,
            marker,
            log,
            seconds,
        } => {
            xtask::lab::flow(&mode, address, &marker, &log, seconds)?;
            Ok(true)
        }
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
            shard,
            list,
            durations,
            mutation,
            case,
        } => {
            if let Some(mutation) = mutation {
                xtask::lab::run_mutation(&artifacts, mutation)?;
                return Ok(true);
            }
            if list {
                print!(
                    "{}",
                    xtask::lab::list_with_durations(
                        shard.as_deref().map(str::parse).transpose()?,
                        durations.as_deref()
                    )?
                );
                return Ok(true);
            }
            xtask::lab::run(
                &artifacts,
                capture_fixtures.as_deref(),
                shard
                    .as_deref()
                    .map(str::parse)
                    .transpose()?
                    .unwrap_or_default(),
                durations.as_deref(),
                case.as_deref(),
            )?;
            Ok(true)
        }
        #[cfg(target_os = "linux")]
        Command::SystemdLab {
            artifacts,
            binaries,
            case,
        } => {
            xtask::lab::run_systemd(&artifacts, &binaries, &case)?;
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
            source,
        } => xtask::lab::probe(&protocol, &target, port, &marker, ipv6, source_port, source),
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
    let command = Args::parse().command;
    #[cfg(target_os = "linux")]
    if let Command::RouteCheck { root, binary } = &command {
        return match xtask::lab::route_check(root, binary) {
            Ok(code) => ExitCode::from(code),
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    match run(command) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
