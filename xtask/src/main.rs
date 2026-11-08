//! Development-only capture classifier.

use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
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
}

fn run() -> Result<bool, Box<dyn std::error::Error>> {
    let Command::Classify {
        file,
        policy,
        limit,
    } = Args::parse().command;
    let policy = Policy::from_toml(&std::fs::read_to_string(policy)?)?;
    let report = classify(&std::fs::read(file)?, &policy, limit)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(report.violation_count == 0)
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
