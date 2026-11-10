//! Host-namespace single-writer daemon entry point.
use clap::Parser;
#[cfg(feature = "testing")]
use std::path::PathBuf;
use std::sync::{Arc, atomic::AtomicBool};

#[derive(Parser)]
#[command(version, about = "Reconcile the applied scupper gateway")]
struct Args {
    #[cfg(feature = "testing")]
    #[arg(long, hide = true)]
    test_root: Option<PathBuf>,
}
fn main() -> std::process::ExitCode {
    let args = Args::parse();
    #[cfg(not(feature = "testing"))]
    let _ = args;
    let stop = Arc::new(AtomicBool::new(false));
    let mut registrations = Vec::new();
    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        match signal_hook::flag::register(signal, stop.clone()) {
            Ok(id) => registrations.push(id),
            Err(error) => {
                eprintln!("scupperd: signal setup: {error}");
                return std::process::ExitCode::FAILURE;
            }
        }
    }
    let mut options = scupper_sys::daemon::Options::default();
    #[cfg(feature = "testing")]
    if let Some(root) = args.test_root {
        options.state_root = root.join("var-lib/scupper");
        options.config_root = root.join("etc/scupper");
        options.run_root = root.join("run/scupper");
    }
    if let Ok(mut binary) = std::env::current_exe() {
        binary.set_file_name("scupper");
        options.probe_binary = binary;
    }
    let result = scupper_sys::daemon::run(&options, &stop);
    for registration in registrations {
        signal_hook::low_level::unregister(registration);
    }
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("scupperd: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
