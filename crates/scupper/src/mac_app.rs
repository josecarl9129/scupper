//! App pinning command parser and macOS dispatch.
use clap::{Args, Subcommand, ValueEnum};
use std::{io::Write, net::Ipv4Addr, path::PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum App {
    Transmission,
    Qbittorrent,
}
impl App {
    #[cfg(any(target_os = "macos", test))]
    fn name(self) -> &'static str {
        match self {
            Self::Transmission => "transmission",
            Self::Qbittorrent => "qbittorrent",
        }
    }
}

#[derive(Clone, Args)]
pub(crate) struct MacArgs {
    /// `WireGuard` client profile (default: ~/.scupper/scupper0.conf).
    #[arg(long, global = true)]
    profile: Option<PathBuf>,
    /// Accepted for scripting; running apps must still be quit first.
    #[arg(long, global = true)]
    yes: bool,
    #[command(subcommand)]
    command: MacCommand,
}
#[derive(Clone, Subcommand)]
enum MacCommand {
    /// Pin torrent clients to the tunnel's IPv4 address.
    App {
        #[command(subcommand)]
        command: AppCommand,
    },
}
#[derive(Clone, Subcommand)]
enum AppCommand {
    /// Show installation, binding, profile match and tunnel availability.
    Status { app: Option<App> },
    /// Bind an app while it is quit; defaults to the profile's IPv4 address.
    Bind {
        app: App,
        #[arg(long, value_parser = scupper_core::config::client_profile::tunnel_address)]
        address: Option<Ipv4Addr>,
    },
    /// Restore saved app binding preferences while quit.
    Unbind { app: App },
}

#[cfg(any(target_os = "macos", test))]
mod ini;
#[cfg(any(target_os = "macos", test))]
mod system;

pub(crate) fn run(args: &MacArgs, out: &mut dyn Write) -> Result<u8, String> {
    #[cfg(target_os = "macos")]
    {
        system::require_user(rustix::process::getuid().as_raw())?;
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or("HOME is not set")?;
        system::execute(args, &home, &system::Native, out)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (args, out);
        Err("macOS only".into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use clap::Parser;
    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: MacArgs,
    }
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn refuses_non_macos_without_observing_host() {
        let parsed = TestCli::try_parse_from(["mac", "app", "status"]).unwrap();
        assert_eq!(
            run(&parsed.args, &mut Vec::new()).unwrap_err(),
            "macOS only"
        );
    }
    #[test]
    fn closed_apps_and_flags() {
        for app in ["transmission", "qbittorrent"] {
            assert!(TestCli::try_parse_from(["mac", "app", "status", app]).is_ok());
            assert!(
                TestCli::try_parse_from([
                    "mac",
                    "app",
                    "bind",
                    app,
                    "--yes",
                    "--profile",
                    "client.conf",
                    "--address",
                    "100.64.1.2"
                ])
                .is_ok()
            );
        }
        let error = TestCli::try_parse_from(["mac", "app", "bind", "other"])
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("transmission") && error.contains("qbittorrent"));
        assert!(
            TestCli::try_parse_from(["mac", "app", "bind", "transmission", "--address", "8.8.8.8"])
                .is_err()
        );
    }
}
