//! Operator-side commands on platforms without Linux gateway adapters.
use clap::{Parser, Subcommand, error::ErrorKind};
use std::ffi::OsString;

#[derive(Parser)]
#[command(name = "scupper", version, about = "Fail-closed VPN gateway")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Stage and deploy a gateway release over SSH.
    Deploy(crate::deploy::DeployArgs),
    #[command(external_subcommand)]
    Gateway(Vec<OsString>),
}
/// Runs operator commands; gateway commands report platform unavailability.
#[must_use]
pub fn run<I, T>(args: I) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            let help = matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion);
            if help {
                print!("{e}");
            } else {
                eprintln!("{e}");
            }
            return u8::from(!help);
        }
    };
    match cli.command {
        Command::Deploy(args) => match crate::deploy::run(
            &args,
            &crate::deploy::Ssh,
            &crate::deploy::Terminal,
            &mut std::io::stdout(),
        ) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("scupper: {e}");
                1
            }
        },
        Command::Gateway(args) => {
            let command = args
                .first()
                .map_or_else(String::new, |s| s.to_string_lossy().into_owned());
            eprintln!("scupper: {command} is not available on this platform");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn operator_parser_and_platform_refusals() {
        assert_eq!(super::run(["scupper", "--version"]), 0);
        assert_eq!(super::run(["scupper", "install", "--plan"]), 1);
        assert_eq!(super::run(["scupper", "check"]), 1);
        assert_eq!(super::run(["scupper", "deploy", "--help"]), 0);
        assert_eq!(super::run(["scupper", "deploy"]), 1);
    }
}
