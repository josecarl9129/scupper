//! Command entry point.

use scupper::cli;

fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(cli::run(std::env::args_os()))
}
