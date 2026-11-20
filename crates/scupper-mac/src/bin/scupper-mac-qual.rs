//! Disposable GitHub macOS runner qualification entry point.
#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(scupper_mac::qual::main_entry())
}
