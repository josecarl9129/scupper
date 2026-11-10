//! Supply the compile-time test directory for library unit tests as well.
use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=CARGO_TARGET_TMPDIR");
    // Cargo supplies this automatically to integration tests, but not lib tests.
    let temporary = match env::var_os("CARGO_TARGET_TMPDIR") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(env::var_os("OUT_DIR").ok_or("missing OUT_DIR")?).join("test-tmp"),
    };
    println!(
        "cargo::rustc-env=CARGO_TARGET_TMPDIR={}",
        temporary.display()
    );
    Ok(())
}
