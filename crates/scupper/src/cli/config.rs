//! Immutable site configuration commands; storing never changes kernel state.
use super::{Dependencies, confirm, output_error, require_root};
use clap::Subcommand;
use scupper_core::{
    config::{GatewayId, ValidatedSite, parse_site, validate},
    render::{VersionStamp, render_netns},
};
use scupper_sys::{
    fs::{Fs, RealFs},
    lock::WriterLock,
    store::{MetaInput, VersionStore},
};
use std::{io::Write, path::PathBuf};

#[derive(Clone, Subcommand)]
pub(super) enum ConfigCommand {
    /// Print head's TOML, or a specific committed version.
    Show {
        #[arg(long)]
        version: Option<u64>,
    },
    /// Parse and report all semantic validation failures with field paths.
    Validate { file: PathBuf },
    /// Validate, preview and store a new head without applying it.
    Load {
        file: PathBuf,
        #[arg(long, default_value = "")]
        reason: String,
        #[arg(long)]
        yes: bool,
    },
    /// Export all public configuration history, or verify a bundle without writing.
    Bundle {
        #[arg(short = 'o', long, conflicts_with = "verify")]
        output: Option<PathBuf>,
        #[arg(long)]
        verify: Option<PathBuf>,
    },
    /// List committed versions and their attribution.
    History,
    /// Compare two versions (defaults to head-1 and head).
    Diff { a: Option<u64>, b: Option<u64> },
    /// Store a historical version's content as a new head.
    Rollback {
        version: u64,
        #[arg(long)]
        yes: bool,
    },
}

pub(super) fn validate_text(text: &str) -> Result<ValidatedSite, String> {
    let parsed = parse_site(text).map_err(|error| error.to_string())?;
    validate(parsed).map_err(|errors| {
        errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    })
}

pub(super) fn gateway_id(
    deps: &Dependencies<'_>,
    site: &ValidatedSite,
) -> Result<GatewayId, String> {
    let gateway = GatewayId(
        RealFs
            .read(&deps.config_root.join("gateway-id"))
            .map_err(|error| format!("read gateway-id: {error}"))?
            .trim()
            .into(),
    );
    if site.gateway(&gateway).is_none() {
        return Err("gateway-id is absent from site".into());
    }
    Ok(gateway)
}

pub(super) fn stamp(version: u64, digest: &str) -> Result<VersionStamp, String> {
    let mut sha256 = [0; 32];
    if digest.len() != 64 {
        return Err("invalid configuration digest".into());
    }
    for (index, byte) in sha256.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid configuration digest")?;
    }
    Ok(VersionStamp { version, sha256 })
}

pub(super) fn run(
    command: ConfigCommand,
    deps: &Dependencies<'_>,
    stdout: &mut dyn Write,
) -> Result<u8, String> {
    let store = VersionStore::read_only(deps.state_root, deps.config_root);
    match command {
        ConfigCommand::Bundle { output, verify } => {
            if let Some(file) = verify {
                let bytes = scupper_sys::bundle::read_bundle(&file).map_err(|e| e.to_string())?;
                scupper_sys::bundle::verify(&bytes).map_err(|e| e.to_string())?;
                writeln!(stdout, "bundle is valid").map_err(output_error)?;
            } else {
                let bytes = scupper_sys::bundle::export(deps.state_root, None)
                    .map_err(|e| e.to_string())?;
                if let Some(file) = output {
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut output = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o640)
                        .open(file)
                        .map_err(|e| e.to_string())?;
                    output.write_all(&bytes).map_err(output_error)?;
                    output.sync_all().map_err(output_error)?;
                } else {
                    stdout.write_all(&bytes).map_err(output_error)?;
                }
            }
        }
        ConfigCommand::Show { version } => {
            let version = version.map_or_else(|| head(&store), Ok)?;
            let (text, _) = store.read(version).map_err(|error| error.to_string())?;
            write!(stdout, "{text}").map_err(output_error)?;
        }
        ConfigCommand::Validate { file } => {
            validate_text(&read_input(&file)?)?;
            writeln!(stdout, "configuration is valid").map_err(output_error)?;
        }
        ConfigCommand::Load { file, reason, yes } => {
            require_root(deps, "config load")?;
            store_new(deps, &store, &read_input(&file)?, reason, yes, stdout)?;
        }
        ConfigCommand::History => {
            writeln!(stdout, "version\tparent\tat\tactor\treason\tsha256").map_err(output_error)?;
            for (index, meta) in store
                .history()
                .map_err(|error| error.to_string())?
                .iter()
                .enumerate()
            {
                writeln!(
                    stdout,
                    "{}\t{}\t{}\t{:?}\t{:?}\t{}",
                    index + 1,
                    meta.parent.map_or_else(|| "-".into(), |n| n.to_string()),
                    meta.at,
                    meta.actor,
                    meta.reason,
                    &meta.sha256[..12]
                )
                .map_err(output_error)?;
            }
        }
        ConfigCommand::Diff { a, b } => {
            let current = head(&store)?;
            let a = a.unwrap_or(current.saturating_sub(1));
            let b = b.unwrap_or(current);
            let old = store.read(a).map_err(|error| error.to_string())?.0;
            let new = store.read(b).map_err(|error| error.to_string())?.0;
            write!(
                stdout,
                "{}",
                unified_diff(
                    &old,
                    &new,
                    &format!("config/{a:06}.toml"),
                    &format!("config/{b:06}.toml")
                )
            )
            .map_err(output_error)?;
        }
        ConfigCommand::Rollback { version, yes } => {
            require_root(deps, "config rollback")?;
            let text = store
                .read(version)
                .map_err(|error| format!("cannot rollback version {version}: {error}"))?
                .0;
            store_new(
                deps,
                &store,
                &text,
                format!("rollback to version {version}"),
                yes,
                stdout,
            )?;
        }
    }
    Ok(0)
}

fn head(store: &VersionStore) -> Result<u64, String> {
    store
        .head()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "configuration store has no head".into())
}

fn read_input(file: &std::path::Path) -> Result<String, String> {
    RealFs
        .read(file)
        .map_err(|error| format!("read {}: {error}", file.display()))
}

fn store_new(
    deps: &Dependencies<'_>,
    store: &VersionStore,
    text: &str,
    reason: String,
    yes: bool,
    stdout: &mut dyn Write,
) -> Result<(), String> {
    let site = validate_text(text)?;
    let gateway = gateway_id(deps, &site)?;
    // Resolve attribution and all renderer inputs before any durable mutation.
    let actor = deps
        .privilege
        .user_name()
        .map_err(|error| format!("local user: {error}"))?;
    let parent = store.head().map_err(|error| error.to_string())?;
    let old = parent
        .map(|n| store.read(n).map(|(text, _)| text))
        .transpose()
        .map_err(|error| error.to_string())?
        .unwrap_or_default();
    write!(stdout, "{}", unified_diff(&old, text, "head", "proposed")).map_err(output_error)?;
    stdout.flush().map_err(output_error)?;
    confirm(
        deps,
        "config write",
        yes,
        "Store this configuration as a new version? [y/N]",
        None,
    )?;
    // Parent was captured before confirmation: another writer must cause a CAS
    // conflict, never silently change what the operator just reviewed.
    let writer = WriterLock::acquire(deps.writer_root).map_err(|error| error.to_string())?;
    let store =
        VersionStore::open_with_mirror_root(deps.state_root, deps.config_root, Some(&writer))
            .map_err(|error| error.to_string())?;
    scupper_sys::secrets::SecretFile::preflight(
        deps.config_root,
        &parse_site(text).map_err(|e| e.to_string())?,
        rustix::process::geteuid().as_raw(),
    )
    .map_err(|e| e.to_string())?;
    let version = store
        .commit(
            &writer,
            parent,
            text,
            MetaInput {
                actor,
                at: deps.system.now_unix_secs(),
                reason,
            },
        )
        .map_err(|error| error.to_string())?;
    let (_, meta) = store.read(version).map_err(|error| error.to_string())?;
    let rules = render_netns(&site, &gateway, &stamp(version, &meta.sha256)?)
        .map_err(|error| error.to_string())?;
    store
        .write_rendered(&writer, version, &rules)
        .map_err(|error| error.to_string())?;
    writeln!(stdout, "version {version} stored, not yet applied").map_err(output_error)
}

pub(super) fn rules(
    deps: &Dependencies<'_>,
    diff: bool,
    stdout: &mut dyn Write,
) -> Result<u8, String> {
    let config = super::m2_config(deps)?.ok_or("not an M2 gateway (no /var/lib/scupper store)")?;
    let rendered = render_netns(&config.site, &config.gateway, &config.stamp)
        .map_err(|error| error.to_string())?;
    if diff {
        let handle = deps
            .namespaces
            .open_gateway()?
            .ok_or("scupper namespace is missing")?;
        let (want, live) = scupper_sys::canon::netns_rulesets(deps.system, &handle, &rendered)
            .map_err(|error| error.to_string())?;
        if want == live {
            writeln!(stdout, "no differences").map_err(output_error)?;
        } else {
            let old =
                serde_json::to_string_pretty(&live).map_err(|error| error.to_string())? + "\n";
            let new =
                serde_json::to_string_pretty(&want).map_err(|error| error.to_string())? + "\n";
            write!(
                stdout,
                "{}",
                unified_diff(&old, &new, "live scupper namespace", "rendered head")
            )
            .map_err(output_error)?;
        }
    } else {
        write!(stdout, "{rendered}").map_err(output_error)?;
    }
    Ok(0)
}

/// One complete-file unified hunk, preserving missing-final-newline semantics.
fn unified_diff(old: &str, new: &str, old_name: &str, new_name: &str) -> String {
    if old == new {
        return String::new();
    }
    let range = |text: &str| match text.lines().count() {
        0 => "0,0".into(),
        1 => "1".into(),
        n => format!("1,{n}"),
    };
    let mut diff = format!(
        "--- {old_name}\n+++ {new_name}\n@@ -{} +{} @@\n",
        range(old),
        range(new)
    );
    for (prefix, contents) in [('-', old), ('+', new)] {
        for line in contents.split_inclusive('\n') {
            diff.push(prefix);
            diff.push_str(line);
            if !line.ends_with('\n') {
                diff.push_str("\n\\ No newline at end of file\n");
            }
        }
    }
    diff
}

#[cfg(test)]
mod tests {
    use super::unified_diff;
    #[test]
    fn diff_handles_equal_empty_and_missing_newlines() {
        assert_eq!(unified_diff("same\n", "same\n", "a", "b"), "");
        assert_eq!(
            unified_diff("", "new\n", "a", "b"),
            "--- a\n+++ b\n@@ -0,0 +1 @@\n+new\n"
        );
        assert_eq!(
            unified_diff("old", "", "a", "b"),
            "--- a\n+++ b\n@@ -1 +0,0 @@\n-old\n\\ No newline at end of file\n"
        );
    }
}
