//! Gateway secret provisioning; command arguments contain references only.
use super::{Dependencies, output_error, require_root};
use clap::Subcommand;
use scupper_core::config::{SecretKind, SecretName, SiteConfig, parse_site};
use scupper_sys::{
    heartbeat,
    secrets::{SecretFile, input},
    store::VersionStore,
};
use std::{
    collections::BTreeSet,
    io::{self, IsTerminal, Write},
};

#[derive(Clone, Subcommand)]
pub(super) enum SecretCommand {
    /// Store a URL credential read from a hidden prompt or stdin.
    Set {
        #[command(subcommand)]
        command: SetCommand,
    },
    /// List secret metadata and committed configuration references, never values.
    List,
    /// Check a bare gateway REF; operator scheme: lookups are not implemented in M2.
    Check { reference: String },
}
#[derive(Clone, Subcommand)]
pub(super) enum SetCommand {
    /// Read one HTTPS URL line (hidden on a TTY).
    Url {
        reference: String,
        #[arg(long)]
        replace: bool,
    },
    /// Read a hidden bot token and a visible chat id, or two stdin lines.
    Telegram {
        reference: String,
        #[arg(long)]
        replace: bool,
    },
}

struct Inventory {
    referenced: BTreeSet<(String, String)>,
    head: Option<SiteConfig>,
}
impl Inventory {
    fn read(deps: &Dependencies<'_>, history: bool) -> Result<Self, String> {
        let store = VersionStore::read_only(deps.state_root, deps.config_root);
        let head = store.head().map_err(|_| "cannot inspect config head")?;
        let mut result = Self {
            referenced: BTreeSet::new(),
            head: None,
        };
        for version in (if history { 1 } else { head.unwrap_or(1) })..=head.unwrap_or(0) {
            let (text, _) = store
                .read(version)
                .map_err(|_| "cannot inspect config version")?;
            let site = parse_site(&text).map_err(|_| "cannot parse config version")?;
            for reference in site
                .identities
                .values()
                .map(|i| &i.private_key_ref)
                .chain(site.gateways.values().flat_map(|g| &g.exits).flat_map(|e| {
                    std::iter::once(&e.private_key_ref).chain(e.preshared_key_ref.as_ref())
                }))
                .chain(
                    site.alerts
                        .sinks
                        .values()
                        .map(scupper_core::config::AlertSink::url_ref),
                )
                .chain(site.heartbeat.as_ref().map(|h| &h.url_ref))
            {
                result
                    .referenced
                    .insert((kind(reference.kind()).into(), reference.name().into()));
            }
            if Some(version) == head {
                result.head = Some(site);
            }
        }
        Ok(result)
    }

    fn next_steps(&self, name: &SecretName, out: &mut dyn Write) -> Result<(), String> {
        let mut current = false;
        if let Some(site) = &self.head {
            for (sink, settings) in &site.alerts.sinks {
                if settings.url_ref() == name {
                    writeln!(out, "Next: scupper alerts test {sink}").map_err(output_error)?;
                    current = true;
                }
            }
            if site.heartbeat.as_ref().is_some_and(|h| &h.url_ref == name) {
                writeln!(out, "The heartbeat uses this ref at the next interval.")
                    .map_err(output_error)?;
                current = true;
            }
        }
        if !current {
            writeln!(
                out,
                "No current config references this ref; use scupper config edit."
            )
            .map_err(output_error)?;
        }
        Ok(())
    }
}

fn kind(kind: SecretKind) -> &'static str {
    match kind {
        SecretKind::Wg => "wg",
        SecretKind::Url => "url",
    }
}
fn reference(text: &str) -> Result<SecretName, String> {
    SecretName::new(SecretKind::Url, text)
        .map_err(|_| "invalid reference; expected [a-z0-9][a-z0-9-]{0,62}".into())
}

pub(super) fn run(
    command: SecretCommand,
    deps: &Dependencies<'_>,
    out: &mut dyn Write,
) -> Result<u8, String> {
    if let SecretCommand::Check { reference } = &command
        && reference.split_once(':').is_some_and(|(scheme, _)| {
            scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                && scheme
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        })
    {
        return Err("operator-side secret lookup is not implemented in M2".into());
    }
    require_root(deps, "secret")?;
    match command {
        SecretCommand::Set { command } => set(command, deps, out)?,
        SecretCommand::List => list(deps, out)?,
        SecretCommand::Check { reference } => check(&reference, deps, out)?,
    }
    Ok(0)
}

fn set(command: SetCommand, deps: &Dependencies<'_>, out: &mut dyn Write) -> Result<(), String> {
    let telegram = matches!(command, SetCommand::Telegram { .. });
    let (text, replace) = match command {
        SetCommand::Url { reference, replace } | SetCommand::Telegram { reference, replace } => {
            (reference, replace)
        }
    };
    let name = reference(&text)?;
    let started = std::time::SystemTime::now();
    let inventory = {
        let _guard = scupper_sys::lock::WriterLock::acquire(deps.writer_root)
            .map_err(|_| "secret writer lock unavailable")?;
        SecretFile::prepare_url(deps.config_root, &name, replace)
            .map_err(|error| write_error(&error))?;
        Inventory::read(deps, false)
    };
    input::disable_core_dumps().map_err(str::to_owned)?;
    let value = if io::stdin().is_terminal() {
        input::read_tty(telegram)
    } else {
        eprintln!("reading the secret from stdin (not a terminal); over SSH use `ssh -t` for a hidden prompt");
        input::read_stdin(&mut input::stdin_reader().map_err(str::to_owned)?, telegram)
    }
    .map_err(str::to_owned)?;
    {
        let _guard = scupper_sys::lock::WriterLock::acquire(deps.writer_root)
            .map_err(|_| "secret writer lock unavailable")?;
        // Another writer may have changed the destination while input waited.
        SecretFile::prepare_url(deps.config_root, &name, replace)
            .map_err(|error| write_error(&error))?;
        SecretFile::sweep_url_temps(deps.config_root, started)
            .map_err(|error| write_error(&error))?;
        SecretFile::write_url(deps.config_root, &name, value.expose(), replace)
            .map_err(|error| write_error(&error))?;
    }
    writeln!(out, "{}: {}", name.name(), value.confirmation()).map_err(output_error)?;
    match inventory {
        Ok(inventory) => inventory.next_steps(&name, out)?,
        Err(_) => writeln!(
            out,
            "Could not inspect config references; next-step hint unavailable."
        )
        .map_err(output_error)?,
    }
    Ok(())
}

fn list(deps: &Dependencies<'_>, out: &mut dyn Write) -> Result<(), String> {
    let inventory = Inventory::read(deps, true);
    for entry in SecretFile::list(deps.config_root, rustix::process::geteuid().as_raw())
        .map_err(|_| "cannot inspect secret metadata")?
    {
        if entry.stray {
            writeln!(
                out,
                "{} {:?} {:04o} stray entry; inspect and move it out of secrets/{}",
                kind(entry.kind),
                entry.basename,
                entry.mode,
                kind(entry.kind)
            )
            .map_err(output_error)?;
            continue;
        }
        let referenced = inventory.as_ref().map_or_else(
            |_| "?".to_owned(),
            |inventory| {
                inventory
                    .referenced
                    .contains(&(kind(entry.kind).into(), entry.basename.clone()))
                    .to_string()
            },
        );
        writeln!(
            out,
            "{} {} {:04o} referenced={referenced}{}",
            kind(entry.kind),
            entry.basename,
            entry.mode,
            if entry.unsafe_metadata {
                " unsafe; restore an owned regular 0600 file"
            } else {
                ""
            }
        )
        .map_err(output_error)?;
    }
    Ok(())
}

fn check(text: &str, deps: &Dependencies<'_>, out: &mut dyn Write) -> Result<(), String> {
    let name = reference(text)?;
    input::disable_core_dumps().map_err(str::to_owned)?;
    let owner = rustix::process::geteuid().as_raw();
    let mut checked = Vec::new();
    for secret_kind in [SecretKind::Wg, SecretKind::Url] {
        let name = SecretName::new(secret_kind, name.name()).map_err(|_| "invalid reference")?;
        if !SecretFile::exists(deps.config_root, &name, owner)
            .map_err(|_| "secret check failed: unsafe metadata or invalid content")?
        {
            continue;
        }
        let length = if secret_kind == SecretKind::Url {
            heartbeat::resolve(deps.config_root, &name, "", owner)
                .map_err(|_| "secret check failed: unsafe metadata or invalid content")?
                .expose()
                .len()
        } else {
            SecretFile::open_with_owner(deps.config_root, &name, owner)
                .map_err(|_| "secret check failed: unsafe metadata or invalid content")?
                .expose()
                .len()
        };
        checked.push((secret_kind, length));
    }
    if checked.is_empty() {
        return Err("secret reference not found".into());
    }
    for (secret_kind, length) in checked {
        writeln!(
            out,
            "{} {}: ok length={length}",
            kind(secret_kind),
            name.name()
        )
        .map_err(output_error)?;
    }
    Ok(())
}

fn write_error(error: &io::Error) -> String {
    if error.kind() == io::ErrorKind::AlreadyExists {
        "secret already exists; use --replace".into()
    } else if error.to_string() == "written; durability not confirmed" {
        "secret written; durability not confirmed".into()
    } else {
        "secret write failed; check ownership, modes and directory safety".into()
    }
}
