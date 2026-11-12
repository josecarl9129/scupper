//! Gateway secret provisioning; command arguments contain references only.
use super::{Dependencies, output_error, require_root};
use clap::Subcommand;
use scupper_core::config::{SecretKind, SecretName, SiteConfig, parse_site};
use scupper_sys::{
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
    /// Resolve REF and print ok and the value length only.
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
    fn read(deps: &Dependencies<'_>) -> Result<Self, String> {
        let store = VersionStore::read_only(deps.state_root, deps.config_root);
        let head = store.head().map_err(|_| "cannot inspect config head")?;
        let mut result = Self {
            referenced: BTreeSet::new(),
            head: None,
        };
        for version in 1..=head.unwrap_or(0) {
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
            if self
                .referenced
                .contains(&(kind(name.kind()).into(), name.name().into()))
            {
                writeln!(
                    out,
                    "Only historical config versions reference this ref; use scupper config edit."
                )
                .map_err(output_error)?;
            } else {
                writeln!(
                    out,
                    "No config version references this ref; use scupper config edit."
                )
                .map_err(output_error)?;
            }
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
    require_root(deps, "secret")?;
    match command {
        SecretCommand::Set { command } => {
            let telegram = matches!(command, SetCommand::Telegram { .. });
            let (text, replace) = match command {
                SetCommand::Url { reference, replace }
                | SetCommand::Telegram { reference, replace } => (reference, replace),
            };
            let name = reference(&text)?;
            let value = if io::stdin().is_terminal() {
                input::read_tty(telegram)
            } else {
                input::read_stdin(&mut io::stdin().lock(), telegram)
            }
            .map_err(str::to_owned)?;
            let _guard = scupper_sys::lock::WriterLock::acquire(deps.writer_root)
                .map_err(|_| "secret writer lock unavailable")?;
            let inventory = Inventory::read(deps)?;
            SecretFile::write_url(deps.config_root, &name, value.expose(), replace).map_err(
                |error| {
                    if error.kind() == io::ErrorKind::AlreadyExists {
                        "secret already exists; use --replace".to_owned()
                    } else {
                        "secret write failed; check ownership, modes and directory safety"
                            .to_owned()
                    }
                },
            )?;
            writeln!(out, "{}: {}", name.name(), value.confirmation()).map_err(output_error)?;
            inventory.next_steps(&name, out)?;
        }
        SecretCommand::List => {
            let inventory = Inventory::read(deps)?;
            for entry in SecretFile::list(deps.config_root, rustix::process::geteuid().as_raw())
                .map_err(|_| "cannot inspect secret metadata")?
            {
                let referenced = inventory
                    .referenced
                    .contains(&(kind(entry.name.kind()).into(), entry.name.name().into()));
                writeln!(
                    out,
                    "{} {} {:04o} referenced={referenced}",
                    kind(entry.name.kind()),
                    entry.name.name(),
                    entry.mode
                )
                .map_err(output_error)?;
            }
        }
        SecretCommand::Check { reference: text } => {
            let name = reference(&text)?;
            let entries = SecretFile::list(deps.config_root, rustix::process::geteuid().as_raw())
                .map_err(|_| "cannot inspect secret metadata")?;
            let matches: Vec<_> = entries
                .iter()
                .filter(|e| e.name.name() == name.name())
                .collect();
            if matches.is_empty() {
                return Err("secret reference not found".into());
            }
            // Resolve all matching kinds before printing success for any of them.
            let values: Vec<_> = matches
                .iter()
                .map(|e| {
                    SecretFile::open_with_owner(
                        deps.config_root,
                        &e.name,
                        rustix::process::geteuid().as_raw(),
                    )
                })
                .collect::<Result<_, _>>()
                .map_err(|_| "secret check failed: unsafe metadata or invalid content")?;
            for (entry, value) in matches.iter().zip(values) {
                writeln!(
                    out,
                    "{} {}: ok length={}",
                    kind(entry.name.kind()),
                    name.name(),
                    value.expose().len()
                )
                .map_err(output_error)?;
            }
        }
    }
    Ok(0)
}
