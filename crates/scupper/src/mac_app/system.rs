//! Small process boundary shared by the macOS adapter and portable fake tests.
use super::{App, AppCommand, MacArgs, MacCommand, ini};
use scupper_core::config::client_profile;
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::{Ipv4Addr, Ipv6Addr},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Output,
    sync::atomic::{AtomicU64, Ordering},
};

const DEFAULTS: &str = "/usr/bin/defaults";
const DOMAIN: &str = "org.m0k.transmission";
const KEY: &str = "BindAddressIPv4";
const KEY6: &str = "BindAddressIPv6";
const PGREP: &str = "/usr/bin/pgrep";
const IFCONFIG: &str = "/sbin/ifconfig";

pub(super) trait Processes {
    fn output(&self, program: &str, args: &[&str]) -> io::Result<Output>;
}
#[cfg(target_os = "macos")]
pub(super) struct Native;
#[cfg(target_os = "macos")]
impl Processes for Native {
    fn output(&self, program: &str, args: &[&str]) -> io::Result<Output> {
        use std::{os::unix::process::ExitStatusExt, process::Command, time::Duration};
        let mut command = Command::new(program);
        command.args(args);
        let result = crate::deploy_process::execute(command, b"", Duration::from_secs(5))
            .map_err(|error| io::Error::other(error.reason))?;
        Ok(Output {
            status: std::process::ExitStatus::from_raw(i32::from(result.code) << 8),
            stdout: result.stdout.into_bytes(),
            stderr: result.stderr.into_bytes(),
        })
    }
}
fn output(process: &impl Processes, program: &str, args: &[&str]) -> Result<Output, String> {
    process
        .output(program, args)
        .map_err(|_| format!("could not run {program} (failed or exceeded 5s deadline)"))
}
fn require_quit(process: &impl Processes, app: App) -> Result<(), String> {
    let name = match app {
        App::Transmission => "Transmission",
        App::Qbittorrent => "qbittorrent",
    };
    match output(process, PGREP, &["-x", name])?.status.code() {
        Some(1) => Ok(()),
        Some(0) => Err(format!(
            "quit {} before binding or unbinding; --yes cannot override this",
            app.name()
        )),
        _ => Err("could not check whether the app is running; refusing changes".into()),
    }
}
pub(super) fn require_user(uid: u32) -> Result<(), String> {
    if uid == 0 {
        return Err("run scupper mac app as your user, without sudo or root".into());
    }
    Ok(())
}
fn profile_address(path: &Path) -> Result<Ipv4Addr, String> {
    read_profile_address(path)
        .map_err(|error| format!("{error}; use --address to specify the tunnel IPv4"))
}
fn read_profile_address(path: &Path) -> Result<Ipv4Addr, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(
            i32::try_from(rustix::fs::OFlags::NONBLOCK.bits()).map_err(|_| "invalid file flags")?,
        )
        .open(path)
        .map_err(|_| "could not open client profile")?;
    if !file
        .metadata()
        .map_err(|_| "could not inspect client profile")?
        .is_file()
    {
        return Err("client profile must be a regular file".into());
    }
    client_profile::read_address(file).map_err(str::to_owned)
}

fn config_path(home: &Path) -> PathBuf {
    home.join(".config/qBittorrent/qBittorrent.ini")
}
fn installed(home: &Path, app: App) -> bool {
    let bundle = match app {
        App::Transmission => "Transmission.app",
        App::Qbittorrent => "qBittorrent.app",
    };
    Path::new("/Applications").join(bundle).is_dir()
        || home.join("Applications").join(bundle).is_dir()
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct TransmissionBinding {
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
}
impl TransmissionBinding {
    fn read(process: &impl Processes) -> Result<Self, String> {
        Ok(Self {
            ipv4: read_preference(process, KEY)?
                .map(|s| s.parse())
                .transpose()
                .map_err(|_| "Transmission IPv4 preference is invalid")?,
            ipv6: read_preference(process, KEY6)?
                .map(|s| s.parse())
                .transpose()
                .map_err(|_| "Transmission IPv6 preference is invalid")?,
        })
    }
    fn values(&self) -> [String; 2] {
        [
            self.ipv4
                .map_or_else(|| "missing".into(), |ip| ip.to_string()),
            self.ipv6
                .map_or_else(|| "missing".into(), |ip| ip.to_string()),
        ]
    }
    fn write_verified(&self, process: &impl Processes, pinning: bool) -> Result<(), String> {
        for (key, value) in [KEY, KEY6].into_iter().zip(self.values()) {
            let args = if value == "missing" {
                vec!["delete", DOMAIN, key]
            } else {
                vec!["write", DOMAIN, key, "-string", &value]
            };
            // A missing key needs no deletion, but other read failures must stop changes.
            if value == "missing" && read_preference(process, key)?.is_none() {
                continue;
            }
            let result = output(process, DEFAULTS, &args).and_then(|result| {
                if result.status.success() {
                    Ok(())
                } else {
                    Err(format!(
                        "could not write Transmission {key}; saved preferences retained"
                    ))
                }
            });
            result.map_err(|error| {
                if key == KEY6 && pinning {
                    format!(
                        "Transmission is partially bound (IPv6 not pinned); rerun bind; {error}"
                    )
                } else {
                    error
                }
            })?;
        }
        if Self::read(process)? != *self {
            return Err(
                "Transmission preferences differ after writing; saved preferences retained".into(),
            );
        }
        Ok(())
    }
}
fn read_preference(process: &impl Processes, key: &str) -> Result<Option<String>, String> {
    let result = output(process, DEFAULTS, &["read", DOMAIN, key])?;
    if !result.status.success() {
        if result.status.code() == Some(1)
            && String::from_utf8_lossy(&result.stderr).contains("does not exist")
        {
            return Ok(None);
        }
        return Err(format!("could not read Transmission {key}"));
    }
    let value = std::str::from_utf8(&result.stdout)
        .map_err(|_| "invalid Transmission preference")?
        .trim();
    Ok(Some(value.into()))
}
fn state_path(home: &Path) -> PathBuf {
    home.join(".config/scupper/transmission-bind.state")
}
fn saved_binding(path: &Path) -> Result<Option<TransmissionBinding>, String> {
    let Some(bytes) = read_state(path, 256, "Transmission")? else {
        return Ok(None);
    };
    let invalid = state_error(path, "Transmission");
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid.clone())?;
    let lines: Vec<_> = text.lines().collect();
    if lines.len() != 2 {
        return Err(invalid);
    }
    Ok(Some(TransmissionBinding {
        ipv4: if lines[0] == "missing" {
            None
        } else {
            Some(lines[0].parse().map_err(|_| invalid.clone())?)
        },
        ipv6: if lines[1] == "missing" {
            None
        } else {
            Some(lines[1].parse().map_err(|_| invalid.clone())?)
        },
    }))
}
fn state_error(path: &Path, app: &str) -> String {
    format!(
        "invalid saved {app} preferences at {}; inspect, then delete this file to recover",
        path.display()
    )
}
fn read_state(path: &Path, limit: u64, app: &str) -> Result<Option<Vec<u8>>, String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(
            i32::try_from((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits())
                .map_err(|_| "invalid file flags")?,
        )
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(state_error(path, app)),
    };
    if !file
        .metadata()
        .map_err(|_| state_error(path, app))?
        .is_file()
    {
        return Err(state_error(path, app));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| state_error(path, app))?;
    if bytes.len() as u64 > limit {
        return Err(state_error(path, app));
    }
    Ok(Some(bytes))
}
fn save_binding(path: &Path, binding: &TransmissionBinding) -> Result<(), String> {
    let [ipv4, ipv6] = binding.values();
    save_state(path, format!("{ipv4}\n{ipv6}\n").as_bytes())
}
fn save_state(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("invalid state path")?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(|_| "could not create binding state directory")?;
    atomic_write(path, bytes, None)
        .map_err(|_| format!("could not save binding preferences at {}", path.display()))
}
fn qbit_state_path(home: &Path) -> PathBuf {
    home.join(".config/scupper/qbittorrent-bind.state")
}
fn saved_qbit_binding(path: &Path) -> Result<Option<[Vec<u8>; 3]>, String> {
    let Some(bytes) = read_state(path, 65536, "qBittorrent")? else {
        return Ok(None);
    };
    let invalid = || state_error(path, "qBittorrent");
    let mut lines = bytes
        .strip_suffix(b"\n")
        .ok_or_else(invalid)?
        .split(|b| *b == b'\n');
    let mut values = [const { Vec::new() }; 3];
    for value in &mut values {
        let line = lines.next().ok_or_else(invalid)?;
        if line.len() % 2 != 0 {
            return Err(invalid());
        }
        for pair in line.as_chunks::<2>().0 {
            let hex = std::str::from_utf8(pair).map_err(|_| invalid())?;
            value.push(u8::from_str_radix(hex, 16).map_err(|_| invalid())?);
        }
        if value.contains(&b'\n') {
            return Err(invalid());
        }
    }
    if lines.next().is_some() {
        return Err(invalid());
    }
    Ok(Some(values))
}
fn save_qbit_binding(path: &Path, values: &[Vec<u8>; 3]) -> Result<(), String> {
    use std::fmt::Write as _;
    let mut text = String::new();
    for value in values {
        for byte in value {
            write!(text, "{byte:02x}").map_err(|_| "could not encode binding preferences")?;
        }
        text.push('\n');
    }
    if text.len() > 65536 {
        return Err("qBittorrent binding preferences exceed state size limit".into());
    }
    save_state(path, text.as_bytes())
}
struct CurrentBinding {
    address: Option<Ipv4Addr>,
    label: String,
    ipv6: String,
    ipv6_unpinned: bool,
}

fn current_binding(
    home: &Path,
    app: App,
    process: &impl Processes,
) -> Result<CurrentBinding, String> {
    match app {
        App::Transmission => {
            let binding = TransmissionBinding::read(process)?;
            let address = binding.ipv4.filter(|ip| !ip.is_unspecified());
            Ok(CurrentBinding {
                address,
                label: address.map_or_else(|| "unbound".into(), |ip| ip.to_string()),
                ipv6: binding
                    .ipv6
                    .map_or_else(|| "default (::)".into(), |ip| ip.to_string()),
                ipv6_unpinned: address.is_some() && binding.ipv6 != Some(Ipv6Addr::LOCALHOST),
            })
        }
        App::Qbittorrent => {
            let bytes = match fs::read(config_path(home)) {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
                Err(_) => return Err("could not read qBittorrent preferences".into()),
            };
            let address = ini::address(&bytes);
            let values = ini::values(&bytes);
            let interface = [values[0].trim_ascii(), values[2].trim_ascii()]
                .into_iter()
                .find(|value| !value.is_empty());
            let raw_address = values[1].trim_ascii();
            let wildcard =
                raw_address.is_empty() || raw_address == b"0.0.0.0" || raw_address == b"::";
            let label = if let Some(interface) = interface {
                format!(
                    "interface {} (address {})",
                    String::from_utf8_lossy(interface),
                    if wildcard {
                        "any".into()
                    } else {
                        String::from_utf8_lossy(raw_address)
                    }
                )
            } else if wildcard {
                "unbound".into()
            } else {
                String::from_utf8_lossy(raw_address).into_owned()
            };
            Ok(CurrentBinding {
                address,
                label,
                ipv6: if interface.is_some() {
                    "interface binding (both families)".into()
                } else if address.is_some() {
                    "disabled (IPv4-only binding)".into()
                } else if wildcard {
                    "unbound".into()
                } else {
                    String::from_utf8_lossy(raw_address).into_owned()
                },
                ipv6_unpinned: false,
            })
        }
    }
}

fn assigned_addresses(process: &impl Processes) -> Result<Vec<(String, Ipv4Addr)>, String> {
    let result = output(process, IFCONFIG, &["-a"])?;
    if !result.status.success() {
        return Err("could not inspect Mac interfaces".into());
    }
    let text = std::str::from_utf8(&result.stdout).map_err(|_| "invalid ifconfig output")?;
    Ok(ifconfig_addresses(text))
}
fn ifconfig_addresses(text: &str) -> Vec<(String, Ipv4Addr)> {
    let mut interface: Option<String> = None;
    let mut addresses = Vec::new();
    for line in text.lines() {
        if line.starts_with(char::is_whitespace) {
            let mut words = line.split_whitespace();
            if words.next() == Some("inet")
                && let Some(ip) = words.next().and_then(|word| word.parse().ok())
                && let Some(name) = &interface
            {
                addresses.push((name.clone(), ip));
            }
        } else {
            interface = line
                .split_once(':')
                .filter(|(name, _)| !name.is_empty() && !name.contains(char::is_whitespace))
                .map(|(name, _)| name.to_owned());
        }
    }
    addresses
}
fn require_tunnel_address(
    address: Ipv4Addr,
    assigned: &[(String, Ipv4Addr)],
) -> Result<(), String> {
    if let Some((name, _)) = assigned
        .iter()
        .find(|(name, ip)| *ip == address && !name.starts_with("utun"))
    {
        return Err(format!(
            "{address} is assigned to non-tunnel interface {name}; choose the tunnel --address"
        ));
    }
    Ok(())
}

pub(super) fn execute(
    args: &MacArgs,
    home: &Path,
    process: &impl Processes,
    out: &mut dyn Write,
) -> Result<u8, String> {
    let MacCommand::App { command } = &args.command;
    match command {
        AppCommand::Status { app } => return status(args, home, process, out, *app),
        AppCommand::Bind { app, address } => {
            require_quit(process, *app)?;
            let address = match address {
                Some(ip) => *ip,
                None => profile_address(
                    &args
                        .profile
                        .clone()
                        .unwrap_or_else(|| home.join(".scupper/scupper0.conf")),
                )?,
            };
            require_tunnel_address(address, &assigned_addresses(process)?)?;
            change(home, *app, Some(address), process, out)?;
            writeln!(out, "{} bound to {address}. Verify once: join the tunnel, start a torrent, then leave the tunnel on a network with IPv6. Transfers must stop before you rely on this binding.", app.name())
                .map_err(|_| "could not write binding result")?;
        }
        AppCommand::Unbind { app } => {
            require_quit(process, *app)?;
            change(home, *app, None, process, out)?;
            writeln!(
                out,
                "{} previous binding restored; it may use the home connection when the tunnel is down",
                app.name()
            )
            .map_err(|_| "could not write binding result")?;
        }
    }
    Ok(0)
}
fn warning(out: &mut dyn Write, app: &str, reason: &str) -> Result<(), String> {
    writeln!(out, "warning: {app}: {reason}").map_err(|_| "could not write status".into())
}
fn status(
    args: &MacArgs,
    home: &Path,
    process: &impl Processes,
    out: &mut dyn Write,
    app: Option<App>,
) -> Result<u8, String> {
    let profile = args
        .profile
        .clone()
        .unwrap_or_else(|| home.join(".scupper/scupper0.conf"));
    let expected = read_profile_address(&profile);
    let assigned = assigned_addresses(process);
    let mut warned = false;
    if let Err(reason) = &expected {
        warning(
            out,
            "profile",
            &format!("unknown ({reason}); use --profile FILE to select a readable client profile"),
        )?;
        warned = true;
    }
    if let Err(reason) = &assigned {
        warning(out, "interfaces", reason)?;
        warned = true;
    }
    let apps = app.map_or_else(
        || vec![App::Transmission, App::Qbittorrent],
        |app| vec![app],
    );
    for app in apps {
        let binding = match current_binding(home, app, process) {
            Ok(binding) => binding,
            Err(reason) => {
                writeln!(out, "{}: error ({reason})", app.name())
                    .map_err(|_| "could not write status")?;
                warning(out, app.name(), &reason)?;
                warned = true;
                continue;
            }
        };
        warned |= status_binding(home, app, &binding, &expected, &assigned, out)?;
    }
    Ok(u8::from(warned))
}

fn status_binding(
    home: &Path,
    app: App,
    binding: &CurrentBinding,
    expected: &Result<Ipv4Addr, String>,
    assigned: &Result<Vec<(String, Ipv4Addr)>, String>,
    out: &mut dyn Write,
) -> Result<bool, String> {
    let mut warned = false;
    let holders: Vec<_> = assigned.as_ref().map_or_else(
        |_| Vec::new(),
        |assigned| {
            assigned
                .iter()
                .filter(|(_, ip)| Some(*ip) == binding.address)
                .collect()
        },
    );
    let non_tunnel = holders.iter().find(|(name, _)| !name.starts_with("utun"));
    let tunnel = if let Some((name, _)) = non_tunnel {
        let reason =
            format!("tunnel NOT USED: {name} holds the bound address; traffic uses this interface");
        warning(out, app.name(), &reason)?;
        warned = true;
        reason
    } else if !holders.is_empty() {
        "tunnel up".into()
    } else if assigned.is_err() || (binding.address.is_none() && binding.label != "unbound") {
        "tunnel unknown".into()
    } else {
        "tunnel down".into()
    };
    let profile = match expected {
        Ok(ip) if binding.address == Some(*ip) => "match".into(),
        Ok(_) => "mismatch".into(),
        Err(reason) => format!("unknown ({reason}); use --profile FILE"),
    };
    let interface = if holders.is_empty() {
        "none".into()
    } else {
        holders
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(",")
    };
    writeln!(
        out,
        "{}: {}; bind {}; profile {}; {}; interface {}; IPv6 {}{}",
        app.name(),
        if installed(home, app) {
            "installed"
        } else {
            "not installed"
        },
        binding.label,
        profile,
        tunnel,
        interface,
        binding.ipv6,
        if binding.ipv6_unpinned {
            "; IPv6 unpinned"
        } else {
            ""
        }
    )
    .map_err(|_| "could not write status")?;
    if binding.ipv6_unpinned {
        warning(out, app.name(), "IPv6 unpinned; rerun bind")?;
        warned = true;
    }
    Ok(warned)
}

fn change(
    home: &Path,
    app: App,
    address: Option<Ipv4Addr>,
    process: &impl Processes,
    out: &mut dyn Write,
) -> Result<(), String> {
    if !installed(home, app) {
        return Err(format!(
            "{} is not installed in /Applications or ~/Applications",
            app.name()
        ));
    }
    match app {
        App::Transmission => {
            require_quit(process, app)?;
            let path = state_path(home);
            let saved = saved_binding(&path)?;
            let desired = if let Some(ipv4) = address {
                let previous = TransmissionBinding::read(process)?;
                if saved.is_none() {
                    save_binding(&path, &previous)?;
                }
                let [ipv4_before, ipv6_before] = saved.as_ref().unwrap_or(&previous).values();
                writeln!(out, "previous Transmission values: {KEY}={ipv4_before}; {KEY6}={ipv6_before}; restore backup: {}", path.display())
                    .map_err(|_| "could not report saved preferences")?;
                TransmissionBinding {
                    ipv4: Some(ipv4),
                    ipv6: Some(Ipv6Addr::LOCALHOST),
                }
            } else {
                saved
                    .clone()
                    .ok_or("no scupper binding to restore; nothing changed")?
            };
            desired.write_verified(process, address.is_some())?;
            if address.is_none() && saved.is_some() {
                fs::remove_file(path)
                    .map_err(|_| "preferences restored but could not remove state file")?;
            }
        }
        App::Qbittorrent => {
            let path = config_path(home);
            let metadata = fs::symlink_metadata(&path).map_err(
                |_| "launch qBittorrent once, then quit it before changing its preferences",
            )?;
            if !metadata.file_type().is_file() {
                return Err("qBittorrent config must be a regular file, not a symlink".into());
            }
            let original = fs::read(&path).map_err(|_| "could not read qBittorrent config")?;
            let state = qbit_state_path(home);
            let saved = saved_qbit_binding(&state)?;
            let already_bound = ini::scupper_binding(&original);
            let edited = if let Some(ip) = address {
                if saved.is_none() {
                    if already_bound {
                        return Err("qBittorrent already holds a scupper binding but no restore state exists; inspect qBittorrent.ini.scupper-backup before changing it".into());
                    }
                    save_qbit_binding(&state, &ini::values(&original))?;
                }
                ini::edit(&original, Some(ip))
            } else {
                let values = saved
                    .as_ref()
                    .ok_or("no scupper binding to restore; nothing changed")?;
                ini::edit_values(&original, &[&values[0], &values[1], &values[2]])
            };
            require_quit(process, app)?;
            replace_config(
                &path,
                &original,
                &edited,
                address.is_some() && !already_bound,
            )
            .map_err(|_| "could not safely replace qBittorrent config")?;
            let verified = fs::read(&path)
                .map_err(|_| "could not verify qBittorrent config; saved preferences retained")?;
            if verified != edited {
                return Err(
                    "qBittorrent preferences differ after writing; saved preferences retained"
                        .into(),
                );
            }
            if address.is_none() {
                fs::remove_file(&state)
                    .map_err(|_| "preferences restored but could not remove state file")?;
            }
        }
    }
    Ok(())
}
fn replace_config(path: &Path, original: &[u8], edited: &[u8], backup: bool) -> io::Result<()> {
    if backup {
        let backup = path.with_file_name("qBittorrent.ini.scupper-backup");
        match fs::symlink_metadata(&backup) {
            Ok(metadata) if !metadata.is_file() => {
                return Err(io::Error::other("backup is not a regular file"));
            }
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
        atomic_write(&backup, original, None)?;
    }
    atomic_write(path, edited, Some(&fs::metadata(path)?))
}
fn atomic_write(path: &Path, bytes: &[u8], metadata: Option<&fs::Metadata>) -> io::Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let temp = path.with_file_name(format!(
        ".scupper-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    let result = (|| {
        file.write_all(bytes)?;
        if let Some(metadata) = metadata {
            let temp_metadata = file.metadata()?;
            if (temp_metadata.uid(), temp_metadata.gid()) != (metadata.uid(), metadata.gid()) {
                rustix::fs::fchown(
                    &file,
                    Some(rustix::process::Uid::from_raw(metadata.uid())),
                    Some(rustix::process::Gid::from_raw(metadata.gid())),
                )?;
            }
            file.set_permissions(metadata.permissions())?;
        }
        file.sync_all()?;
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::{
        cell::RefCell,
        collections::VecDeque,
        os::unix::{fs::PermissionsExt, process::ExitStatusExt},
        process::ExitStatus,
    };
    struct Call {
        program: &'static str,
        args: Vec<String>,
        code: i32,
        stdout: &'static [u8],
        stderr: &'static [u8],
    }
    struct Fake(RefCell<VecDeque<Call>>);
    impl Processes for Fake {
        fn output(&self, program: &str, args: &[&str]) -> io::Result<Output> {
            let call = self.0.borrow_mut().pop_front().unwrap();
            assert_eq!(program, call.program);
            assert_eq!(args, call.args);
            if call.code == -1 {
                return Err(io::Error::other("deadline exceeded"));
            }
            Ok(Output {
                status: ExitStatus::from_raw(call.code << 8),
                stdout: call.stdout.to_vec(),
                stderr: call.stderr.to_vec(),
            })
        }
    }
    fn call(program: &'static str, args: &[&str], code: i32, stdout: &'static [u8]) -> Call {
        Call {
            program,
            args: args.iter().map(|s| (*s).into()).collect(),
            code,
            stdout,
            stderr: b"",
        }
    }
    fn fake(calls: Vec<Call>) -> Fake {
        Fake(RefCell::new(calls.into()))
    }
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target/mac-app-tests")
                .join(format!(
                    "{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            fs::create_dir_all(path.join("Applications/Transmission.app")).unwrap();
            fs::create_dir_all(path.join("Applications/qBittorrent.app")).unwrap();
            fs::create_dir_all(path.join(".config/qBittorrent")).unwrap();
            fs::create_dir_all(path.join(".scupper")).unwrap();
            fs::write(
                path.join(".scupper/scupper0.conf"),
                b"[Interface]\nPrivateKey=NEVER_EXPOSE\nAddress=10.99.0.2/32\n",
            )
            .unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn args(command: AppCommand) -> MacArgs {
        MacArgs {
            profile: None,
            yes: true,
            command: MacCommand::App { command },
        }
    }
    #[test]
    fn running_apps_and_process_errors_refuse_all_changes_even_with_yes() {
        for (app, name) in [
            (App::Transmission, "Transmission"),
            (App::Qbittorrent, "qbittorrent"),
        ] {
            for command in [
                AppCommand::Bind { app, address: None },
                AppCommand::Unbind { app },
            ] {
                let p = fake(vec![call(PGREP, &["-x", name], 0, b"123\n")]);
                let error = execute(
                    &args(command),
                    Path::new("missing-home"),
                    &p,
                    &mut Vec::new(),
                )
                .unwrap_err();
                assert!(error.contains("quit") && error.contains("--yes"));
                assert!(p.0.borrow().is_empty());
            }
        }
        let p = fake(vec![call(PGREP, &["-x", "Transmission"], 2, b"")]);
        assert!(require_quit(&p, App::Transmission).is_err());
    }
    fn read_calls(ipv4: &'static [u8], ipv6: &'static [u8]) -> Vec<Call> {
        vec![
            call(DEFAULTS, &["read", DOMAIN, KEY], 0, ipv4),
            call(DEFAULTS, &["read", DOMAIN, KEY6], 0, ipv6),
        ]
    }
    fn write_calls(ipv4: &str, ipv6: &str) -> Vec<Call> {
        vec![
            call(DEFAULTS, &["write", DOMAIN, KEY, "-string", ipv4], 0, b""),
            call(DEFAULTS, &["write", DOMAIN, KEY6, "-string", ipv6], 0, b""),
        ]
    }
    fn missing(key: &str) -> Call {
        let mut call = call(DEFAULTS, &["read", DOMAIN, key], 1, b"");
        call.stderr = b"The domain/default pair does not exist";
        call
    }
    #[test]
    fn refuses_root_and_profile_errors_suggest_address() {
        assert!(
            require_user(0)
                .unwrap_err()
                .contains("without sudo or root")
        );
        assert!(require_user(501).is_ok());
        assert!(
            profile_address(Path::new("missing-profile"))
                .unwrap_err()
                .contains("--address")
        );
        let home = Fixture::new();
        let path = home.0.join(".scupper/scupper0.conf");
        fs::write(
            &path,
            b"[Interface]\nPrivateKey=NEVER_EXPOSE\nAddress=invalid",
        )
        .unwrap();
        let error = profile_address(&path).unwrap_err();
        assert!(error.contains("--address") && !error.contains("NEVER_EXPOSE"));
    }
    #[test]
    fn transmission_binds_both_families_and_restores_original_across_rebinds() {
        let home = Fixture::new();
        for (index, ip) in ["10.99.0.2", "10.99.0.3"].into_iter().enumerate() {
            let mut calls = vec![
                call(PGREP, &["-x", "Transmission"], 1, b""),
                call(IFCONFIG, &["-a"], 0, b""),
                call(PGREP, &["-x", "Transmission"], 1, b""),
            ];
            calls.extend(if index == 0 {
                read_calls(b"192.168.1.3\n", b"fd00::5\n")
            } else {
                read_calls(b"10.99.0.2\n", b"::1\n")
            });
            calls.extend(write_calls(ip, "::1"));
            calls.extend(read_calls(
                if index == 0 {
                    b"10.99.0.2\n"
                } else {
                    b"10.99.0.3\n"
                },
                b"::1\n",
            ));
            let p = fake(calls);
            let mut out = Vec::new();
            execute(
                &args(AppCommand::Bind {
                    app: App::Transmission,
                    address: Some(ip.parse().unwrap()),
                }),
                &home.0,
                &p,
                &mut out,
            )
            .unwrap();
            let text = String::from_utf8(out).unwrap();
            assert!(text.contains(
                "previous Transmission values: BindAddressIPv4=192.168.1.3; BindAddressIPv6=fd00::5"
            ));
            assert!(
                text.contains("Transfers must stop")
                    && text.contains("network with IPv6")
                    && !text.contains("NEVER_EXPOSE")
            );
            assert!(p.0.borrow().is_empty());
            assert_eq!(
                fs::read_to_string(state_path(&home.0)).unwrap(),
                "192.168.1.3\nfd00::5\n"
            );
            assert_eq!(
                fs::metadata(state_path(&home.0)).unwrap().mode() & 0o777,
                0o600
            );
        }
        let mut calls = vec![
            call(PGREP, &["-x", "Transmission"], 1, b""),
            call(PGREP, &["-x", "Transmission"], 1, b""),
        ];
        calls.extend(write_calls("192.168.1.3", "fd00::5"));
        calls.extend(read_calls(b"192.168.1.3\n", b"fd00::5\n"));
        let p = fake(calls);
        execute(
            &args(AppCommand::Unbind {
                app: App::Transmission,
            }),
            &home.0,
            &p,
            &mut Vec::new(),
        )
        .unwrap();
        assert!(!state_path(&home.0).exists());
        assert!(p.0.borrow().is_empty());
    }
    #[test]
    fn transmission_missing_keys_restore_as_missing_and_failed_readback_keeps_backup() {
        let home = Fixture::new();
        let mut calls = vec![
            call(PGREP, &["-x", "Transmission"], 1, b""),
            missing(KEY),
            missing(KEY6),
        ];
        calls.extend(write_calls("10.99.0.2", "::1"));
        calls.extend(read_calls(b"10.99.0.2\n", b"::\n"));
        let error = change(
            &home.0,
            App::Transmission,
            Some("10.99.0.2".parse().unwrap()),
            &fake(calls),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(error.contains("differ after writing"));
        assert_eq!(
            fs::read_to_string(state_path(&home.0)).unwrap(),
            "missing\nmissing\n"
        );
        let mut calls = vec![call(PGREP, &["-x", "Transmission"], 1, b"")];
        for key in [KEY, KEY6] {
            calls.push(call(DEFAULTS, &["read", DOMAIN, key], 0, b"::1\n"));
            calls.push(call(DEFAULTS, &["delete", DOMAIN, key], 0, b""));
        }
        calls.extend([missing(KEY), missing(KEY6)]);
        change(
            &home.0,
            App::Transmission,
            None,
            &fake(calls),
            &mut Vec::new(),
        )
        .unwrap();
        assert!(!state_path(&home.0).exists());
        assert!(
            read_preference(
                &fake(vec![call(DEFAULTS, &["read", DOMAIN, KEY], 2, b"")]),
                KEY
            )
            .is_err()
        );
    }
    #[test]
    fn transmission_without_backup_refuses_to_overwrite_user_preferences() {
        let home = Fixture::new();
        let p = fake(vec![call(PGREP, &["-x", "Transmission"], 1, b"")]);
        let error = change(&home.0, App::Transmission, None, &p, &mut Vec::new()).unwrap_err();
        assert!(error.contains("no scupper binding to restore; nothing changed"));
        assert!(p.0.borrow().is_empty());
    }
    #[test]
    fn saved_state_and_defaults_failures_stop_changes() {
        let home = Fixture::new();
        let path = state_path(&home.0);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"corrupt").unwrap();
        let p = fake(vec![call(PGREP, &["-x", "Transmission"], 1, b"")]);
        assert!(
            change(&home.0, App::Transmission, None, &p, &mut Vec::new())
                .unwrap_err()
                .contains("invalid saved")
        );
        assert!(p.0.borrow().is_empty());
        fs::remove_file(&path).unwrap();
        let ip = "10.99.0.2".parse().unwrap();
        let mut calls = vec![call(PGREP, &["-x", "Transmission"], 1, b"")];
        calls.extend(read_calls(b"0.0.0.0\n", b"::\n"));
        calls.push(call(
            DEFAULTS,
            &["write", DOMAIN, KEY, "-string", "10.99.0.2"],
            1,
            b"",
        ));
        let p = fake(calls);
        assert!(change(&home.0, App::Transmission, Some(ip), &p, &mut Vec::new()).is_err());
        assert!(p.0.borrow().is_empty());
        assert_eq!(
            saved_binding(&path).unwrap(),
            Some(TransmissionBinding {
                ipv4: Some(Ipv4Addr::UNSPECIFIED),
                ipv6: Some(Ipv6Addr::UNSPECIFIED)
            })
        );
        assert!(
            require_quit(
                &fake(vec![call(PGREP, &["-x", "Transmission"], 255, b"")]),
                App::Transmission
            )
            .is_err()
        );
    }
    #[test]
    fn refuses_home_addresses_before_changing_preferences() {
        let home = Fixture::new();
        for app in [App::Transmission, App::Qbittorrent] {
            for address in [None, Some("10.99.0.2".parse().unwrap())] {
                let name = if app == App::Transmission {
                    "Transmission"
                } else {
                    "qbittorrent"
                };
                let p = fake(vec![call(PGREP, &["-x", name], 1, b""),
                    call(IFCONFIG, &["-a"], 0, b"utun4: flags=8051\n\tinet 10.99.0.2 netmask 0xffffffff\nen0: flags=8863\n\tinet 10.99.0.2 netmask 0xffffff00\n")]);
                let error = execute(
                    &args(AppCommand::Bind { app, address }),
                    &home.0,
                    &p,
                    &mut Vec::new(),
                )
                .unwrap_err();
                assert!(error.contains("non-tunnel interface en0"));
                assert!(p.0.borrow().is_empty());
                assert!(!state_path(&home.0).exists());
                assert!(!config_path(&home.0).exists());
            }
        }
    }
    #[test]
    fn qbit_rebind_restores_original_raw_values_and_preserves_metadata() {
        let home = Fixture::new();
        let path = config_path(&home.0);
        let original = b"[General]\r\nx=\xff\r\n[BitTorrent]\r\nSession\\Interface=utun7\r\nSession\\InterfaceAddress=10.7.0.2\r\nSession\\InterfaceName=old\xff\r\n";
        fs::write(&path, original).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        let original_values = ini::values(original);
        let mut first_state = None;
        for address in [
            Some("100.64.1.2".parse().unwrap()),
            Some("10.99.0.2".parse().unwrap()),
            None,
        ] {
            let p = fake(vec![call(PGREP, &["-x", "qbittorrent"], 1, b"")]);
            change(&home.0, App::Qbittorrent, address, &p, &mut Vec::new()).unwrap();
            let after_bytes = fs::read(&path).unwrap();
            if address.is_some() {
                assert_eq!(ini::address(&after_bytes), address);
                let state = fs::read(qbit_state_path(&home.0)).unwrap();
                if let Some(first) = &first_state {
                    assert_eq!(&state, first);
                } else {
                    first_state = Some(state);
                }
                assert_eq!(
                    saved_qbit_binding(&qbit_state_path(&home.0)).unwrap(),
                    Some(original_values.clone())
                );
                assert_eq!(
                    fs::metadata(qbit_state_path(&home.0)).unwrap().mode() & 0o777,
                    0o600
                );
            } else {
                assert_eq!(ini::values(&after_bytes), original_values);
                assert_eq!(after_bytes, original);
                assert!(!qbit_state_path(&home.0).exists());
            }
            assert_eq!(
                fs::read(path.with_file_name("qBittorrent.ini.scupper-backup")).unwrap(),
                original
            );
            let after = fs::metadata(&path).unwrap();
            assert_eq!(
                (after.uid(), after.gid(), after.mode()),
                (metadata.uid(), metadata.gid(), metadata.mode())
            );
        }
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 2);
    }
    #[test]
    fn qbit_refuses_symlink_config_and_backup_without_changes() {
        use std::os::unix::fs::symlink;
        let home = Fixture::new();
        let path = config_path(&home.0);
        let target = home.0.join("untouched");
        fs::write(&target, b"untouched").unwrap();
        symlink(&target, &path).unwrap();
        assert!(
            change(
                &home.0,
                App::Qbittorrent,
                Some("10.99.0.2".parse().unwrap()),
                &fake(vec![]),
                &mut Vec::new()
            )
            .is_err()
        );
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"[General]\nx=1\n").unwrap();
        symlink(
            &target,
            path.with_file_name("qBittorrent.ini.scupper-backup"),
        )
        .unwrap();
        let p = fake(vec![call(PGREP, &["-x", "qbittorrent"], 1, b"")]);
        assert!(
            change(
                &home.0,
                App::Qbittorrent,
                Some("10.99.0.2".parse().unwrap()),
                &p,
                &mut Vec::new()
            )
            .is_err()
        );
        assert_eq!(fs::read(&target).unwrap(), b"untouched");
        assert_eq!(fs::read(&path).unwrap(), b"[General]\nx=1\n");
    }
    #[test]
    fn status_warns_when_home_interface_holds_the_bound_address() {
        let home = Fixture::new();
        fs::write(
            config_path(&home.0),
            b"[BitTorrent]\nSession\\InterfaceAddress=10.99.0.2\n",
        )
        .unwrap();
        for app in [App::Transmission, App::Qbittorrent] {
            let mut calls = vec![call(IFCONFIG, &["-a"], 0,
                b"en0: flags=8863\n\tinet 10.99.0.2 netmask 0xffffff00\nutun4: flags=1\n\tinet 10.99.0.2 netmask 0xffffffff\n")];
            if app == App::Transmission {
                calls.extend(read_calls(b"10.99.0.2\n", b"::1\n"));
            }
            let p = fake(calls);
            let mut out = Vec::new();
            let code = execute(
                &args(AppCommand::Status { app: Some(app) }),
                &home.0,
                &p,
                &mut out,
            )
            .unwrap();
            let text = String::from_utf8(out).unwrap();
            assert_eq!(code, 1);
            assert!(text.contains("tunnel NOT USED: en0 holds the bound address"));
            assert!(text.contains(&format!("warning: {}:", app.name())));
            assert!(!text.contains("tunnel down") && !text.contains("tunnel up"));
            assert!(p.0.borrow().is_empty());
        }
    }
    #[test]
    fn status_checks_the_bound_address_and_profile_match_independently() {
        let home = Fixture::new();
        fs::write(
            config_path(&home.0),
            b"[BitTorrent]\nSession\\InterfaceAddress=100.64.1.2\n",
        )
        .unwrap();
        let p = fake(vec![call(IFCONFIG, &["-a"], 0, b"utun4: flags=8051\n\tinet 10.99.0.2 netmask 0xffffffff\n\tinet6 fd00::2 prefixlen 128\n"), call(DEFAULTS, &["read", DOMAIN, KEY], 0, b"10.99.0.2\n"), call(DEFAULTS, &["read", DOMAIN, KEY6], 0, b"::1\n")]);
        let mut out = Vec::new();
        assert_eq!(
            execute(
                &args(AppCommand::Status { app: None }),
                &home.0,
                &p,
                &mut out,
            )
            .unwrap(),
            0
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("transmission: installed; bind 10.99.0.2; profile match; tunnel up"));
        assert!(
            text.contains("qbittorrent: installed; bind 100.64.1.2; profile mismatch; tunnel down")
        );
        assert!(text.contains("interface utun4; IPv6 ::1"));
        assert!(text.contains("IPv6 disabled (IPv4-only binding)"));
        assert!(!text.contains("NEVER_EXPOSE"));
        assert_eq!(
            ifconfig_addresses("inet6 ::1\n inet 127.0.0.1 netmask 0xff\n"),
            Vec::<(String, Ipv4Addr)>::new()
        );
    }
    #[test]
    fn transmission_ipv6_write_failure_reports_partial_binding_and_retains_state() {
        for code in [1, -1] {
            let home = Fixture::new();
            let mut calls = vec![call(PGREP, &["-x", "Transmission"], 1, b"")];
            calls.extend(read_calls(b"0.0.0.0\n", b"::\n"));
            calls.extend(write_calls("10.99.0.2", "::1"));
            calls.last_mut().unwrap().code = code;
            let p = fake(calls);
            let error = change(
                &home.0,
                App::Transmission,
                Some("10.99.0.2".parse().unwrap()),
                &p,
                &mut Vec::new(),
            )
            .unwrap_err();
            assert!(
                error.contains("Transmission is partially bound (IPv6 not pinned); rerun bind")
            );
            assert_eq!(
                fs::read_to_string(state_path(&home.0)).unwrap(),
                "0.0.0.0\n::\n"
            );
            assert!(p.0.borrow().is_empty());
        }
    }
    #[test]
    fn profile_file_rejects_oversize_fifo_and_directory_without_blocking() {
        let home = Fixture::new();
        let path = home.0.join("profile");
        fs::write(&path, vec![b'x'; 16 * 1024 + 1]).unwrap();
        assert!(
            read_profile_address(&path)
                .unwrap_err()
                .contains("exceeds 16 KiB")
        );
        fs::remove_file(&path).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            read_profile_address(&path)
                .unwrap_err()
                .contains("regular file")
        );
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(
            read_profile_address(&path)
                .unwrap_err()
                .contains("regular file")
        );
    }
    #[test]
    fn status_flags_unpinned_ipv6_only_when_ipv4_is_bound() {
        let home = Fixture::new();
        for ipv4 in [b"10.99.0.2\n".as_slice(), b"0.0.0.0\n"] {
            for ipv6 in [Some(b"::\n".as_slice()), Some(b"fd00::2\n"), None] {
                let mut calls = vec![call(
                    IFCONFIG,
                    &["-a"],
                    0,
                    b"utun4: flags=1\n\tinet 10.99.0.2 netmask 0xffffffff\n",
                )];
                calls.push(call(DEFAULTS, &["read", DOMAIN, KEY], 0, ipv4));
                calls.push(ipv6.map_or_else(
                    || missing(KEY6),
                    |ip| call(DEFAULTS, &["read", DOMAIN, KEY6], 0, ip),
                ));
                let p = fake(calls);
                let mut out = Vec::new();
                let code = execute(
                    &args(AppCommand::Status {
                        app: Some(App::Transmission),
                    }),
                    &home.0,
                    &p,
                    &mut out,
                )
                .unwrap();
                let text = String::from_utf8(out).unwrap();
                let bound = ipv4 == b"10.99.0.2\n";
                assert_eq!(code, u8::from(bound));
                assert_eq!(text.contains("IPv6 unpinned"), bound);
                assert_eq!(text.contains("warning:"), bound);
            }
        }
    }
    #[test]
    fn status_profile_error_keeps_app_lines_and_suggests_profile() {
        let home = Fixture::new();
        for invalid in [false, true] {
            let profile = home.0.join(".scupper/scupper0.conf");
            if invalid {
                fs::write(&profile, b"PrivateKey=NEVER_EXPOSE").unwrap();
            } else {
                fs::remove_file(&profile).unwrap();
            }
            let mut calls = vec![call(IFCONFIG, &["-a"], 0, b"")];
            calls.extend(read_calls(b"10.99.0.2\n", b"::1\n"));
            let mut out = Vec::new();
            assert_eq!(
                execute(
                    &args(AppCommand::Status { app: None }),
                    &home.0,
                    &fake(calls),
                    &mut out
                )
                .unwrap(),
                1
            );
            let text = String::from_utf8(out).unwrap();
            assert!(text.contains("transmission: installed; bind 10.99.0.2; profile unknown ("));
            assert!(text.contains("qbittorrent: installed; bind unbound; profile unknown ("));
            assert!(
                text.contains("--profile")
                    && !text.contains("--address")
                    && !text.contains("NEVER_EXPOSE")
            );
        }
    }
    #[test]
    fn status_prints_app_and_interface_errors_and_continues() {
        let home = Fixture::new();
        fs::create_dir(config_path(&home.0)).unwrap();
        let p = fake(vec![
            call(IFCONFIG, &["-a"], 1, b""),
            call(DEFAULTS, &["read", DOMAIN, KEY], 2, b""),
        ]);
        let mut out = Vec::new();
        assert_eq!(
            execute(
                &args(AppCommand::Status { app: None }),
                &home.0,
                &p,
                &mut out
            )
            .unwrap(),
            1
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("transmission: error (could not read Transmission"));
        assert!(text.contains("qbittorrent: error (could not read qBittorrent"));
        assert!(text.contains("warning: interfaces:"));
        assert!(p.0.borrow().is_empty());
    }
    #[test]
    fn qbit_status_handles_wildcards_and_interface_only_bindings() {
        let home = Fixture::new();
        for ip in ["0.0.0.0", "::", ""] {
            for interface in ["", "utun7"] {
                fs::write(config_path(&home.0), format!("[BitTorrent]\nSession\\Interface={interface}\nSession\\InterfaceAddress={ip}\n")).unwrap();
                let mut out = Vec::new();
                let p = fake(vec![call(IFCONFIG, &["-a"], 0, b"")]);
                assert_eq!(
                    execute(
                        &args(AppCommand::Status {
                            app: Some(App::Qbittorrent)
                        }),
                        &home.0,
                        &p,
                        &mut out
                    )
                    .unwrap(),
                    0
                );
                let text = String::from_utf8(out).unwrap();
                if interface.is_empty() {
                    assert!(text.contains("bind unbound;") && text.contains("IPv6 unbound"));
                } else {
                    assert!(
                        text.contains("bind interface utun7 (address any);")
                            && text.contains("both families")
                    );
                    assert!(text.contains("tunnel unknown"));
                }
                assert!(!text.contains("IPv4-only binding"));
            }
        }
    }
    #[test]
    fn qbit_existing_scupper_binding_without_state_is_not_saved_as_original() {
        let home = Fixture::new();
        let path = config_path(&home.0);
        let original = b"[BitTorrent]\nSession\\InterfaceAddress=10.99.0.2\n";
        fs::write(&path, original).unwrap();
        let error = change(
            &home.0,
            App::Qbittorrent,
            Some("10.99.0.3".parse().unwrap()),
            &fake(vec![]),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(error.contains("no restore state exists"));
        assert!(!qbit_state_path(&home.0).exists());
        assert_eq!(fs::read(path).unwrap(), original);
    }
    #[test]
    fn transmission_restore_reports_failure_to_remove_state() {
        struct RemovalFailure {
            fake: Fake,
            path: PathBuf,
        }
        impl Processes for RemovalFailure {
            fn output(&self, program: &str, args: &[&str]) -> io::Result<Output> {
                let result = self.fake.output(program, args)?;
                if args == ["read", DOMAIN, KEY6] {
                    fs::remove_file(&self.path)?;
                    fs::create_dir(&self.path)?;
                }
                Ok(result)
            }
        }
        let home = Fixture::new();
        let path = state_path(&home.0);
        save_binding(
            &path,
            &TransmissionBinding {
                ipv4: Some(Ipv4Addr::UNSPECIFIED),
                ipv6: Some(Ipv6Addr::UNSPECIFIED),
            },
        )
        .unwrap();
        let mut calls = vec![call(PGREP, &["-x", "Transmission"], 1, b"")];
        calls.extend(write_calls("0.0.0.0", "::"));
        calls.extend(read_calls(b"0.0.0.0\n", b"::\n"));
        let p = RemovalFailure {
            fake: fake(calls),
            path,
        };
        let error = change(&home.0, App::Transmission, None, &p, &mut Vec::new()).unwrap_err();
        assert!(error.contains("preferences restored but could not remove state file"));
        assert!(p.fake.0.borrow().is_empty());
    }

    #[test]
    fn qbit_empty_original_values_and_invalid_restore_state() {
        let home = Fixture::new();
        let path = config_path(&home.0);
        let original = b"[BitTorrent]\nSession\\Interface=\nSession\\InterfaceAddress=\nSession\\InterfaceName=\n";
        fs::write(&path, original).unwrap();
        let p = fake(vec![call(PGREP, &["-x", "qbittorrent"], 1, b"")]);
        change(
            &home.0,
            App::Qbittorrent,
            Some("10.99.0.2".parse().unwrap()),
            &p,
            &mut Vec::new(),
        )
        .unwrap();
        let state = qbit_state_path(&home.0);
        assert_eq!(fs::read(&state).unwrap(), b"\n\n\n");
        let bound = fs::read(&path).unwrap();
        for invalid in [
            b"zz\n\n\n".as_slice(),
            b"0\n\n\n",
            b"00\n",
            b"0a\n\n\n",
            b"\n\n\n\n",
        ] {
            fs::write(&state, invalid).unwrap();
            let error = change(
                &home.0,
                App::Qbittorrent,
                None,
                &fake(vec![]),
                &mut Vec::new(),
            )
            .unwrap_err();
            assert!(
                error.contains(&state.display().to_string())
                    && error.contains("inspect, then delete")
            );
            assert_eq!(fs::read(&path).unwrap(), bound);
            assert_eq!(fs::read(&state).unwrap(), invalid);
        }
        fs::write(&state, b"\n\n\n").unwrap();
        let p = fake(vec![call(PGREP, &["-x", "qbittorrent"], 1, b"")]);
        change(&home.0, App::Qbittorrent, None, &p, &mut Vec::new()).unwrap();
        assert_eq!(fs::read(path).unwrap(), original);
        assert!(!state.exists());
    }
}
