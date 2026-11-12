//! Small process boundary shared by the macOS adapter and portable fake tests.
use super::{App, AppCommand, MacArgs, MacCommand, ini};
use scupper_core::config::client_profile;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    net::Ipv4Addr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::Output,
    sync::atomic::{AtomicU64, Ordering},
};

const DEFAULTS: &str = "/usr/bin/defaults";
const DOMAIN: &str = "org.m0k.transmission";
const KEY: &str = "BindAddressIPv4";
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
        std::process::Command::new(program).args(args).output()
    }
}
fn output(process: &impl Processes, program: &str, args: &[&str]) -> Result<Output, String> {
    process
        .output(program, args)
        .map_err(|_| format!("could not run {program}"))
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
fn profile_address(path: &Path) -> Result<Ipv4Addr, String> {
    let file = fs::File::open(path).map_err(|_| "could not open client profile")?;
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
fn transmission_address(process: &impl Processes) -> Result<Option<Ipv4Addr>, String> {
    let result = output(process, DEFAULTS, &["read", DOMAIN, KEY])?;
    if !result.status.success() {
        // defaults uses exit 1 for a missing domain/key. Other failures fail closed.
        if result.status.code() == Some(1)
            && String::from_utf8_lossy(&result.stderr).contains("does not exist")
        {
            return Ok(None);
        }
        return Err("could not read Transmission bind preference".into());
    }
    let ip: Ipv4Addr = std::str::from_utf8(&result.stdout)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .ok_or("Transmission bind preference is not an IPv4 address")?;
    Ok((!ip.is_unspecified()).then_some(ip))
}
fn current_address(
    home: &Path,
    app: App,
    process: &impl Processes,
) -> Result<Option<Ipv4Addr>, String> {
    match app {
        App::Transmission => transmission_address(process),
        App::Qbittorrent => match fs::read(config_path(home)) {
            Ok(bytes) => Ok(ini::address(&bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err("could not read qBittorrent preferences".into()),
        },
    }
}
fn assigned_addresses(process: &impl Processes) -> Result<Vec<Ipv4Addr>, String> {
    let result = output(process, IFCONFIG, &["-a"])?;
    if !result.status.success() {
        return Err("could not inspect Mac interfaces".into());
    }
    let text = std::str::from_utf8(&result.stdout).map_err(|_| "invalid ifconfig output")?;
    Ok(ifconfig_addresses(text))
}
fn ifconfig_addresses(text: &str) -> Vec<Ipv4Addr> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("inet"))
                .then(|| words.next().and_then(|word| word.parse().ok()))
                .flatten()
        })
        .collect()
}

pub(super) fn execute(
    args: &MacArgs,
    home: &Path,
    process: &impl Processes,
    out: &mut dyn Write,
) -> Result<(), String> {
    let MacCommand::App { command } = &args.command;
    match command {
        AppCommand::Status { app } => {
            let profile = args
                .profile
                .clone()
                .unwrap_or_else(|| home.join(".scupper/scupper0.conf"));
            let expected = profile_address(&profile)?;
            let assigned = assigned_addresses(process)?;
            let apps = app.map_or_else(
                || vec![App::Transmission, App::Qbittorrent],
                |app| vec![app],
            );
            for app in apps {
                let installed = installed(home, app);
                let address = current_address(home, app, process)?;
                let matches = address == Some(expected);
                let up = address.is_some_and(|a| assigned.contains(&a));
                writeln!(
                    out,
                    "{}: {}; bind {}; profile {}; tunnel {}",
                    app.name(),
                    if installed {
                        "installed"
                    } else {
                        "not installed"
                    },
                    address.map_or_else(|| "unbound".into(), |a| a.to_string()),
                    if matches { "match" } else { "mismatch" },
                    if up { "up" } else { "down" }
                )
                .map_err(|_| "could not write status")?;
            }
        }
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
            change(home, *app, Some(address), process)?;
            writeln!(out, "{} bound to {address}. Verify once: join the tunnel, start a torrent, then leave the tunnel. Transfers must stop before you rely on this binding.", app.name())
                .map_err(|_| "could not write binding result")?;
        }
        AppCommand::Unbind { app } => {
            require_quit(process, *app)?;
            change(home, *app, None, process)?;
            writeln!(
                out,
                "{} unbound; it can use the home connection when the tunnel is down",
                app.name()
            )
            .map_err(|_| "could not write binding result")?;
        }
    }
    Ok(())
}
fn change(
    home: &Path,
    app: App,
    address: Option<Ipv4Addr>,
    process: &impl Processes,
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
            let value = address.map_or_else(|| "0.0.0.0".into(), |a| a.to_string());
            let result = output(
                process,
                DEFAULTS,
                &["write", DOMAIN, KEY, "-string", &value],
            )?;
            if !result.status.success() {
                return Err("could not write Transmission bind preference".into());
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
            let edited = ini::edit(&original, address);
            require_quit(process, app)?;
            replace_config(&path, &original, &edited)
                .map_err(|_| "could not safely replace qBittorrent config")?;
        }
    }
    Ok(())
}
fn replace_config(path: &Path, original: &[u8], edited: &[u8]) -> io::Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let backup = path.with_file_name("qBittorrent.ini.scupper-backup");
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&backup)
    {
        Ok(mut file) => {
            if let Err(error) = file.write_all(original).and_then(|()| file.sync_all()) {
                drop(file);
                let _ = fs::remove_file(&backup);
                return Err(error);
            }
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            if !fs::symlink_metadata(&backup)?.file_type().is_file() {
                return Err(io::Error::other("backup is not a regular file"));
            }
        }
        Err(e) => return Err(e),
    }
    let temp = path.with_file_name(format!(
        ".qBittorrent.ini.scupper-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    let result = (|| {
        file.write_all(edited)?;
        file.set_permissions(fs::metadata(path)?.permissions())?;
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
        cell::RefCell, collections::VecDeque, os::unix::process::ExitStatusExt, process::ExitStatus,
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
            fs::remove_dir_all(&self.0).unwrap();
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
    #[test]
    fn transmission_defaults_use_constant_argv_and_validated_address() {
        let home = Fixture::new();
        for address in [Some("10.99.0.2".parse::<Ipv4Addr>().unwrap()), None] {
            let value = if address.is_some() {
                "10.99.0.2"
            } else {
                "0.0.0.0"
            };
            let p = fake(vec![
                call(PGREP, &["-x", "Transmission"], 1, b""),
                call(PGREP, &["-x", "Transmission"], 1, b""),
                call(DEFAULTS, &["write", DOMAIN, KEY, "-string", value], 0, b""),
            ]);
            let command = if address.is_some() {
                AppCommand::Bind {
                    app: App::Transmission,
                    address: None,
                }
            } else {
                AppCommand::Unbind {
                    app: App::Transmission,
                }
            };
            let mut out = Vec::new();
            execute(&args(command), &home.0, &p, &mut out).unwrap();
            assert!(!String::from_utf8_lossy(&out).contains("NEVER_EXPOSE"));
            if address.is_some() {
                assert!(String::from_utf8_lossy(&out).contains("Transfers must stop"));
            }
            assert!(p.0.borrow().is_empty());
        }
        let mut missing = call(DEFAULTS, &["read", DOMAIN, KEY], 1, b"");
        missing.stderr = b"The domain/default pair does not exist";
        assert_eq!(transmission_address(&fake(vec![missing])).unwrap(), None);
        assert!(
            transmission_address(&fake(vec![call(DEFAULTS, &["read", DOMAIN, KEY], 2, b"")]))
                .is_err()
        );
    }
    #[test]
    fn qbit_atomic_replacement_keeps_original_backup_and_unrelated_bytes() {
        let home = Fixture::new();
        let path = config_path(&home.0);
        let original = b"[General]\r\nx=\xff\r\n";
        fs::write(&path, original).unwrap();
        for address in [Some("100.64.1.2".parse().unwrap()), None] {
            let p = fake(vec![call(PGREP, &["-x", "qbittorrent"], 1, b"")]);
            change(&home.0, App::Qbittorrent, address, &p).unwrap();
            assert_eq!(ini::address(&fs::read(&path).unwrap()), address);
            assert!(fs::read(&path).unwrap().starts_with(original));
            assert_eq!(
                fs::read(path.with_file_name("qBittorrent.ini.scupper-backup")).unwrap(),
                original
            );
        }
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 2);
    }
    #[test]
    fn status_checks_the_bound_address_and_profile_match_independently() {
        let home = Fixture::new();
        fs::write(
            config_path(&home.0),
            b"[BitTorrent]\nSession\\InterfaceAddress=100.64.1.2\n",
        )
        .unwrap();
        let p = fake(vec![call(IFCONFIG, &["-a"], 0, b"utun4: flags=8051\n\tinet 10.99.0.2 netmask 0xffffffff\n\tinet6 fd00::2 prefixlen 128\n"), call(DEFAULTS, &["read", DOMAIN, KEY], 0, b"10.99.0.2\n")]);
        let mut out = Vec::new();
        execute(
            &args(AppCommand::Status { app: None }),
            &home.0,
            &p,
            &mut out,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("transmission: installed; bind 10.99.0.2; profile match; tunnel up"));
        assert!(
            text.contains("qbittorrent: installed; bind 100.64.1.2; profile mismatch; tunnel down")
        );
        assert!(!text.contains("NEVER_EXPOSE"));
        assert_eq!(
            ifconfig_addresses("inet6 ::1\n inet 127.0.0.1 netmask 0xff\n"),
            vec![Ipv4Addr::LOCALHOST]
        );
    }
}
