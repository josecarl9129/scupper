//! Read-only host facts for installation.
use super::{
    BTreeMap, EXEC_TIMEOUT, Facts, Paths, Program, Refusal, System, VersionStore, command, config,
    input, io, model, optional, stdfs, version,
};
pub(super) fn observe(system: &dyn System, paths: &Paths) -> Result<Facts, Refusal> {
    let release = stdfs::read_to_string(paths.at("/etc/os-release"))
        .map_err(|_| input("cannot read os-release"))?;
    let values: BTreeMap<_, _> = release
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k, v.trim_matches('"')))
        .collect();
    let mut facts = Facts {
        os: values.get("ID").copied().unwrap_or("").into(),
        os_version: version(values.get("VERSION_ID").copied().unwrap_or("0"))?,
        kernel: version(&command(system, Program::Uname, &["-r"])?)?,
        arch: command(system, Program::Uname, &["-m"])?.trim().into(),
        uid: system.install_uid(),
        ..Facts::default()
    };
    for package in model::PACKAGES {
        let out = system
            .run(
                Program::DpkgQuery,
                &["-W".into(), "-f=${Status}".into(), package.into()],
                EXEC_TIMEOUT,
            )
            .map_err(|_| input("dpkg-query failed"))?;
        if out.status == Some(0) && out.stdout.trim() == "install ok installed" {
            facts.packages.insert(package.into());
        } else if !matches!(out.status, Some(0 | 1)) {
            return Err(input("dpkg-query failed"));
        }
    }
    // Check host support first, deferring missing packages until v1 evidence
    // has been inspected. Detection skips utilities absent from the package set.
    let mut platform = facts.clone();
    platform.packages.extend(model::PACKAGES.map(String::from));
    model::preflight(&platform)?;
    if optional(&paths.at(model::SCUPPER_FILE), false)?.is_some()
        && let Some(marker) = crate::v1_detect::detect_installed_binary(system)
            .map_err(|_| input("cannot inspect installed binary"))?
    {
        facts.v1_markers.push(format!("{marker:?}"));
    }
    if !facts.v1_markers.is_empty() {
        return Err(Refusal::V1);
    }
    facts.v1_markers =
        crate::v1_detect::detect_install_layout(system, &["wg0", "ex-0"], &facts.packages)
            .map_err(|_| input("cannot inspect v1 layout"))?
            .iter()
            .map(|m| format!("{m:?}"))
            .collect();
    let netns = paths.at(model::NETNS_FILE);
    match stdfs::symlink_metadata(&netns) {
        Ok(_) => {
            let report = stdfs::read(paths.at(model::BOOT_FILE))
                .ok()
                .and_then(|b| serde_json::from_slice::<crate::boot::BootReport>(&b).ok());
            let identity = system.namespace_identity(&netns).ok();
            let recorded = matches!((report, identity), (Some(r), Some((dev, ino))) if r.netns.is_some_and(|n| n.dev == dev && n.ino == ino));
            let supervised = !recorded && identity.is_some_and(|(dev, ino)| {
                let control = crate::daemon::control::call(
                    &paths.at(model::RUN_ROOT),
                    &crate::daemon::control::request(scupper_proto::Op::Ping {}),
                    std::time::Duration::from_secs(2),
                );
                matches!(control, Ok(scupper_proto::Response { result: Ok(scupper_proto::OpResult::Ping { netns, .. }), .. }) if netns.device == dev && netns.inode == ino)
            });
            facts.foreign_namespace = !recorded && !supervised;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(input("cannot inspect namespace")),
    }
    model::preflight(&facts)?;
    observe_accounts(system, &mut facts)?;
    observe_files(system, paths, &mut facts)?;
    let store =
        VersionStore::read_only(&paths.at(model::STATE_ROOT), &paths.at(model::CONFIG_ROOT));
    facts.head = store
        .head()
        .map_err(|_| input("invalid configuration store"))?;
    observe_history(paths, &store, &mut facts)?;
    normalize_owner(system, &mut facts);
    Ok(facts)
}
fn observe_history(paths: &Paths, store: &VersionStore, facts: &mut Facts) -> Result<(), Refusal> {
    for version in 1..=facts.head.unwrap_or(0) {
        for path in [
            format!("{}/{version:06}.toml", model::VERSIONS_ROOT),
            format!("{}/{version:06}.meta.json", model::VERSIONS_ROOT),
            format!("{}/{version:06}.nft", model::RENDERED_ROOT),
        ] {
            if let Some(node) = optional(&paths.at(&path), false)? {
                facts.nodes.insert(path, node);
            }
        }
        let (text, _) = store
            .read(version)
            .map_err(|_| input("invalid historical configuration"))?;
        let site =
            config::parse_site(&text).map_err(|_| input("invalid historical configuration"))?;
        if Some(version) == facts.head {
            let gateway = site
                .gateways
                .get(&site.site.primary)
                .ok_or_else(|| input("unknown stored gateway"))?;
            facts
                .config_inputs
                .insert("uplink".into(), gateway.uplinks.join(","));
            if let Some(exit) = gateway.exits.first() {
                facts
                    .config_inputs
                    .insert("exit-id".into(), exit.id.to_string());
            }
        }
        facts.identity_named |= site
            .identities
            .values()
            .any(|i| i.private_key_ref.name() == "wg0");
    }
    Ok(())
}
fn normalize_owner(system: &dyn System, facts: &mut Facts) {
    // Map the unprivileged filesystem owner to root only for injected root
    // executors. RealSystem reports the actual uid and fails root preflight.
    if system.install_uid() == 0 && rustix::process::geteuid().as_raw() != 0 {
        for node in facts.nodes.values_mut() {
            if node.uid == rustix::process::geteuid().as_raw() {
                node.uid = 0;
            }
        }
    }
}
fn observe_accounts(system: &dyn System, facts: &mut Facts) -> Result<(), Refusal> {
    for user in model::USERS {
        let out = system
            .run(
                Program::Getent,
                &["passwd".into(), user.into()],
                EXEC_TIMEOUT,
            )
            .map_err(|_| input("cannot inspect accounts"))?;
        if out.status == Some(2) {
            continue;
        }
        let fields: Vec<_> = out.stdout.trim().split(':').collect();
        if out.status != Some(0)
            || fields.len() != 7
            || fields[0] != user
            || !fields[2]
                .parse::<u32>()
                .is_ok_and(|uid| uid > 0 && uid < 1000)
            || fields[5] != "/nonexistent"
            || fields[6] != "/usr/sbin/nologin"
        {
            return Err(input("existing helper account is unsafe"));
        }
        facts.users.insert(user.into());
    }
    let group = system
        .run(
            Program::Getent,
            &["group".into(), model::ADMIN_GROUP.into()],
            EXEC_TIMEOUT,
        )
        .map_err(|_| input("cannot inspect group"))?;
    match group.status {
        Some(0) => {
            facts.groups.insert(model::ADMIN_GROUP.into());
        }
        Some(2) => {}
        _ => return Err(input("cannot inspect group")),
    }
    Ok(())
}
fn observe_files(system: &dyn System, paths: &Paths, facts: &mut Facts) -> Result<(), Refusal> {
    for (path, _) in model::DIRECTORIES {
        if let Some(node) = optional(&paths.at(path), false)? {
            if !paths.at(path).is_dir() {
                return Err(input("expected installation directory"));
            }
            facts.nodes.insert(path.into(), node);
        }
    }
    for path in [
        model::WG0_FILE,
        model::GATEWAY_FILE,
        model::MODULES_FILE,
        model::MIRROR_FILE,
        model::STATE_FILE,
    ] {
        if let Some(node) = optional(&paths.at(path), path != model::WG0_FILE)? {
            facts.nodes.insert(path.into(), node);
        }
    }
    let bin = optional(&paths.at(model::BIN_ROOT), false)?.ok_or_else(|| {
        input("/usr/local/bin must exist, be root-owned and not group- or world-writable")
    })?;
    let owner = if system.install_uid() == 0 {
        rustix::process::geteuid().as_raw()
    } else {
        0
    };
    if !paths.at(model::BIN_ROOT).is_dir() || bin.uid != owner || bin.mode & 0o022 != 0 {
        return Err(input(
            "/usr/local/bin must exist, be root-owned and not group- or world-writable",
        ));
    }
    for name in model::BINARIES {
        let path = format!("{}/{name}", model::BIN_ROOT);
        if let Some(node) = optional(&paths.at(&path), true)? {
            facts.nodes.insert(path, node);
        }
    }
    for unit in model::UNITS {
        let path = format!("{}/{unit}.service", model::UNIT_ROOT);
        if let Some(node) = optional(&paths.at(&path), true)? {
            facts.nodes.insert(path, node);
        }
        let out = system
            .run(
                Program::Systemctl,
                &["is-enabled".into(), format!("{unit}.service")],
                EXEC_TIMEOUT,
            )
            .map_err(|_| input("cannot inspect units"))?;
        if unit_enabled(&out)? {
            facts.enabled.insert(unit.into());
        }
    }
    if facts.nodes.contains_key(model::GATEWAY_FILE) {
        let id = stdfs::read_to_string(paths.at(model::GATEWAY_FILE))
            .map_err(|_| input("cannot read gateway-id"))?;
        facts.gateway_id = Some(id.trim().into());
    }
    Ok(())
}

// is-enabled uses nonzero statuses for ordinary states, including missing units.
// Interpret the state before the exit code: systemd 249 can emit only stderr.
fn unit_enabled(out: &crate::system::ExecOutput) -> Result<bool, Refusal> {
    match out.stdout.trim() {
        // Installation requires persistent enablement across reboots.
        "enabled" => Ok(true),
        "enabled-runtime" | "alias" | "linked" | "linked-runtime" | "static" | "indirect"
        | "generated" | "transient" | "disabled" | "masked" | "masked-runtime" | "not-found"
        | "bad" => Ok(false),
        "" if out.status.is_some_and(|code| code != 0)
            && out.stderr.lines().any(|line| {
                line.starts_with("Failed to get unit file state for ")
                    && line.ends_with(": No such file or directory")
            }) =>
        {
            Ok(false)
        }
        _ => Err(Refusal::UnitState {
            status: out.status,
            stderr: out
                .stderr
                .chars()
                .take(2048)
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::ExecOutput;

    #[test]
    fn systemd_249_and_255_unit_states() {
        // 249 reports a missing file on stderr; 255 prints not-found.
        for (status, stdout, stderr, enabled) in [
            (0, "enabled\n", "", true),
            (1, "disabled\n", "", false),
            (1, "masked\n", "", false),
            (
                1,
                "",
                "Failed to get unit file state for scupperd.service: No such file or directory\n",
                false,
            ),
            (4, "not-found\n", "", false),
            (
                1,
                "disabled\n",
                "Failed to get unit file state for scupperd.service: No such file or directory\n",
                false,
            ),
        ] {
            assert_eq!(
                unit_enabled(&ExecOutput {
                    status: Some(status),
                    stdout: stdout.into(),
                    stderr: stderr.into(),
                })
                .unwrap(),
                enabled
            );
        }
        for state in [
            "enabled-runtime",
            "alias",
            "linked",
            "linked-runtime",
            "static",
            "indirect",
            "generated",
            "transient",
            "masked-runtime",
            "bad",
        ] {
            assert!(
                !unit_enabled(&ExecOutput {
                    status: Some(1),
                    stdout: state.into(),
                    stderr: String::new(),
                })
                .unwrap(),
                "{state}"
            );
        }
    }

    #[test]
    fn unknown_unit_state_keeps_bounded_sanitized_diagnostics() {
        let error = unit_enabled(&ExecOutput {
            status: Some(7),
            stdout: String::new(),
            stderr: format!("bus\n\u{1b}{}", "x".repeat(3000)),
        })
        .unwrap_err();
        let Refusal::UnitState { status, stderr } = &error else {
            panic!("{error}")
        };
        assert_eq!(*status, Some(7));
        assert_eq!(stderr.len(), 2048);
        assert!(stderr.starts_with("bus  "));
        assert!(!stderr.chars().any(char::is_control));
        assert!(error.to_string().contains("Some(7)"));
        assert!(
            unit_enabled(&ExecOutput {
                status: None,
                stdout: String::new(),
                stderr: String::new(),
            })
            .is_err()
        );
    }
}
