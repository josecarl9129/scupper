//! Real check CLI against an immutable store and the boot-built topology. Mount
//! overlays confine its fixed production roots to the lab's private directory.
use super::{
    Lab, Result,
    command::Invocation,
    evidence::{self, Row},
    fail,
};
use scupper_core::{
    config::{DurationStr, GatewayId, HealthSettings, parse_site, validate},
    render::{VersionStamp, render_netns},
};
use scupper_sys::{
    lock::WriterLock,
    state::{State, StateFile},
    store::{MetaInput, VersionStore},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

// Keep /run/netns propagation intact. Isolate only the two overlay destinations
// before binding: a recursive propagation change at / would include nsfs peers.
const CHECK: &str = r#"
set -eu
# / is always a mount point; never let a missing or failing `mountpoint` skip it.
mount --make-private /
for path in /etc /var /var/lib; do
    if mountpoint -q "$path"; then
        mount --make-private "$path"
    fi
done
mount --bind "$1/etc" /etc
mount --make-private /etc
mount --bind "$1/var-lib" /var/lib
mount --make-private /var/lib
exec nsenter --net=/run/netns/gwhost -- "$2" --test-root "$1" check --json
"#;

// Each row proves the intended stage, even when several verdicts share a code.
fn verdict_matches(name: &str, report: &serde_json::Value) -> bool {
    let verdict = &report["verdict"];
    match name {
        "default" => {
            verdict["Degraded"]["DefaultRouteWrong"]["family"] == "V4"
                && verdict["Degraded"]["DefaultRouteWrong"]["got"] == "Missing"
        }
        "ruleset" => verdict["Unprotected"]
            .as_array()
            .is_some_and(|found| found.iter().any(|v| v.get("RulesetDiffers").is_some())),
        "local-table" => verdict["Unprotected"].as_array().is_some_and(|found| {
            found.iter().any(|v| {
                v["ExtraRoute"]["table"] == "local"
                    && v["ExtraRoute"]["dst"] == "128.0.0.0/1"
                    && v["ExtraRoute"]["dev"] == "wg0"
            })
        }),
        "exit-down" => verdict["FailClosed"] == "NoHealthyExit",
        _ => verdict["Protected"]["exit_ip"]
            .as_str()
            .is_some_and(|ip| ip.parse::<std::net::IpAddr>().is_ok()),
    }
}

impl Lab {
    pub(super) fn check_v2_case(&mut self) -> Result<String> {
        let binary = fs::canonicalize(
            std::env::current_exe()?
                .parent()
                .and_then(Path::parent)
                .ok_or("lab executable must be in target/{profile}")?
                .join("debug/scupper"),
        )?;
        let root = self.prepare_check_v2()?;
        let result = self.check_v2_faults(&binary, &root);
        // Restore the boot-built state even after an assertion/launcher failure.
        let restored = (|| {
            // These faults may still be active after an assertion/launcher error.
            let _ = self.cmd(
                "scupper",
                "ip",
                &[
                    "route",
                    "del",
                    "128.0.0.0/1",
                    "dev",
                    "wg0",
                    "table",
                    "local",
                ],
            );
            let _ = self.cmd("gwhost", "ip", &["link", "del", "wg-legacy"]);
            self.cmd("scupper", "ip", &["link", "set", "ex-ch1", "up"])?;
            self.cmd(
                "scupper",
                "ip",
                &["route", "replace", "default", "dev", "ex-ch1"],
            )?;
            self.load_real_rules()?;
            self.wait_provider()?;
            self.service_check(&mut Vec::new())
        })();
        match (result, restored) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(restore)) => fail(format!("{error}; restore: {restore}")),
        }
    }

    pub(super) fn prepare_check_v2(&mut self) -> Result<PathBuf> {
        let root = self.private.join("boot-root");
        if root.is_dir() {
            return self.prepare_short_boot_root();
        }
        let etc = root.join("etc/scupper");
        let state = root.join("var-lib/scupper");
        fs::create_dir_all(&etc)?;
        fs::create_dir_all(&state)?;
        for account in ["passwd", "group"] {
            fs::copy(
                Path::new("/etc").join(account),
                root.join("etc").join(account),
            )?;
        }
        fs::write(etc.join("gateway-id"), "gw1\n")?;
        for kind in ["secrets", "secrets/wg", "secrets/url"] {
            let path = etc.join(kind);
            fs::create_dir(&path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        fs::create_dir_all(root.join("run/scupper"))?;
        for (key, reference) in [("gateway", "lab-client"), ("exit", "lab-exit")] {
            let path = etc.join("secrets/wg").join(reference);
            fs::copy(self.private.join(format!("{key}.key")), &path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        // Runtime public identities and real HTTPS probes describe the boot inputs.
        let text = fs::read_to_string(self.private.join("runtime-site.toml"))?;
        let mut config = parse_site(&text)?;
        config.health.probe_targets = HealthSettings::default().probe_targets;
        // Minimum allowed WireGuard rekey interval + slack. L3 must observe
        // staleness with a single exit, rather than relying on probe failures.
        config.health.handshake_stale = DurationStr("175s".into());
        config.health.failover_grace = DurationStr("30s".into());
        config.health.require_daemon = false; // scupperd is deliberately absent in this lab.
        let text = toml::to_string(&config)?;
        self.site = validate(config).map_err(|errors| format!("check lab config: {errors:?}"))?;
        let writer = WriterLock::acquire(root.join("writer"))?;
        let store = VersionStore::open_with_mirror_root(&state, &etc, Some(&writer))?;
        let version = store.commit(
            &writer,
            None,
            &text,
            MetaInput {
                actor: "lab".into(),
                at: 1,
                reason: "boot-built namespace lab".into(),
            },
        )?;
        StateFile::open(&state, Some(&writer))?.write(
            &writer,
            &State {
                applied_version: Some(version),
                ..State::default()
            },
        )?;
        let rules = render_netns(
            &self.site,
            &GatewayId("gw1".into()),
            &VersionStamp {
                version,
                sha256: Sha256::digest(text.as_bytes()).into(),
            },
        )?;
        store.write_rendered(&writer, version, &rules)?;
        fs::write(&self.rules, rules)?;
        self.prepare_short_boot_root()
    }

    // Keep private state in place; only the public runtime pathname needs shortening.
    fn prepare_short_boot_root(&mut self) -> Result<PathBuf> {
        use super::cleanup::Resource;
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, symlink};
        if !self.boot_root_ready {
            let parent = Path::new("/run/scupper-lab");
            match fs::DirBuilder::new().mode(0o755).create(parent) {
                Ok(()) => {
                    self.registry.register(Resource::Directory(parent.into()));
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
            let meta = fs::symlink_metadata(parent)?;
            if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o777 != 0o755 {
                return fail("/run/scupper-lab must be a root-owned 0755 directory");
            }
            fs::DirBuilder::new().mode(0o755).create(&self.boot_root)?;
            self.registry
                .register(Resource::Directory(self.boot_root.clone()));
            fs::set_permissions(&self.boot_root, fs::Permissions::from_mode(0o755))?;
            let storage = self.private.join("boot-root");
            for name in ["etc", "var-lib", "run"] {
                symlink(storage.join(name), self.boot_root.join(name))?;
            }
            self.boot_root_ready = true;
        }
        Ok(self.boot_root.clone())
    }

    pub(super) fn check_result(
        &mut self,
        binary: &Path,
        root: &Path,
    ) -> Result<(i32, serde_json::Value)> {
        let (status, stdout) = self.runner.output_timeout(
            &Invocation::new(
                "",
                "unshare",
                &[
                    "--mount",
                    "--propagation",
                    "unchanged",
                    "--",
                    "/bin/sh",
                    "-c",
                    CHECK,
                    "check-v2",
                    root.to_str().ok_or("non-UTF8 check root")?,
                    binary.to_str().ok_or("non-UTF8 binary")?,
                ],
            ),
            None,
            15,
        )?;
        let report = serde_json::from_str(&stdout)
            .map_err(|error| format!("check-v2 JSON: {error}; output: {stdout}"))?;
        Ok((status.code().ok_or("check-v2 killed by signal")?, report))
    }

    fn check_row(
        &mut self,
        name: &str,
        want: i32,
        code: i32,
        report: &serde_json::Value,
        skip: Option<&str>,
    ) -> Result<()> {
        self.rows.push(Row {
            name: format!("check-v2-{name}"),
            wanted: want.to_string(),
            got: if skip.is_some() {
                "skipped".into()
            } else {
                code.to_string()
            },
            detail: skip.map_or_else(|| report.to_string(), str::to_owned),
        });
        evidence::save_results(&self.artifacts, &self.rows)?;
        if skip.is_none() && (code != want || !verdict_matches(name, report)) {
            // Diagnostic only: the namespace route tables at the time of the mismatch.
            let mut dump = Vec::new();
            for args in [
                &["-d", "-j", "route", "show", "table", "all"][..],
                &["-6", "-d", "-j", "route", "show", "table", "all"][..],
                &["-j", "route", "show", "default"][..],
                &["-6", "-j", "route", "show", "default"][..],
            ] {
                let out = self
                    .cmd("scupper", "ip", args)
                    .unwrap_or_else(|e| e.to_string());
                dump.push(format!("== ip {}\n{out}", args.join(" ")));
            }
            fs::write(
                self.artifacts.join(format!("check-v2-{name}.routes.txt")),
                dump.join("\n"),
            )?;
            return fail(format!(
                "check-v2 {name}: wanted {want} and its specific verdict, got {code}: {report}"
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // Keep each injected fault beside its assertion and restoration.
    fn check_v2_faults(&mut self, binary: &Path, root: &Path) -> Result<String> {
        let (code, report) = self.check_result(binary, root)?;
        // Skip only a classified exit-path error after every local stage passed.
        // A setup/collection error, wrong route or containment failure must fail.
        let no_internet = code == 3
            && report["verdict"]["Degraded"]
                .get("ExitProbeFailed")
                .is_some();
        let reason =
            no_internet.then(|| format!("runner internet unavailable through provA: {report}"));
        self.check_row("healthy", 0, code, &report, reason.as_deref())?;
        for fault in [
            "host-wg-other-port",
            "default",
            "ruleset",
            "local-table",
            "exit-down",
        ] {
            let expected = match fault {
                "host-wg-other-port" => {
                    self.cmd(
                        "gwhost",
                        "ip",
                        &["link", "add", "wg-legacy", "type", "wireguard"],
                    )?;
                    self.cmd(
                        "gwhost",
                        "wg",
                        &["set", "wg-legacy", "listen-port", "51822"],
                    )?;
                    0
                }
                "local-table" => {
                    self.cmd(
                        "scupper",
                        "ip",
                        &[
                            "route",
                            "add",
                            "128.0.0.0/1",
                            "dev",
                            "wg0",
                            "table",
                            "local",
                        ],
                    )?;
                    2
                }
                "default" => {
                    self.cmd("scupper", "ip", &["route", "del", "default"])?;
                    3
                }
                "ruleset" => {
                    self.cmd(
                        "scupper",
                        "nft",
                        &[
                            "add", "rule", "inet", "scupper", "forward", "iifname", "wg0",
                            "oifname", "lab-x", "accept",
                        ],
                    )?;
                    2
                }
                _ => {
                    self.cmd("scupper", "ip", &["link", "set", "ex-ch1", "down"])?;
                    4
                }
            };
            let (code, report) = self.check_result(binary, root)?;
            if fault == "exit-down" {
                let defaults: serde_json::Value = serde_json::from_str(&self.cmd(
                    "scupper",
                    "ip",
                    &["-j", "route", "show", "default"],
                )?)?;
                if !defaults.as_array().is_some_and(Vec::is_empty) {
                    return fail(format!("exit-down retained a default: {defaults}"));
                }
            }
            let skip = reason.as_deref().filter(|_| {
                fault == "default" && verdict_matches(fault, &report)
                    || fault == "host-wg-other-port"
                        && report["verdict"]["Degraded"]
                            .get("ExitProbeFailed")
                            .is_some()
            });
            self.check_row(fault, expected, code, &report, skip)?;
            if fault == "local-table" {
                self.cmd(
                    "scupper",
                    "ip",
                    &[
                        "route",
                        "del",
                        "128.0.0.0/1",
                        "dev",
                        "wg0",
                        "table",
                        "local",
                    ],
                )?;
            }
            if fault == "host-wg-other-port" {
                self.cmd("gwhost", "ip", &["link", "del", "wg-legacy"])?;
            }
            self.cmd("scupper", "ip", &["link", "set", "ex-ch1", "up"])?;
            self.cmd(
                "scupper",
                "ip",
                &["route", "replace", "default", "dev", "ex-ch1"],
            )?;
            self.load_real_rules()?;
            self.wait_provider()?;
            let (code, report) = self.check_result(binary, root)?;
            self.check_row(
                &format!("restore-{fault}"),
                0,
                code,
                &report,
                reason.as_deref().filter(|_| {
                    code == 3
                        && report["verdict"]["Degraded"]
                            .get("ExitProbeFailed")
                            .is_some()
                }),
            )?;
        }
        Ok(reason.map_or_else(
            || "Protected and host wg on another port; DefaultRouteWrong, RulesetDiffers, ExtraRoute, NoHealthyExit; all restores Protected".into(),
            |reason| format!("skipped healthy, host-wg-other-port, default and restores: {reason}; RulesetDiffers, ExtraRoute and NoHealthyExit verified"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{CHECK, verdict_matches};
    use serde_json::json;

    #[test]
    fn check_isolates_only_mounted_overlay_ancestors() -> Result<(), Box<dyn std::error::Error>> {
        // Exercise the actual shell decisions for ordinary and separately
        // mounted /etc and /var layouts, without issuing privileged syscalls.
        let setup = CHECK.split("exec nsenter").next().ok_or("missing setup")?;
        for (points, private) in [
            ("/", vec!["/"]),
            ("/|/etc|/var", vec!["/", "/etc", "/var"]),
            ("/|/var/lib", vec!["/", "/var/lib"]),
        ] {
            let script = format!(
                r#"
mountpoint() {{ case "$2" in {points}) return 0;; *) return 1;; esac; }}
mount() {{ printf '%s\n' "$*"; }}
{setup}
"#
            );
            let output = std::process::Command::new("/bin/sh")
                .args(["-c", &script, "check-test", "/lab-root"])
                .output()?;
            assert!(output.status.success());
            let mut expected: Vec<_> = private
                .into_iter()
                .map(|path| format!("--make-private {path}"))
                .collect();
            expected.extend([
                "--bind /lab-root/etc /etc".into(),
                "--make-private /etc".into(),
                "--bind /lab-root/var-lib /var/lib".into(),
                "--make-private /var/lib".into(),
            ]);
            assert_eq!(
                String::from_utf8(output.stdout)?,
                expected.join("\n") + "\n"
            );
        }
        Ok(())
    }

    #[test]
    fn lab_rows_require_specific_verdicts_and_healthy_exit_ip() {
        let probe_failure = json!({"verdict":{"Degraded":{"ExitProbeFailed":"path"}}});
        for row in [
            "healthy",
            "default",
            "ruleset",
            "local-table",
            "exit-down",
            "host-wg-other-port",
            "restore-default",
        ] {
            assert!(!verdict_matches(row, &probe_failure), "{row}");
        }
        assert!(verdict_matches(
            "healthy",
            &json!({"verdict":{"Protected":{"exit_ip":"8.8.4.4"}}})
        ));
        assert!(!verdict_matches(
            "healthy",
            &json!({"verdict":{"Protected":{}}})
        ));
        assert!(verdict_matches(
            "default",
            &json!({"verdict":{"Degraded":{"DefaultRouteWrong":{"family":"V4","got":"Missing"}}}})
        ));
        assert!(verdict_matches(
            "ruleset",
            &json!({"verdict":{"Unprotected":[{"RulesetDiffers":{}}]}})
        ));
        assert!(!verdict_matches(
            "ruleset",
            &json!({"verdict":{"Unprotected":[{"ForeignLink":"eth0"}]}})
        ));
        assert!(verdict_matches(
            "local-table",
            &json!({"verdict":{"Unprotected":[{"ExtraRoute":{"table":"local","dst":"128.0.0.0/1","dev":"wg0"}}]}})
        ));
        assert!(verdict_matches(
            "exit-down",
            &json!({"verdict":{"FailClosed":"NoHealthyExit"}})
        ));
    }
}
