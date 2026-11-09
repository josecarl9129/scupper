//! Real check CLI against an immutable store and the reference topology. Mount
//! overlays confine its fixed production roots to the lab's private directory.
use super::{
    Lab, Result,
    command::Invocation,
    evidence::{self, Row},
    fail,
};
use scupper_core::{
    canon::canonicalize,
    config::{GatewayId, HealthSettings, parse_site, validate},
    render::{VersionStamp, render_netns},
};
use scupper_sys::{
    lock::WriterLock,
    netns::NetnsHandle,
    state::{State, StateFile},
    store::{MetaInput, VersionStore},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

// Only these child mounts change. The original /etc, /var/lib, host network
// routes, firewall and forwarding settings remain outside the mount namespace.
const CHECK: &str = r#"
set -eu
mount --bind "$1/etc" /etc
mount --bind "$1/var-lib" /var/lib
exec nsenter --net=/run/netns/gwhost -- "$2" check --json
"#;

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
        // Restore the reference state even after an assertion/launcher failure.
        let restored = (|| {
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

    fn prepare_check_v2(&mut self) -> Result<PathBuf> {
        let root = self.private.join("check-v2");
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
        // Runtime lab public keys, plus the real default HTTPS targets. Private
        // keys stay in the existing private lab files; check never reads them.
        let text = fs::read_to_string(self.private.join("runtime-site.toml"))?;
        let mut config = parse_site(&text)?;
        config.health.probe_targets = HealthSettings::default().probe_targets;
        config.health.require_daemon = false; // scupperd is deliberately absent in 2i1.
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
                reason: "check-v2 reference topology".into(),
            },
        )?;
        StateFile::open(&state, Some(&writer))?.write(
            &writer,
            &State {
                applied_version: Some(version),
                ..State::default()
            },
        )?;
        let handle = NetnsHandle::open("/run/netns/scupper")?;
        fs::write(
            state.join("boot.json"),
            serde_json::to_vec(&serde_json::json!({
                "netns": { "dev": handle.identity().0, "ino": handle.identity().1 }
            }))?,
        )?;
        let rules = render_netns(
            &self.site,
            &GatewayId("gw1".into()),
            &VersionStamp {
                version,
                sha256: Sha256::digest(text.as_bytes()).into(),
            },
        )?;
        fs::write(&self.rules, rules)?;
        self.load_real_rules()?;
        self.expected_rules =
            canonicalize(&self.cmd("scupper", "nft", &["-j", "list", "ruleset"])?)?;
        Ok(root)
    }

    fn check_result(&mut self, binary: &Path, root: &Path) -> Result<(i32, serde_json::Value)> {
        let (status, stdout) = self.runner.output(
            &Invocation::new(
                "",
                "unshare",
                &[
                    "--mount",
                    "--propagation",
                    "private",
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
        if code != want && skip.is_none() {
            return fail(format!(
                "check-v2 {name}: wanted {want}, got {code}: {report}"
            ));
        }
        Ok(())
    }

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
        for fault in ["default", "ruleset", "exit-down"] {
            let expected = match fault {
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
            self.check_row(fault, expected, code, &report, None)?;
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
            || "0,3,0,2,0,4,0".into(),
            |reason| format!("skipped: {reason}; fault codes 3,2,4 verified"),
        ))
    }
}
