//! Healthy-topology observation fixtures, with public identities normalized.
use super::{Lab, Result, addresses::A};
use scupper_core::{render::desired_sysctls, rules::IfName};
use std::{fs, path::Path};

impl Lab {
    pub(super) fn fixtures(&mut self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir)?;
        for ns in ["scupper", "gwhost"] {
            for family in ["-4", "-6"] {
                for object in ["link", "addr", "route", "rule"] {
                    self.fixture(
                        dir,
                        &format!("{ns}-{family}-{object}.json"),
                        ns,
                        "ip",
                        &["-j", family, object, "show"],
                    )?;
                }
                self.fixture(
                    dir,
                    &format!("{ns}-{family}-routes-all.json"),
                    ns,
                    "ip",
                    &["-j", family, "route", "show", "table", "all"],
                )?;
            }
            self.fixture(
                dir,
                &format!("{ns}-tc-qdisc.json"),
                ns,
                "tc",
                &["-j", "qdisc", "show"],
            )?;
            let interfaces: &[&str] = if ns == "scupper" {
                &["lo", "wg0", "ex-ch1"]
            } else {
                &["lo", "eth0"]
            };
            for iface in interfaces {
                for direction in ["ingress", "egress"] {
                    self.fixture(
                        dir,
                        &format!("{ns}-tc-{iface}-{direction}.json"),
                        ns,
                        "tc",
                        &["-j", "filter", "show", "dev", iface, direction],
                    )?;
                }
            }
        }
        self.gateway_fixtures(dir)?;
        Ok(())
    }
    fn gateway_fixtures(&mut self, dir: &Path) -> Result<()> {
        for iface in ["wg0", "ex-ch1"] {
            for field in [
                "public-key",
                "listen-port",
                "peers",
                "allowed-ips",
                "endpoints",
                "persistent-keepalive",
                "latest-handshakes",
                "transfer",
            ] {
                self.fixture(
                    dir,
                    &format!("scupper-wg-{iface}-{field}.txt"),
                    "scupper",
                    "wg",
                    &["show", iface, field],
                )?;
            }
        }
        let links = [
            IfName::new("lo")?,
            IfName::new("wg0")?,
            IfName::new("ex-ch1")?,
        ];
        for setting in desired_sysctls(&links, true) {
            let key = setting.key.to_string();
            self.fixture(
                dir,
                &format!("scupper-sysctl-{key}.txt"),
                "scupper",
                "sysctl",
                &["-n", &key],
            )?;
        }
        self.fixture(
            dir,
            "scupper-nft-ruleset.json",
            "scupper",
            "nft",
            &["-j", "list", "ruleset"],
        )?;
        for (name, target) in [("public", "1.1.1.1"), ("lab", A.internet.peer)] {
            self.fixture(
                dir,
                &format!("scupper-route-get-{name}.txt"),
                "scupper",
                "ip",
                &["route", "get", target, "from", A.client_inner, "iif", "wg0"],
            )?;
        }
        for file in ["udp", "udp6"] {
            self.fixture(
                dir,
                &format!("gwhost-proc-net-{file}.txt"),
                "gwhost",
                "cat",
                &[&format!("/proc/net/{file}")],
            )?;
        }
        self.fixture(dir, "nft-version.txt", "", "nft", &["--version"])?;
        self.fixture(dir, "kernel.txt", "", "uname", &["-r"])?;
        Ok(())
    }
    fn fixture(
        &mut self,
        dir: &Path,
        name: &str,
        ns: &str,
        program: &str,
        args: &[&str],
    ) -> Result<()> {
        let output = self.cmd(ns, program, args)?;
        fs::write(
            dir.join(name),
            redact_public_keys(&output, &self.public_keys),
        )?;
        Ok(())
    }
}
pub(super) fn redact_public_keys(text: &str, public_keys: &[String]) -> String {
    public_keys
        .iter()
        .enumerate()
        .fold(text.to_owned(), |text, (i, key)| {
            text.replace(key, &format!("PUBKEY{}", i + 1))
        })
}
