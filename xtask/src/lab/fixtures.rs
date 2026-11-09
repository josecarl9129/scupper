//! Healthy-topology observation fixtures, with public identities normalized.
use super::{Lab, Result, addresses::A};
use scupper_core::{render::desired_sysctls, rules::IfName};
use std::{fs, path::Path};

impl Lab {
    pub(super) fn fixtures(&mut self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir)?;
        self.rule_fixtures(dir)?;
        for ns in ["scupper", "gwhost"] {
            for family in ["-4", "-6"] {
                for object in ["link", "addr", "route", "rule"] {
                    let mut args = vec!["-j", family, object, "show"];
                    if object == "link" {
                        args.insert(0, "-d");
                    }
                    self.fixture(
                        dir,
                        &format!("{ns}-{family}-{object}.json"),
                        ns,
                        "ip",
                        &args,
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
    pub(super) fn verify_handle_execution() -> Result<()> {
        use scupper_sys::{
            cmd::{IpCmd, KernelCmd, run_cmd},
            netns::NetnsHandle,
            system::{EXEC_TIMEOUT, ExecTarget, RealSystem},
        };
        let first = NetnsHandle::open("/run/netns/scupper")?;
        let handle = NetnsHandle::open_expected("/run/netns/scupper", Some(first.identity()))?;
        handle.verify(first.identity())?;
        if NetnsHandle::open_expected("/run/netns/scupper", Some((0, 0))).is_ok() {
            return super::fail("namespace accepted the wrong boot identity");
        }
        let output = run_cmd(
            &RealSystem::default(),
            ExecTarget::Netns(&handle),
            &KernelCmd::Ip(IpCmd::LinkShowJson),
            EXEC_TIMEOUT,
        )?;
        if output.status != Some(0) {
            return super::fail("held namespace link inventory failed");
        }
        let links = scupper_core::parse::links(&output.stdout)?;
        if !links
            .iter()
            .any(|link| link.name == "ex-ch1" && link.kind.as_deref() == Some("wireguard"))
            || links.iter().any(|link| link.name == "eth0")
        {
            return super::fail("held namespace saw incorrect links or kinds");
        }
        Ok(())
    }

    fn rule_fixtures(&mut self, dir: &Path) -> Result<()> {
        self.new_namespace("rulecap", "")?;
        // Exclusive creation registers ownership immediately; the lab registry
        // also cleans this namespace if any add/capture fails or is interrupted.
        self.cmd("rulecap", "ip", &["link", "add", "wg0", "type", "dummy"])?;
        self.cmd("rulecap", "ip", &["link", "set", "wg0", "up"])?;
        for words in RULES_V4 {
            let mut args = vec!["rule", "add"];
            args.extend_from_slice(words);
            self.cmd("rulecap", "ip", &args)?;
        }
        for extra in [
            vec!["not", "iif", "wg0", "lookup", "107", "priority", "1001"],
            vec!["iif", "nosuchdev", "lookup", "108", "priority", "1002"],
            vec!["sport", "1-2", "lookup", "109", "priority", "1003"],
        ] {
            let mut args = vec!["rule", "add"];
            args.extend(extra);
            self.cmd("rulecap", "ip", &args)?;
        }
        self.cmd(
            "rulecap",
            "ip",
            &["-6", "rule", "add", "from", "fd00:99::/64", "lookup", "106"],
        )?;
        self.fixture(
            dir,
            "rules-v4.json",
            "rulecap",
            "ip",
            &["-j", "rule", "show"],
        )?;
        self.fixture(
            dir,
            "rules-v6.json",
            "rulecap",
            "ip",
            &["-6", "-j", "rule", "show"],
        )?;
        // Capture a real source-specific route too: iproute2 currently prints
        // its source under `from`, unlike the rule printer's src/srclen pair.
        self.cmd(
            "rulecap",
            "ip",
            &[
                "-6",
                "route",
                "add",
                "default",
                "from",
                "2001:db8::/64",
                "dev",
                "wg0",
            ],
        )?;
        self.fixture(
            dir,
            "routes-source-v6.json",
            "rulecap",
            "ip",
            &["-6", "-j", "route", "show"],
        )?;
        self.cmd("", "ip", &["netns", "delete", "rulecap"])?;
        self.registry
            .unregister(&super::Resource::Namespace("rulecap".into()));
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

// Literal ip rule add selectors; no invented JSON fixtures stand in for these.
const RULES_V4: &[&[&str]] = &[
    &["from", "10.99.0.0/24", "lookup", "100"],
    &["to", "192.0.2.0/24", "lookup", "101"],
    &["not", "fwmark", "0x1", "lookup", "102"],
    &["uidrange", "1000-2000", "lookup", "103"],
    &["sport", "1000-2000", "lookup", "104"],
    &["dport", "53", "ipproto", "udp", "lookup", "105"],
    &["iif", "wg0", "lookup", "51820", "priority", "1000"],
    &["lookup", "main", "suppress_prefixlen", "0"],
    &["from", "all", "unreachable"],
];

#[cfg(test)]
mod capture_tests {
    #[test]
    fn rule_capture_has_each_required_selector() {
        let commands = super::RULES_V4
            .iter()
            .map(|args| args.join(" "))
            .collect::<Vec<_>>();
        assert_eq!(
            commands,
            [
                "from 10.99.0.0/24 lookup 100",
                "to 192.0.2.0/24 lookup 101",
                "not fwmark 0x1 lookup 102",
                "uidrange 1000-2000 lookup 103",
                "sport 1000-2000 lookup 104",
                "dport 53 ipproto udp lookup 105",
                "iif wg0 lookup 51820 priority 1000",
                "lookup main suppress_prefixlen 0",
                "from all unreachable",
            ]
        );
    }
}
