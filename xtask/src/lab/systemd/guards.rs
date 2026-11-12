//! Pure parsers and root-uplink setup with fail-closed host guards.
use super::{A, Invocation, Result, Runner, SystemdLab, fail, fs};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fs::OpenOptions, io::Write};

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct HostSnapshot {
    defaults4: Vec<String>,
    defaults6: Vec<String>,
    eth0: Vec<String>,
    rules4: String,
    rules6: String,
    eth0_link: Value,
    resolv_conf: String,
    eth0_dns: String,
    ip_forward: String,
}
fn routes(text: &str) -> Result<Vec<String>> {
    let mut rows: Vec<Value> = serde_json::from_str(text)?;
    for row in &mut rows {
        row.as_object_mut().ok_or("route object")?.remove("expires");
    }
    let mut routes = rows
        .iter()
        .map(serde_json::to_string)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    routes.sort();
    Ok(routes)
}
fn addresses(text: &str) -> Result<Vec<String>> {
    let rows: Vec<Value> = serde_json::from_str(text)?;
    if rows.len() != 1 || rows[0]["ifname"] != "eth0" {
        return fail("guard requires exactly one eth0");
    }
    let mut result = Vec::new();
    for address in rows[0]["addr_info"]
        .as_array()
        .ok_or("missing eth0 addr_info")?
    {
        if !address["local"].is_string() || !address["prefixlen"].is_number() {
            return fail("malformed eth0 address");
        }
        // DHCP/IPv6 lifetimes count down without a configuration change.
        let mut address = address.clone();
        let fields = address.as_object_mut().ok_or("address object")?;
        fields.remove("valid_life_time");
        fields.remove("preferred_life_time");
        result.push(serde_json::to_string(&address)?);
    }
    result.sort();
    if result.is_empty() {
        return fail("runner eth0 has no addresses");
    }
    Ok(result)
}
impl HostSnapshot {
    pub fn read(runner: &mut Runner) -> Result<Self> {
        let defaults4 = routes(&runner.run(&Invocation::new(
            "",
            "ip",
            &["-4", "-j", "route", "show", "table", "all", "default"],
        ))?)?;
        let defaults6 = routes(&runner.run(&Invocation::new(
            "",
            "ip",
            &["-6", "-j", "route", "show", "table", "all", "default"],
        ))?)?;
        let eth0 = addresses(&runner.run(&Invocation::new(
            "",
            "ip",
            &["-j", "address", "show", "dev", "eth0"],
        ))?)?;
        if defaults4.is_empty() {
            return fail("runner has no IPv4 default route");
        }
        let rules4 = runner.run(&Invocation::new("", "ip", &["-4", "-j", "rule", "show"]))?;
        let rules6 = runner.run(&Invocation::new("", "ip", &["-6", "-j", "rule", "show"]))?;
        let links: Value = serde_json::from_str(&runner.run(&Invocation::new(
            "",
            "ip",
            &["-j", "link", "show", "dev", "eth0"],
        ))?)?;
        let eth0_link = serde_json::json!({"flags":links[0]["flags"],"operstate":links[0]["operstate"],"mtu":links[0]["mtu"],"address":links[0]["address"]});
        let resolv_conf = fs::read_to_string("/etc/resolv.conf")?;
        let eth0_dns = runner.run(&Invocation::new("", "resolvectl", &["dns", "eth0"]))?;
        let ip_forward = runner.run(&Invocation::new(
            "",
            "sysctl",
            &["-n", "net.ipv4.ip_forward"],
        ))?;
        if ip_forward.trim() != "1" {
            return fail("root ip_forward=1 required for adversarial inheritance");
        }
        Ok(Self {
            defaults4,
            defaults6,
            eth0,
            rules4,
            rules6,
            eth0_link,
            resolv_conf,
            eth0_dns,
            ip_forward,
        })
    }
    pub fn verify(&self, now: &Self) -> Result<()> {
        if self != now {
            return fail("runner routes, rules, eth0, DNS or forwarding changed");
        }
        Ok(())
    }
}
// networkctl status is available on both systemd 249 (22.04) and 255 (24.04).
// Accept only the setup state, never an incidental "unmanaged" elsewhere.
pub(super) fn unmanaged(status: &str) -> bool {
    status
        .lines()
        .filter_map(|l| l.trim().strip_prefix("State:"))
        .any(|s| s.split_whitespace().last() == Some("(unmanaged)"))
}
impl SystemdLab {
    pub(super) fn uplink(&mut self) -> Result<()> {
        self.lab.cmd(
            "",
            "ip",
            &[
                "link",
                "add",
                "up0",
                "type",
                "veth",
                "peer",
                "name",
                A.gwhost.wan_if,
            ],
        )?;
        self.lab
            .cmd("", "ip", &["link", "set", A.gwhost.wan_if, "netns", "wan"])?;
        self.cmd("udevadm", &["settle", "--timeout=10"])?;
        let mut before = self.cmd(
            "networkctl",
            &["--no-pager", "--no-legend", "status", "up0"],
        )?;
        fs::write(self.lab.artifacts.join("networkd-up0-before.txt"), &before)?;
        let settle = super::Instant::now() + super::Duration::from_secs(2);
        while before.contains("(pending)") || before.contains("(initialized)") {
            if super::Instant::now() >= settle {
                break;
            }
            self.lab.runner.dwell(super::Duration::from_millis(100))?;
            before = self.cmd("networkctl", &["--no-pager", "status", "up0"])?;
        }
        let mut override_used = false;
        if !unmanaged(&before) {
            if !before
                .lines()
                .any(|l| l.trim().starts_with("Network File:") && l.contains(".network"))
            {
                return fail(
                    "networkd up0 state unresolved without a matching network file; refusing global reload",
                );
            }
            let path = "/run/systemd/network/00-000-scupper-lab-up0.network";
            fs::create_dir_all("/run/systemd/network")?;
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(path)?
                .write_all(b"[Match]\nName=up0\n[Link]\nUnmanaged=yes\n")?;
            self.cmd("networkctl", &["reload"])?;
            let (status, _) = self.lab.runner.output(
                &Invocation::new("", "networkctl", &["reconfigure", "up0"]),
                None,
            )?;
            // Some versions refuse reconfigure precisely because reload has
            // already made the link unmanaged. The state readback decides.
            if !matches!(status.code(), Some(0 | 1)) {
                return fail("networkd reconfigure failed");
            }
            override_used = true;
        }
        let until = super::Instant::now() + super::Duration::from_secs(10);
        loop {
            let state = self.cmd(
                "networkctl",
                &["--no-pager", "--no-legend", "status", "up0"],
            )?;
            if unmanaged(&state) {
                fs::write(self.lab.artifacts.join("networkd-up0.txt"), state)?;
                break;
            }
            if super::Instant::now() >= until {
                return fail("networkd manages up0; refusing to configure uplink");
            }
            self.lab.runner.dwell(super::Duration::from_millis(100))?;
        }
        fs::write(
            self.lab.artifacts.join("networkd-override.json"),
            format!("{{\"lab_unmanaged_override\":{override_used}}}\n"),
        )?;
        // up0 has no default route, DHCP, DNS, or automatic IPv6 configuration.
        for (ns, link, address) in [
            ("", "up0", A.gwhost.peer),
            ("wan", A.gwhost.wan_if, A.gwhost.wan),
        ] {
            self.lab.cmd(
                ns,
                "ip",
                &["link", "set", "dev", link, "addrgenmode", "none"],
            )?;
            for key in ["rp_filter", "send_redirects"] {
                self.lab.cmd(
                    ns,
                    "sysctl",
                    &["-q", "-w", &format!("net.ipv4.conf.{link}.{key}=0")],
                )?;
            }
            self.lab
                .cmd(ns, "ip", &["link", "set", "dev", link, "multicast", "off"])?;
            self.lab
                .address_up(ns, link, &format!("{address}/30"), 1500)?;
        }
        self.restore_uplink_routes()?;
        self.guard("uplink-after")
    }
    pub(super) fn restore_uplink_routes(&mut self) -> Result<()> {
        for segment in [A.client, A.client2, A.provider, A.internet] {
            self.lab.cmd(
                "",
                "ip",
                &[
                    "route",
                    "replace",
                    segment.network,
                    "via",
                    A.gwhost.wan,
                    "dev",
                    "up0",
                ],
            )?;
        }
        Ok(())
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn networkd_requires_explicit_setup_state() {
        for text in ["State: routable (unmanaged)", "   State: off (unmanaged)\n"] {
            assert!(unmanaged(text));
        }
        for text in [
            "State: routable (configured)",
            "Network File: unmanaged.network",
            "State: unmanaged",
            "",
            "State: off (configuring)",
        ] {
            assert!(!unmanaged(text));
        }
    }
    #[test]
    fn eth0_normalizes_order_and_lifetimes_but_detects_changes() {
        let a = r#"[{"ifname":"eth0","addr_info":[{"local":"192.0.2.9","prefixlen":24,"valid_life_time":90},{"local":"2001:db8::1","prefixlen":64}]}]"#;
        let b = r#"[{"ifname":"eth0","addr_info":[{"local":"2001:db8::1","prefixlen":64},{"local":"192.0.2.9","prefixlen":24,"valid_life_time":80}]}]"#;
        assert_eq!(addresses(a).unwrap(), addresses(b).unwrap());
        assert_ne!(
            addresses(a).unwrap(),
            addresses(&a.replace("192.0.2.9", "192.0.2.10")).unwrap()
        );
        assert!(addresses("[]").is_err());
        assert!(addresses(&a.replace("eth0", "up0")).is_err());
        assert!(addresses(r#"[{"ifname":"eth0","addr_info":[{}]}]"#).is_err());
    }
    #[test]
    fn route_guard_detects_gateway_interface_and_metric_drift() {
        let text = r#"[{"dst":"default","gateway":"192.0.2.1","dev":"eth0","metric":100}]"#;
        for changed in [
            text.replace("192.0.2.1", "192.0.2.2"),
            text.replace("eth0", "up0"),
            text.replace("100", "101"),
        ] {
            assert_ne!(routes(text).unwrap(), routes(&changed).unwrap());
        }
        assert!(routes("{}").is_err());
        let original = HostSnapshot {
            defaults4: routes(text).unwrap(),
            defaults6: vec![],
            eth0: vec!["a".into()],
            ..HostSnapshot::default()
        };
        let mut changed = HostSnapshot {
            defaults4: routes(text).unwrap(),
            defaults6: vec![],
            eth0: vec!["a".into()],
            ..HostSnapshot::default()
        };
        original.verify(&changed).unwrap();
        changed.eth0.push("b".into());
        assert!(original.verify(&changed).is_err());
    }
    #[test]
    fn later_boot_policy_requires_current_exit_tuple_instead_of_first_boot() {
        let text = super::super::uplink_policy(&[], &[41000, 42000, 43000], 43000).unwrap();
        crate::pcap::Policy::from_toml(&text).unwrap();
        let parsed: toml::Value = toml::from_str(&text).unwrap();
        let pairs = parsed["wireguard"].as_array().unwrap();
        // expect wireguard[1] must refer to this boot's working exit.
        assert_eq!(pairs[1]["gateway"].as_str(), Some("198.51.100.2:43000"));
        assert_eq!(pairs.len(), 5); // both clients plus three exact exit ports
        for port in [41000, 42000, 43000] {
            let endpoint = format!("198.51.100.2:{port}");
            assert_eq!(
                pairs
                    .iter()
                    .filter(|p| p["gateway"].as_str() == Some(endpoint.as_str()))
                    .count(),
                1
            );
        }
    }
    #[test]
    fn route_expiration_is_not_configuration_drift() {
        assert_eq!(
            routes(r#"[{"dst":"default","expires":45}]"#).unwrap(),
            routes(r#"[{"dst":"default","expires":40}]"#).unwrap()
        );
    }
}
