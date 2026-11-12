//! Counter-only root namespace coverage for paths outside the captured veth.
use super::{Invocation, Result, SystemdLab, fail, fs};
const TABLE: &str = "scupper_lab_egress";
const RULES: &str = r#"table inet scupper_lab_egress {
 chain postrouting {
  type filter hook postrouting priority 300; policy accept;
  oifname != "up0" ip saddr { 10.99.0.0/24, 10.2.0.0/24, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 } counter
  oifname != "up0" ip daddr { 10.99.0.0/24, 10.2.0.0/24, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 } counter
  oifname != "up0" ip6 saddr { 2001:db8::/32, fd00::/8 } counter
  oifname != "up0" ip6 daddr { 2001:db8::/32, fd00::/8 } counter
 }
}
"#;
impl SystemdLab {
    pub(super) fn egress_setup(&mut self) -> Result<()> {
        let (status, _) = self.lab.runner.output(
            &Invocation::new("", "nft", &["list", "table", "inet", TABLE]),
            None,
        )?;
        if status.success() {
            return fail("occupied root egress detector");
        }
        self.lab.runner.input(
            &Invocation::new("", "nft", &["-f", "-"]),
            Some(RULES.as_bytes()),
        )?;
        self.cmd("ip", &["link", "add", "ctl0", "type", "dummy"])?;
        let control = (|| {
            self.cmd("ip", &["address", "add", "198.51.100.9/32", "dev", "ctl0"])?;
            self.cmd("ip", &["link", "set", "ctl0", "up"])?;
            self.cmd("ip", &["route", "add", "198.51.100.10/32", "dev", "ctl0"])?;
            self.lab.runner.output(
                &Invocation::new(
                    "",
                    "ping",
                    &["-I", "198.51.100.9", "-c", "1", "-W", "1", "198.51.100.10"],
                ),
                None,
            )?;
            if self.egress_count("egress-positive-control")? == 0 {
                return fail("root egress counter positive control was blind");
            }
            Ok(())
        })();
        let deleted = self.cmd("ip", &["link", "delete", "ctl0"]).map(|_| ());
        super::super::mutation::finish(control, deleted)?;
        self.cmd("nft", &["delete", "table", "inet", TABLE])?;
        self.lab.runner.input(
            &Invocation::new("", "nft", &["-f", "-"]),
            Some(RULES.as_bytes()),
        )?;
        self.egress_zero("egress-reset")
    }
    fn egress_count(&mut self, label: &str) -> Result<u64> {
        let text = self.cmd("nft", &["-j", "list", "table", "inet", TABLE])?;
        fs::write(
            self.lab.artifacts.join(format!("{label}-root-egress.json")),
            &text,
        )?;
        count(&text)
    }
    pub(super) fn egress_zero(&mut self, label: &str) -> Result<()> {
        if self.egress_count(label)? != 0 {
            return fail("lab or tunnel prefix escaped root namespace through non-up0 egress");
        }
        Ok(())
    }
}
fn count(text: &str) -> Result<u64> {
    let json: serde_json::Value = serde_json::from_str(text)?;
    let mut counts = Vec::new();
    for rule in json["nftables"]
        .as_array()
        .ok_or("nftables array")?
        .iter()
        .filter_map(|v| v.get("rule"))
    {
        for expr in rule["expr"].as_array().ok_or("rule expressions")? {
            if let Some(counter) = expr.get("counter") {
                counts.push(counter["packets"].as_u64().ok_or("packet counter")?);
            }
        }
    }
    if counts.len() != 4 {
        return fail("root egress detector missing counters");
    }
    Ok(counts.into_iter().sum())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detector_requires_all_four_counters_and_detects_nonzero() {
        let rules: Vec<_> = (0..4)
            .map(|n| serde_json::json!({"rule":{"expr":[{"counter":{"packets":n}}]}}))
            .collect();
        assert_eq!(
            count(&serde_json::json!({"nftables":rules}).to_string()).ok(),
            Some(6)
        );
        assert!(count(r#"{"nftables":[]}"#).is_err());
        assert!(!RULES.contains(" drop"));
        assert!(!RULES.contains(" reject"));
    }
}
