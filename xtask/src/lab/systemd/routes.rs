//! Root containment for documentation destinations only.
use super::{Result, SystemdLab, fail, fs};
use serde_json::Value;

// Never blackhole IPv4 client/tunnel sources: reverse-path validation would drop
// incoming packets before forwarding. More-specific lab links remain usable. Everything else in
// these ranges must terminate here instead of following a runner default route.
const BLACKHOLES: &[(&str, &str)] = &[
    ("-4", "192.0.2.0/24"),
    ("-4", "198.51.100.0/24"),
    ("-4", "203.0.113.0/24"),
    ("-6", "2001:db8::/32"),
];
fn blackhole(text: &str, prefix: &str) -> Result<()> {
    let routes: Vec<Value> = serde_json::from_str(text)?;
    if routes.len() != 1 || routes[0]["dst"] != prefix || routes[0]["type"] != "blackhole" {
        return fail(format!("missing exclusive root blackhole for {prefix}"));
    }
    Ok(())
}
impl SystemdLab {
    pub(super) fn root_routes_setup(&mut self) -> Result<()> {
        for &(family, prefix) in BLACKHOLES {
            // Exclusive add: never replace an existing runner route. Register
            // immediately so a later failed add/readback still gets cleanup.
            self.cmd(
                "ip",
                &[
                    family,
                    "route",
                    "add",
                    "blackhole",
                    prefix,
                    "proto",
                    "static",
                ],
            )?;
            self.root_routes.push((family, prefix));
        }
        self.root_routes_verify("installed")
    }
    pub(super) fn root_routes_verify(&mut self, label: &str) -> Result<()> {
        let mut evidence = Vec::new();
        for (family, prefix) in self.root_routes.clone() {
            let text = self.cmd("ip", &[family, "-j", "route", "show", "exact", prefix])?;
            evidence.push(serde_json::json!({"family":family,"prefix":prefix,"routes":serde_json::from_str::<Value>(&text)?}));
            fs::write(
                self.lab
                    .artifacts
                    .join(format!("root-blackholes-{label}.json")),
                serde_json::to_vec_pretty(&evidence)?,
            )?;
            blackhole(&text, prefix)?;
        }
        Ok(())
    }
    pub(super) fn root_routes_cleanup(&mut self) -> Result<()> {
        let mut evidence = Vec::new();
        let mut errors = Vec::new();
        // Attempt every owned route, including on partial setup or failure.
        for (family, prefix) in std::mem::take(&mut self.root_routes).into_iter().rev() {
            let result = (|| -> Result<()> {
                let text = self.cmd("ip", &[family, "-j", "route", "show", "exact", prefix])?;
                blackhole(&text, prefix)?;
                self.cmd(
                    "ip",
                    &[
                        family,
                        "route",
                        "del",
                        "blackhole",
                        prefix,
                        "proto",
                        "static",
                    ],
                )?;
                let text = self.cmd("ip", &[family, "-j", "route", "show", "exact", prefix])?;
                let routes: Vec<Value> = serde_json::from_str(&text)?;
                if !routes.is_empty() {
                    return fail(format!("root route remains after cleanup: {prefix}"));
                }
                Ok(())
            })();
            evidence.push(serde_json::json!({"prefix":prefix,"removed":result.is_ok(),"error":result.as_ref().err().map(ToString::to_string)}));
            if let Err(error) = result {
                errors.push(error.to_string());
            }
        }
        fs::write(
            self.lab.artifacts.join("root-blackholes-cleanup.json"),
            serde_json::to_vec_pretty(&evidence)?,
        )?;
        if !errors.is_empty() {
            return fail(errors.join("; "));
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requires_blackhole_at_exact_prefix() {
        for (_, prefix) in BLACKHOLES {
            let text = serde_json::json!([{"dst":prefix,"type":"blackhole"}]).to_string();
            blackhole(&text, prefix).unwrap();
            assert!(blackhole(&text.replace("blackhole", "unicast"), prefix).is_err());
            assert!(blackhole(&text, "0.0.0.0/0").is_err());
        }
        for source in ["10.99.0.0/24", "10.2.0.0/24", "fd00::/8"] {
            assert!(!BLACKHOLES.iter().any(|(_, prefix)| *prefix == source));
        }
        assert!(blackhole("[]", "10.99.0.0/24").is_err());
        assert!(blackhole(r#"[{"dst":"10.99.0.0/24","dev":"eth0"}]"#, "10.99.0.0/24").is_err());
    }
}
