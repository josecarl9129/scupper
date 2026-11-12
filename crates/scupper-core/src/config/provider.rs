//! Bounded, pure parsing of provider wg-quick files. Diagnostics retain no input.
use super::{ExitId, ExitName, PublicKey, types::valid_wg_secret};
use ipnet::IpNet;
use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, SocketAddr},
};
use zeroize::Zeroizing;

/// Maximum provider file size, checked before examining any syntax.
pub const MAX_PROVIDER_BYTES: usize = 16 * 1024;

/// A diagnostic containing only recognized section/key names and a static rule.
#[derive(Debug, thiserror::Error)]
#[error("[{section}] {key} = <redacted>: {rule}")]
pub struct ProviderError {
    section: &'static str,
    key: &'static str,
    rule: &'static str,
}
fn error(section: &'static str, key: &'static str, rule: &'static str) -> ProviderError {
    ProviderError { section, key, rule }
}

/// Parsed provider settings. Secret fields are zeroized and never formatted.
pub struct ProviderConfig {
    private_key: Zeroizing<String>,
    preshared_key: Option<Zeroizing<String>>,
    /// Provider peer's public key.
    pub peer_public_key: PublicKey,
    /// Numeric remote address and nonzero port.
    pub endpoint: SocketAddr,
    /// Assigned IPv4 host prefix.
    pub address4: String,
    /// Optional assigned IPv6 host prefix.
    pub address6: Option<String>,
    /// Literal resolver addresses.
    pub dns: Vec<IpAddr>,
    /// Optional MTU in 1280..=1500.
    pub mtu: Option<u16>,
    /// Optional keepalive in seconds; zero disables it.
    pub keepalive: Option<u16>,
    /// Whether the default IPv6 prefix is allowed.
    pub allows_ipv6: bool,
    /// Validated provider-derived suggestion.
    pub suggested_id: ExitId,
    /// Validated country name suggestion.
    pub suggested_name: ExitName,
    /// `NetShield` level from a provider comment, if present.
    pub netshield: Option<u8>,
}
impl fmt::Debug for ProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProviderConfig { PrivateKey: <redacted>, PresharedKey: <redacted>, settings: <redacted> }")
    }
}
impl ProviderConfig {
    /// Borrows canonical padded key bytes for a local secret consumer.
    #[must_use]
    pub fn private_key(&self) -> &[u8] {
        self.private_key.as_bytes()
    }
    /// Borrows canonical padded preshared key bytes, if supplied.
    #[must_use]
    pub fn preshared_key(&self) -> Option<&[u8]> {
        self.preshared_key.as_ref().map(|s| s.as_bytes())
    }
    /// Builds a display summary with the derived public key in base64.
    #[must_use]
    pub fn summary(&self, public: &PublicKey) -> ProviderSummary {
        ProviderSummary {
            public_key: public.clone(),
            endpoint: self.endpoint,
            netshield: self.netshield,
            ipv6: self.address6.is_some()
                || self.allows_ipv6
                || self.dns.iter().any(IpAddr::is_ipv6),
        }
    }
}

/// Confirmation data with no secret or arbitrary provider-text fields.
#[derive(Debug, Clone)]
pub struct ProviderSummary {
    /// Derived public key in canonical base64.
    pub public_key: PublicKey,
    /// Numeric endpoint.
    pub endpoint: SocketAddr,
    /// Provider filtering level.
    pub netshield: Option<u8>,
    /// Whether provider IPv6 settings will be ignored.
    pub ipv6: bool,
}
impl fmt::Display for ProviderSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key = self.public_key.as_str();
        if f.alternate() || self.public_key.bytes().is_err() || key.len() != 44 {
            write!(f, "public key {key}")?;
        } else {
            write!(f, "public key {}…{}", &key[..4], &key[key.len() - 4..])?;
        }
        write!(
            f,
            " · endpoint {} · NetShield {} · IPv4{}",
            self.endpoint,
            self.netshield
                .map_or_else(|| "unknown".into(), |n| n.to_string()),
            if self.ipv6 {
                " · IPv6 not used: client IPv6 fails closed"
            } else {
                ""
            }
        )
    }
}

fn known_key(key: &str) -> &'static str {
    match key {
        "PrivateKey" => "PrivateKey",
        "Address" => "Address",
        "DNS" => "DNS",
        "MTU" => "MTU",
        "PublicKey" => "PublicKey",
        "Endpoint" => "Endpoint",
        "AllowedIPs" => "AllowedIPs",
        "PersistentKeepalive" => "PersistentKeepalive",
        "PresharedKey" => "PresharedKey",
        "PostUp" => "PostUp",
        "PreUp" => "PreUp",
        "PostDown" => "PostDown",
        "PreDown" => "PreDown",
        "Table" => "Table",
        "SaveConfig" => "SaveConfig",
        "FwMark" => "FwMark",
        "ListenPort" => "ListenPort",
        _ => "<unknown>",
    }
}
fn secret(
    section: &'static str,
    key: &'static str,
    value: &str,
) -> Result<Zeroizing<String>, ProviderError> {
    let mut padded = Zeroizing::new(String::with_capacity(value.len().max(44)));
    padded.push_str(value);
    if padded.len() == 43 {
        padded.push('=');
    }
    let value = padded;
    if !valid_wg_secret(&value) {
        return Err(error(section, key, "expected a 32-byte base64 key"));
    }
    Ok(value)
}

/// Parses a provider file without filesystem, process, DNS or clock access.
///
/// # Errors
/// Refuses oversize input, unknown/duplicate sections or keys and invalid values.
#[allow(clippy::too_many_lines)]
pub fn parse_provider(input: &str) -> Result<ProviderConfig, ProviderError> {
    if input.len() > MAX_PROVIDER_BYTES {
        return Err(error("file", "size", "maximum 16 KiB"));
    }
    let mut section = "file";
    let mut sections = Vec::new();
    let mut fields = BTreeMap::new();
    let mut suggested_id = ExitId("imported".into());
    let mut suggested_name = ExitName("Imported exit".into());
    let mut netshield = None;
    for line in input.lines().map(str::trim) {
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#') {
            for word in comment.split_whitespace() {
                if let Some((country, number)) = word.split_once('#') {
                    let name = match country {
                        "CH" => Some("Switzerland"),
                        "NL" => Some("Netherlands"),
                        "DE" => Some("Germany"),
                        "US" => Some("United States"),
                        "GB" => Some("United Kingdom"),
                        "FR" => Some("France"),
                        _ if country.len() == 2
                            && country.bytes().all(|b| b.is_ascii_uppercase()) =>
                        {
                            Some(country)
                        }
                        _ => None,
                    };
                    if let Some(name) = name.filter(|_| {
                        !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit())
                    }) {
                        let id = ExitId(format!("{}-{number}", country.to_ascii_lowercase()));
                        let name = ExitName(name.into());
                        if id.is_valid() && name.is_valid() {
                            suggested_id = id;
                            suggested_name = name;
                        }
                    }
                }
            }
            if let Some(value) = comment.trim().strip_prefix("NetShield =") {
                netshield = value.trim().parse::<u8>().ok().filter(|n| *n <= 2);
            }
            continue;
        }
        if line.starts_with('[') {
            section = match line {
                "[Interface]" => "Interface",
                "[Peer]" => "Peer",
                _ => return Err(error("<unknown>", "section", "unsupported section")),
            };
            if sections.contains(&section) {
                return Err(error(section, "section", "duplicate section"));
            }
            sections.push(section);
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| error(section, "<unknown>", "expected key = value"))?;
        let key = known_key(key.trim());
        let allowed = matches!(
            (section, key),
            ("Interface", "PrivateKey" | "Address" | "DNS" | "MTU")
                | (
                    "Peer",
                    "PublicKey"
                        | "Endpoint"
                        | "AllowedIPs"
                        | "PersistentKeepalive"
                        | "PresharedKey"
                )
        );
        if !allowed {
            return Err(error(section, key, "unsupported key"));
        }
        if fields.insert((section, key), value.trim()).is_some() {
            return Err(error(section, key, "duplicate key"));
        }
    }
    for required in ["Interface", "Peer"] {
        if !sections.contains(&required) {
            return Err(error(required, "section", "missing section"));
        }
    }
    let required = |section, key| {
        fields
            .get(&(section, key))
            .copied()
            .ok_or_else(|| error(section, key, "missing key"))
    };
    let private_key = secret(
        "Interface",
        "PrivateKey",
        required("Interface", "PrivateKey")?,
    )?;
    let preshared_key = fields
        .get(&("Peer", "PresharedKey"))
        .map(|s| secret("Peer", "PresharedKey", s))
        .transpose()?;
    let public_text = required("Peer", "PublicKey")?;
    let public_unpadded = public_text.trim_end_matches('=');
    if public_unpadded == private_key.trim_end_matches('=')
        || preshared_key
            .as_ref()
            .is_some_and(|key| public_unpadded == key.trim_end_matches('='))
    {
        return Err(error(
            "Peer",
            "PublicKey",
            "public field must not repeat a secret value",
        ));
    }
    let mut peer_public_key = PublicKey(public_text.into());
    peer_public_key
        .bytes()
        .map_err(|_| error("Peer", "PublicKey", "expected a 32-byte base64 key"))?;
    if peer_public_key.0.len() == 43 {
        peer_public_key.0.push('=');
    }
    let endpoint = required("Peer", "Endpoint")?
        .parse::<SocketAddr>()
        .ok()
        .filter(|a| a.port() != 0)
        .ok_or_else(|| error("Peer", "Endpoint", "expected literal IP and port 1-65535"))?;
    let mut address4 = None;
    let mut address6 = None;
    for address in required("Interface", "Address")?.split(',').map(str::trim) {
        let net = address
            .parse::<IpNet>()
            .or_else(|_| address.parse::<IpAddr>().map(IpNet::from))
            .map_err(|_| error("Interface", "Address", "expected host addresses"))?;
        let target = if net.addr().is_ipv4() && net.prefix_len() == 32 {
            &mut address4
        } else if net.addr().is_ipv6() && net.prefix_len() == 128 {
            &mut address6
        } else {
            return Err(error(
                "Interface",
                "Address",
                "expected /32 or /128 host prefix",
            ));
        };
        if target.replace(net.to_string()).is_some() {
            return Err(error("Interface", "Address", "duplicate address family"));
        }
    }
    let address4 =
        address4.ok_or_else(|| error("Interface", "Address", "IPv4 host address required"))?;
    let dns = required("Interface", "DNS")?
        .split(',')
        .map(|s| {
            s.trim()
                .parse::<IpAddr>()
                .map_err(|_| error("Interface", "DNS", "expected literal IPs"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let allowed = required("Peer", "AllowedIPs")?
        .split(',')
        .map(str::trim)
        .collect::<Vec<_>>();
    let allows_ipv6 = allowed.contains(&"::/0");
    if !allowed.contains(&"0.0.0.0/0")
        || allowed.len() != if allows_ipv6 { 2 } else { 1 }
        || allowed.iter().any(|s| !matches!(*s, "0.0.0.0/0" | "::/0"))
    {
        return Err(error(
            "Peer",
            "AllowedIPs",
            "expected IPv4 default and optional IPv6 default",
        ));
    }
    let mtu = fields
        .get(&("Interface", "MTU"))
        .map(|s| {
            s.parse::<u16>()
                .ok()
                .filter(|n| (1280..=1500).contains(n))
                .ok_or_else(|| error("Interface", "MTU", "expected 1280-1500"))
        })
        .transpose()?;
    let keepalive = fields
        .get(&("Peer", "PersistentKeepalive"))
        .map(|s| {
            s.parse::<u16>()
                .map_err(|_| error("Peer", "PersistentKeepalive", "expected 0-65535 seconds"))
        })
        .transpose()?;
    Ok(ProviderConfig {
        private_key,
        preshared_key,
        peer_public_key,
        endpoint,
        address4,
        address6,
        dns,
        mtu,
        keepalive,
        allows_ipv6,
        suggested_id,
        suggested_name,
        netshield,
    })
}
