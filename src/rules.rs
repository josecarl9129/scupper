//! Validated inputs and a pure renderer for the v1 fail-closed ruleset.

use std::{fmt, net::Ipv4Addr, str::FromStr};

use thiserror::Error;

/// A configuration failure that prevents rendering unsafe or ambiguous rules.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// Rejects unsafe syntax before a name can enter any interface field.
    #[error("config: client_iface/exit_iface/uplink_iface: {reason}")]
    InvalidInterfaceName {
        /// Why the name cannot safely identify a Linux interface in nftables.
        reason: &'static str,
    },
    /// Prevents interface roles from collapsing into an uplink accept path.
    #[error("config: {field} must differ from {other}")]
    InterfaceConflict {
        /// The interface field whose role conflicts with another field.
        field: &'static str,
        /// The other field sharing the same interface name.
        other: &'static str,
    },
    /// Rejects addresses that cannot identify an individual tunnel endpoint.
    #[error("config: {field} {reason}")]
    InvalidAddress {
        /// The address field that would make the configuration unsafe.
        field: &'static str,
        /// Why the address is unsuitable for a tunnel endpoint.
        reason: &'static str,
    },
    /// Prevents the client and exit endpoints from sharing an identity.
    #[error("config: client_addr must differ from exit_addr")]
    AddressConflict,
}

/// A Linux interface name restricted to syntax safe inside nftables quotes.
///
/// The private representation prevents callers from bypassing validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfName(String);

impl IfName {
    /// Validates a 1–15 byte ASCII name without quote or statement injection.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidInterfaceName`] for invalid length,
    /// characters, or the reserved names `.` and `..`. Since the name has no
    /// assigned role yet, the error identifies all three interface fields.
    pub fn new(name: &str) -> Result<Self, ConfigError> {
        let reason = if name.is_empty() || name.len() > 15 {
            Some("must contain 1 to 15 bytes")
        } else if name == "." || name == ".." {
            Some("must not be . or ..")
        } else if !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            Some("must contain only ASCII letters, digits, '.', '_' or '-'")
        } else {
            None
        };

        if let Some(reason) = reason {
            return Err(ConfigError::InvalidInterfaceName { reason });
        }
        Ok(Self(name.to_owned()))
    }

    /// Borrows the validated name for safe, quoted interface matching.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for IfName {
    type Err = ConfigError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::new(name)
    }
}

impl fmt::Display for IfName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Inputs for the lab-only v1 ruleset, with distinct tunnel and uplink roles.
///
/// Fields are public to allow configuration assembly without duplicate setters.
/// Interface syntax is enforced by [`IfName`]; [`ruleset`] always validates the
/// relationships and addresses before emitting any rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V1Config {
    /// Client ingress tunnel, permitted to forward only to the exit tunnel.
    pub client_iface: IfName,
    /// VPN exit tunnel, the only permitted forwarding and masquerade target.
    pub exit_iface: IfName,
    /// Host uplink, excluded from forwarding accepts and guarded on output.
    pub uplink_iface: IfName,
    /// Exit tunnel source address blocked from escaping over the host uplink.
    pub exit_addr: Ipv4Addr,
    /// Client tunnel identity; validated but unused by the v1 ruleset text.
    pub client_addr: Ipv4Addr,
}

impl Default for V1Config {
    /// Preserves v1's fixed tunnel names and private endpoint addresses.
    fn default() -> Self {
        Self {
            // These fixed ASCII literals satisfy the private IfName invariant.
            client_iface: IfName("wg0".to_owned()),
            exit_iface: IfName("proton0".to_owned()),
            uplink_iface: IfName("eth0".to_owned()),
            exit_addr: Ipv4Addr::new(10, 2, 0, 2),
            client_addr: Ipv4Addr::new(10, 99, 0, 2),
        }
    }
}

impl V1Config {
    /// Checks that endpoint and interface identities preserve separate roles.
    ///
    /// In particular, an exit equal to the uplink would turn the forwarding
    /// accept and masquerade rules into a plaintext escape path.
    ///
    /// # Errors
    ///
    /// Returns a field-naming [`ConfigError`] for overlapping interface roles,
    /// unspecified, broadcast or multicast addresses, or equal endpoints.
    pub fn validate(&self) -> Result<(), ConfigError> {
        for (field, name, other, other_name) in [
            (
                "client_iface",
                &self.client_iface,
                "exit_iface",
                &self.exit_iface,
            ),
            (
                "exit_iface",
                &self.exit_iface,
                "uplink_iface",
                &self.uplink_iface,
            ),
            (
                "client_iface",
                &self.client_iface,
                "uplink_iface",
                &self.uplink_iface,
            ),
        ] {
            if name == other_name {
                return Err(ConfigError::InterfaceConflict { field, other });
            }
        }

        for (field, address) in [
            ("exit_addr", self.exit_addr),
            ("client_addr", self.client_addr),
        ] {
            let reason = if address.is_unspecified() {
                Some("must not be unspecified")
            } else if address.is_broadcast() {
                Some("must not be broadcast")
            } else if address.is_multicast() {
                Some("must not be multicast")
            } else {
                None
            };
            if let Some(reason) = reason {
                return Err(ConfigError::InvalidAddress { field, reason });
            }
        }
        if self.exit_addr == self.client_addr {
            return Err(ConfigError::AddressConflict);
        }
        Ok(())
    }
}

/// Renders the complete v1 nftables file without performing any I/O.
///
/// Forward `policy drop` closes every path except client→exit and directional
/// exit→client established/related replies. A broad established accept would
/// permit replies on an uplink path. Masquerade applies only to the exit.
/// The output chain blocks locally generated exit-source traffic on the uplink;
/// other host traffic remains permitted, as required for v1 parity.
/// Interface matches use quoted names so links need not exist at load time.
///
/// # Errors
///
/// Returns [`ConfigError`] if validation fails, without rendering a ruleset.
pub fn ruleset(cfg: &V1Config) -> Result<String, ConfigError> {
    cfg.validate()?;

    Ok(format!(
        concat!(
            "#!/usr/sbin/nft -f\n",
            "# Generated by scupper, do not edit. Regenerate with: scupper apply\n",
            "# The kill switch is the absence of any {uplink} exit path below.\n",
            "flush ruleset\n",
            "\n",
            "table inet scupper {{\n",
            "\tchain forward {{\n",
            "\t\ttype filter hook forward priority 0; policy drop;\n",
            "\t\tiifname \"{client}\" oifname \"{exit}\" accept\n",
            "\t\tiifname \"{exit}\" oifname \"{client}\" ct state established,related accept\n",
            "\t}}\n",
            "\n",
            "\tchain postrouting {{\n",
            "\t\ttype nat hook postrouting priority 100;\n",
            "\t\toifname \"{exit}\" masquerade\n",
            "\t}}\n",
            "\n",
            "\tchain output {{\n",
            "\t\ttype filter hook output priority 0; policy accept;\n",
            "\t\toifname \"{uplink}\" ip saddr {exit_addr} drop\n",
            "\t}}\n",
            "}}\n",
        ),
        client = cfg.client_iface,
        exit = cfg.exit_iface,
        uplink = cfg.uplink_iface,
        exit_addr = cfg.exit_addr,
    ))
}
