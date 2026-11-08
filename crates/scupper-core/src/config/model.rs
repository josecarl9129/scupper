//! Strict, editable input model. Only `ValidatedSite` is safe to render.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::types::{
    DurationStr, ExitId, ExitName, Failback, GatewayId, HeartbeatKind, HeartbeatReport, PublicKey,
    Role, SecretName, Severity, Standby, Tag, WebhookPreset, url_ref, wg_ref,
};

/// An editable site document. Call `validate` before using it to render.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteConfig {
    /// Schema version; only 1 is supported.
    pub schema: u32,
    /// Site identity and authority.
    pub site: Site,
    /// Named client-facing identities.
    pub identities: BTreeMap<String, Identity>,
    /// Gateways indexed by stable ID.
    pub gateways: BTreeMap<GatewayId, Gateway>,
    /// Global ordered exit policy.
    pub policy: Policy,
    /// Probe and health settings.
    #[serde(default)]
    pub health: HealthSettings,
    /// Named users.
    #[serde(default)]
    pub users: BTreeMap<String, User>,
    /// Named client devices.
    #[serde(default)]
    pub devices: BTreeMap<String, Device>,
    /// Optional delivery sinks.
    #[serde(default)]
    pub alerts: Alerts,
    /// Optional external dead-man heartbeat.
    pub heartbeat: Option<HeartbeatSettings>,
    /// Reserved R2 groups, explicitly rejected by validation.
    pub groups: Option<toml::Value>,
    /// Reserved R2 policies, explicitly rejected by validation.
    pub policies: Option<toml::Value>,
    /// Reserved R2 allow rules, explicitly rejected by validation.
    pub allow: Option<toml::Value>,
    /// Reserved provider settings; this release supports only exit provider `proton`.
    pub providers: Option<toml::Value>,
}

/// Site metadata shared by gateways.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Site {
    /// Human-readable site name.
    pub name: String,
    /// Primary gateway ID; must identify the sole M2 gateway.
    pub primary: GatewayId,
}

/// A client-facing `WireGuard` identity, containing only a reference to its private key.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// Public `WireGuard` key.
    pub public_key: PublicKey,
    /// Local reference in the `wg` secret directory.
    #[serde(deserialize_with = "wg_ref")]
    pub private_key_ref: SecretName,
    /// Host UDP listen port, 1–65535.
    pub listen_port: u32,
}

/// A gateway's namespace and tunnel configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Gateway {
    /// Owned network namespace, `scupper` in M2.
    pub netns: String,
    /// Host uplink interfaces; never tunnel interfaces.
    pub uplinks: Vec<String>,
    /// Client-facing literal IP and UDP port.
    pub endpoint: String,
    /// Client ingress tunnel.
    pub client_tunnel: ClientTunnel,
    /// Configured provider tunnels.
    pub exits: Vec<Exit>,
    /// Optional M5 API syntax, accepted for future rendering.
    pub api: Option<ApiSettings>,
    /// Optional DNS settings.
    pub dns: Option<DnsSettings>,
}

/// Client-facing interface and identity reference.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientTunnel {
    /// Interface name.
    pub ifname: String,
    /// Existing client-facing identity ID.
    pub identity: String,
    /// Gateway IPv4 address and client subnet prefix.
    pub address4: String,
    /// Reserved IPv6 prefix, rejected in M2.
    pub address6: Option<String>,
    /// `WireGuard` MTU; defaults to 1420.
    #[serde(default = "default_mtu")]
    pub mtu: u32,
}

/// One provider `WireGuard` tunnel.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Exit {
    /// Stable machine identifier.
    pub id: ExitId,
    /// Editable display name.
    pub name: ExitName,
    /// Optional labels.
    #[serde(default)]
    pub tags: Vec<Tag>,
    /// Provider; only `proton` is supported.
    pub provider: String,
    /// Interface name beginning with `ex-`.
    pub ifname: String,
    /// Local private-key reference.
    #[serde(deserialize_with = "wg_ref")]
    pub private_key_ref: SecretName,
    /// Provider peer's public key.
    pub peer_public_key: PublicKey,
    /// Provider literal IP and UDP port.
    pub endpoint: String,
    /// Exit's assigned IPv4 address and prefix.
    pub address4: String,
    /// Reserved IPv6 address, rejected in M2.
    pub address6: Option<String>,
    /// Provider DNS servers, all literal IPs.
    pub dns: Vec<String>,
    /// Persistent keepalive; defaults to 25 seconds.
    #[serde(default = "default_keepalive")]
    pub keepalive: DurationStr,
    /// `WireGuard` MTU; defaults to 1420.
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    /// Whether this exit may be selected; defaults to true.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// The ordered global failover policy.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Enabled exit IDs in preference order.
    pub exits: Vec<ExitId>,
    /// Manual by default.
    #[serde(default = "default_failback")]
    pub failback: Failback,
    /// Required healthy time before automatic failback; defaults to 10 minutes.
    #[serde(default = "default_failback_hold")]
    pub failback_hold: DurationStr,
    /// Minimum time between switches; defaults to 120 seconds.
    #[serde(default = "default_min_dwell")]
    pub min_dwell: DurationStr,
    /// Standby mode, hot by default. With one exit, hot has no effect.
    #[serde(default = "default_standby")]
    pub standby: Standby,
}

/// Health settings and the defaults from the design's configuration example.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HealthSettings {
    /// Maximum fresh handshake age; default 180 seconds.
    pub handshake_stale: DurationStr,
    /// Failover pending grace; default 30 seconds, less than handshake stale.
    pub failover_grace: DurationStr,
    /// Exit-IP HTTPS targets; defaults to ifconfig.me/ip and icanhazip.com.
    pub probe_targets: Vec<String>,
    /// Literal IPv4 forwarding probe destination.
    pub route_probe_dst4: String,
    /// Literal IPv6 forwarding probe destination (not an assigned address6).
    pub route_probe_dst6: String,
    /// HTTPS target for an explicitly requested speed test.
    pub speed_test_url: String,
    /// Whether absence of the supervisor yields verdict 5; default true.
    pub require_daemon: bool,
}
impl Default for HealthSettings {
    fn default() -> Self {
        Self {
            handshake_stale: DurationStr("180s".into()),
            failover_grace: DurationStr("30s".into()),
            probe_targets: vec![
                "https://ifconfig.me/ip".into(),
                "https://icanhazip.com/".into(),
            ],
            // Public forwarding probes from DESIGN §8.
            route_probe_dst4: "1.1.1.1".into(),
            route_probe_dst6: "2606:4700:4700::1111".into(),
            speed_test_url: "https://speed.example.net/25MB.bin".into(),
            require_daemon: true,
        }
    }
}

/// Site user.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    /// Authorization role.
    pub role: Role,
}

/// One client peer. Its address must be a host prefix (topology lemma T).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    /// Existing user's ID.
    pub user: String,
    /// Client public `WireGuard` key.
    pub public_key: PublicKey,
    /// Unique IPv4 host prefix inside each selected gateway's client subnet.
    pub address4: String,
    /// Reserved IPv6 host prefix, rejected in M2.
    pub address6: Option<String>,
    /// Optional SHA-256 API token digest as 64 hex digits, never a token.
    pub api_token_sha256: Option<String>,
    /// Existing gateways on which this peer is installed.
    pub gateways: Vec<GatewayId>,
}

/// Optional alert configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Alerts {
    /// Named delivery sinks.
    #[serde(default)]
    pub sinks: BTreeMap<String, AlertSink>,
}

/// Supported delivery transports; URLs are always local secret references.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum AlertSink {
    /// ntfy HTTP notification service.
    #[serde(rename = "ntfy")]
    Ntfy {
        /// Credential-bearing URL reference in the `url` directory.
        #[serde(deserialize_with = "url_ref")]
        url_ref: SecretName,
        /// Lowest delivered severity.
        min_severity: Severity,
    },
    /// HTTP JSON webhook.
    #[serde(rename = "webhook")]
    Webhook {
        /// Supported payload template.
        preset: WebhookPreset,
        /// Credential-bearing URL reference in the `url` directory.
        #[serde(deserialize_with = "url_ref")]
        url_ref: SecretName,
        /// Lowest delivered severity.
        min_severity: Severity,
    },
}
impl AlertSink {
    /// Returns the local credential reference for either transport.
    #[must_use]
    pub fn url_ref(&self) -> &SecretName {
        match self {
            Self::Ntfy { url_ref, .. } | Self::Webhook { url_ref, .. } => url_ref,
        }
    }
    /// Returns the minimum delivered event severity.
    #[must_use]
    pub fn min_severity(&self) -> Severity {
        match self {
            Self::Ntfy { min_severity, .. } | Self::Webhook { min_severity, .. } => *min_severity,
        }
    }
}

/// External dead-man heartbeat settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatSettings {
    /// Only healthchecks-compatible dead-man services are supported.
    pub kind: HeartbeatKind,
    /// Credential-bearing URL reference in the `url` directory.
    #[serde(deserialize_with = "url_ref")]
    pub url_ref: SecretName,
    /// Reporting interval, default 60 seconds.
    #[serde(default = "default_heartbeat_interval")]
    pub interval: DurationStr,
    /// Reporting mode, default `ok_only`.
    #[serde(default = "default_report")]
    pub report: HeartbeatReport,
}

/// Optional API settings, syntax checked even before M5.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiSettings {
    /// TCP listen port, 1–65535.
    pub port: u32,
}

/// Optional DNS settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsSettings {
    /// Must be true in this release.
    pub block_dot: bool,
    /// Whether the forwarder keeps an in-memory cache.
    pub cache: bool,
}

fn default_mtu() -> u32 {
    1420
}
fn default_true() -> bool {
    true
}
fn default_keepalive() -> DurationStr {
    DurationStr("25s".into())
}
fn default_failback() -> Failback {
    Failback::Manual
}
fn default_failback_hold() -> DurationStr {
    DurationStr("10m".into())
}
fn default_min_dwell() -> DurationStr {
    DurationStr("120s".into())
}
fn default_standby() -> Standby {
    Standby::Hot
}
fn default_heartbeat_interval() -> DurationStr {
    DurationStr("60s".into())
}
fn default_report() -> HeartbeatReport {
    HeartbeatReport::OkOnly
}
