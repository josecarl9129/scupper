//! Strict TOML parsing with value-free errors and precise unknown-field paths.

use std::fmt;

use super::{SiteConfig, child};

/// The kind of parse failure; no source excerpt or supplied value is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseRule {
    /// Malformed TOML syntax.
    InvalidToml,
    /// A field outside the documented schema.
    UnknownField,
    /// A missing required field or a field with the wrong type or enum variant.
    InvalidShape,
    /// Schema versions other than 1.
    UnsupportedSchema,
}

/// Safe parse error. Unlike a TOML diagnostic, it never includes source text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// Field path when known; empty for a document-level syntax error.
    pub path: String,
    /// Parse failure identifier.
    pub rule: ParseRule,
}
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.path, self.rule)
    }
}
impl std::error::Error for ConfigError {}

/// Parses a strict schema-1 site document without I/O.
///
/// Semantic checks, including explicitly reserved R2 sections, belong to
/// `validate`. Unknown fields include their complete dotted/indexed paths.
///
/// # Errors
/// Returns a value-free error for malformed TOML, unknown fields, missing or
/// mistyped fields, invalid enum variants, or an unsupported schema version.
pub fn parse_site(text: &str) -> Result<SiteConfig, ConfigError> {
    let value: toml::Value = toml::from_str(text).map_err(|_| ConfigError {
        path: String::new(),
        rule: ParseRule::InvalidToml,
    })?;
    check_fields(&value, "root", "")?;
    if value
        .get("schema")
        .and_then(toml::Value::as_integer)
        .is_some_and(|v| v != 1)
    {
        return Err(ConfigError {
            path: "schema".into(),
            rule: ParseRule::UnsupportedSchema,
        });
    }
    value.try_into().map_err(|_| ConfigError {
        path: String::new(),
        rule: ParseRule::InvalidShape,
    })
}

// Field names live in this parsing-only schema. deny_unknown_fields on the
// model independently guards deserialization outside parse_site as well.
fn fields(shape: &str) -> &'static [(&'static str, &'static str)] {
    match shape {
        "root" => &[
            ("schema", ""),
            ("site", "site"),
            ("identities", "map:identity"),
            ("gateways", "map:gateway"),
            ("policy", "policy"),
            ("health", "health"),
            ("users", "map:user"),
            ("devices", "map:device"),
            ("alerts", "alerts"),
            ("heartbeat", "heartbeat"),
            ("groups", "opaque"),
            ("policies", "opaque"),
            ("allow", "opaque"),
            ("providers", "opaque"),
        ],
        "site" => &[("name", ""), ("primary", "")],
        "identity" => &[
            ("public_key", ""),
            ("private_key_ref", ""),
            ("listen_port", ""),
        ],
        "gateway" => &[
            ("netns", ""),
            ("uplinks", ""),
            ("endpoint", ""),
            ("client_tunnel", "client"),
            ("exits", "array:exit"),
            ("api", "api"),
            ("dns", "dns"),
        ],
        "client" => &[
            ("ifname", ""),
            ("identity", ""),
            ("address4", ""),
            ("address6", ""),
            ("mtu", ""),
        ],
        "exit" => &[
            ("id", ""),
            ("name", ""),
            ("tags", ""),
            ("provider", ""),
            ("ifname", ""),
            ("private_key_ref", ""),
            ("peer_public_key", ""),
            ("endpoint", ""),
            ("address4", ""),
            ("address6", ""),
            ("dns", ""),
            ("keepalive", ""),
            ("mtu", ""),
            ("enabled", ""),
        ],
        "policy" => &[
            ("exits", ""),
            ("failback", ""),
            ("failback_hold", ""),
            ("min_dwell", ""),
            ("standby", ""),
        ],
        "health" => &[
            ("handshake_stale", ""),
            ("failover_grace", ""),
            ("probe_targets", ""),
            ("route_probe_dst4", ""),
            ("route_probe_dst6", ""),
            ("speed_test_url", ""),
            ("require_daemon", ""),
        ],
        "user" => &[("role", "")],
        "device" => &[
            ("user", ""),
            ("public_key", ""),
            ("address4", ""),
            ("address6", ""),
            ("api_token_sha256", ""),
            ("gateways", ""),
        ],
        "alerts" => &[("sinks", "map:sink"), ("fail_closed_grace_seconds", "")],
        "sink" => &[
            ("kind", ""),
            ("preset", ""),
            ("url_ref", ""),
            ("min_severity", ""),
        ],
        "heartbeat" => &[
            ("kind", ""),
            ("url_ref", ""),
            ("interval", ""),
            ("report", ""),
        ],
        "api" => &[("port", "")],
        "dns" => &[("block_dot", ""), ("cache", "")],
        _ => &[],
    }
}
fn check_fields(value: &toml::Value, shape: &str, path: &str) -> Result<(), ConfigError> {
    if shape.is_empty() || shape == "opaque" {
        return Ok(());
    }
    if let Some(element) = shape.strip_prefix("array:") {
        if let Some(items) = value.as_array() {
            for (i, item) in items.iter().enumerate() {
                check_fields(item, element, &format!("{path}[{i}]"))?;
            }
        }
    } else if let Some(element) = shape.strip_prefix("map:") {
        if let Some(items) = value.as_table() {
            for (name, item) in items {
                check_fields(item, element, &child(path, name))?;
            }
        }
    } else if let Some(table) = value.as_table() {
        for (key, item) in table {
            let next = child(path, key);
            let Some((_, element)) = fields(shape).iter().find(|(name, _)| key == name) else {
                return Err(ConfigError {
                    path: next,
                    rule: ParseRule::UnknownField,
                });
            };
            // An ntfy sink has no preset, even though webhooks do.
            if shape == "sink"
                && key == "preset"
                && table.get("kind").and_then(toml::Value::as_str) == Some("ntfy")
            {
                return Err(ConfigError {
                    path: next,
                    rule: ParseRule::UnknownField,
                });
            }
            check_fields(item, element, &next)?;
        }
    }
    Ok(())
}
