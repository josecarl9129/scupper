//! Configuration vocabulary; deserialization preserves invalid input for validation.

use std::{fmt, time::Duration};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::Rule;
use crate::rules::IfName;

macro_rules! text_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
        #[serde(transparent)]
        pub struct $name(pub String);
        impl $name {
            /// Borrows the configured text. Syntax is checked by `validate`.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}
text_type!(
    GatewayId,
    "Stable gateway identifier, used for pure gateway selection."
);
text_type!(
    ExitId,
    "Stable exit identifier; validation restricts it to 1–32 lowercase ID characters."
);
text_type!(
    ExitName,
    "Editable printable exit name; validation enforces gateway-local uniqueness."
);
text_type!(
    Tag,
    "An exit label using lowercase letters, digits and hyphens."
);
text_type!(
    DurationStr,
    "A positive integer duration with unit s, m or h, checked by validation."
);
text_type!(
    PublicKey,
    "A public `WireGuard` key. Its base64 text is public and safe to display."
);

impl DurationStr {
    /// Converts a valid duration to seconds, checking arithmetic overflow.
    ///
    /// # Errors
    /// Returns `InvalidDuration` for zero, fractions, unsupported units or overflow.
    pub fn duration(&self) -> Result<Duration, Rule> {
        let (number, unit) = self
            .0
            .split_at_checked(self.0.len().saturating_sub(1))
            .ok_or(Rule::InvalidDuration)?;
        if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Rule::InvalidDuration);
        }
        let multiplier = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 3600,
            _ => return Err(Rule::InvalidDuration),
        };
        let seconds = number
            .parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(multiplier))
            .filter(|n| *n > 0)
            .ok_or(Rule::InvalidDuration)?;
        Ok(Duration::from_secs(seconds))
    }
}

impl PublicKey {
    /// Decodes exactly 32 public bytes from standard, canonical padded base64.
    ///
    /// # Errors
    /// Returns `InvalidPublicKey` without including the supplied text.
    pub fn bytes(&self) -> Result<[u8; 32], Rule> {
        key_bytes(&self.0).ok_or(Rule::InvalidPublicKey)
    }
}

// `WireGuard` keys are canonical 44-byte base64 (or the equivalent unpadded
// 43 bytes). Keeping this tiny fixed-size decoder here avoids a codec dependency.
pub(super) fn key_bytes(text: &str) -> Option<[u8; 32]> {
    decode_key(text.as_bytes(), false)
}

fn decode_key(input: &[u8], url_safe: bool) -> Option<[u8; 32]> {
    if !(input.len() == 43 || (input.len() == 44 && input[43] == b'=')) {
        return None;
    }
    let mut output = [0; 32];
    let mut bits = 0_u32;
    let mut count = 0;
    let mut index = 0;
    for byte in &input[..43] {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'-' if url_safe => 62,
            b'_' if url_safe => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            output[index] = (bits >> count).to_le_bytes()[0];
            index += 1;
        }
    }
    (bits.trailing_zeros() >= 2).then_some(output)
}

// Check every offset, including URL-safe and unpadded keys. Preserve the
// conservative padded-key check even for noncanonical padding bits.
pub(super) fn contains_key(text: &str) -> bool {
    text.as_bytes()
        .windows(43)
        .any(|window| decode_key(window, true).is_some())
        || text.as_bytes().windows(44).any(|window| {
            window[43] == b'='
                && window[..43]
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_'))
        })
}

/// Secret directory selected by the schema field, never by config input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    /// `WireGuard` private keys.
    Wg,
    /// Credential-bearing delivery URLs.
    Url,
}

/// A local secret reference, never the contents of a secret file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretName {
    kind: SecretKind,
    name: String,
}
impl SecretName {
    /// Returns the schema-derived secret directory.
    #[must_use]
    pub fn kind(&self) -> SecretKind {
        self.kind
    }
    /// Returns the reference name; `validate` checks its grammar.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Builds a reference after checking its basename grammar.
    ///
    /// # Errors
    /// Returns a value-free error for an invalid reference.
    pub fn new(kind: SecretKind, name: &str) -> Result<Self, Rule> {
        let result = Self {
            kind,
            name: name.into(),
        };
        if result.valid() {
            Ok(result)
        } else {
            Err(Rule::InvalidSecretRef)
        }
    }
    /// Checks the reference basename without filesystem access.
    #[must_use]
    pub fn valid(&self) -> bool {
        (1..=63).contains(&self.name.len())
            && self
                .name
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && self
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    }
}
impl Serialize for SecretName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.name)
    }
}
pub(super) fn wg_ref<'de, D: Deserializer<'de>>(d: D) -> Result<SecretName, D::Error> {
    Ok(SecretName {
        kind: SecretKind::Wg,
        name: String::deserialize(d)?,
    })
}
pub(super) fn url_ref<'de, D: Deserializer<'de>>(d: D) -> Result<SecretName, D::Error> {
    Ok(SecretName {
        kind: SecretKind::Url,
        name: String::deserialize(d)?,
    })
}

/// A validated exit interface, constructible only during site validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitIfname(IfName);
impl ExitIfname {
    pub(super) fn validated(text: &str) -> Option<Self> {
        (valid_exit_ifname(text) && valid_ifname(text))
            .then(|| IfName::site_name(text).ok().map(Self))
            .flatten()
    }
    /// Borrows the shared interface type used by ruleset rendering.
    #[must_use]
    pub fn ifname(&self) -> &IfName {
        &self.0
    }
    /// Borrows the interface text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
impl fmt::Display for ExitIfname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
pub(super) fn id_chars(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub(super) fn valid_id(text: &str) -> bool {
    text.len() <= 32 && starts_id(text) && id_chars(text)
}
fn starts_id(text: &str) -> bool {
    text.bytes()
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}
pub(super) fn valid_ifname(text: &str) -> bool {
    text.len() <= 15 && starts_id(text) && id_chars(text) && IfName::site_name(text).is_ok()
}

macro_rules! choices {
    ($name:ident, $doc:literal, $($variant:ident => $text:literal),+ $(,)?) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
        pub enum $name { $(#[doc = concat!("`", $text, "`")] #[serde(rename = $text)] $variant),+ }
    };
}
choices!(Failback, "How a recovered preferred exit becomes active.", Manual => "manual", Auto => "auto");
choices!(Standby, "Whether an eligible standby remains connected.", Hot => "hot", Cold => "cold");
choices!(Role, "Site user authorization role.", Admin => "admin", User => "user");
choices!(Severity, "Minimum event severity delivered to a sink.", Info => "info", Warning => "warning", Critical => "critical");
choices!(WebhookPreset, "Supported webhook payload format.", Telegram => "telegram", Pushover => "pushover", Generic => "generic");
choices!(HeartbeatKind, "Supported dead-man heartbeat service.", Healthchecks => "healthchecks");
choices!(HeartbeatReport, "When and how heartbeat verdicts are reported.", OkOnly => "ok_only", StatusCode => "status_code");

pub(super) fn valid_exit_ifname(text: &str) -> bool {
    text.strip_prefix("ex-").is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    })
}

/// Checks strict HTTPS syntax without allocating or retaining the supplied URL.
#[must_use]
pub fn valid_https_url(text: &str) -> bool {
    super::network::https_host(text).is_some()
}

/// Checks exactly 44 padded standard-base64 characters encoding 32 bytes.
/// The caller may remove one trailing newline before validation.
#[must_use]
pub fn valid_wg_secret(text: &str) -> bool {
    // Validate syntax without constructing a second copy of private key bytes.
    let input = text.as_bytes();
    (input.len() == 44 && input[43] == b'=')
        && input[..43]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
        && input.get(42).is_some_and(|b| {
            matches!(
                b,
                b'A' | b'E'
                    | b'I'
                    | b'M'
                    | b'Q'
                    | b'U'
                    | b'Y'
                    | b'c'
                    | b'g'
                    | b'k'
                    | b'o'
                    | b's'
                    | b'w'
                    | b'0'
                    | b'4'
                    | b'8'
            )
        })
}
