//! Pure schema-1 event, local control socket, and JSON output vocabulary.

mod control;
mod event;

pub use control::*;
pub use event::*;
pub use scupper_core::{
    config::{ExitId, GatewayId},
    verdict::v2::Report,
};
use serde::{Deserialize, Serialize};

/// Caller-supplied wall time in whole seconds since the Unix epoch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UnixSeconds(pub u64);

/// A validated operational identity, never arbitrary diagnostic text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Identifier(String);
impl TryFrom<String> for Identifier {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if ExitId(value.clone()).is_valid() {
            Ok(Self(value))
        } else {
            Err("invalid identifier")
        }
    }
}
impl From<Identifier> for String {
    fn from(value: Identifier) -> Self {
        value.0
    }
}

impl From<&ExitId> for Identifier {
    /// Converts a core identity, replacing invalid configuration text with a
    /// fixed value so raw text can never enter the audit schema.
    fn from(value: &ExitId) -> Self {
        Self::try_from(value.as_str().to_owned()).unwrap_or_else(|_| Self("invalid-id".into()))
    }
}

// The declaration and its serialization samples share one source of truth.
// Every new variant and every field must supply a sample expression.
macro_rules! sampled_enum {
    (
        $(#[$meta:meta])* pub enum $name:ident, $samples:ident {
            $( $(#[$variant_meta:meta])* $variant:ident
               $( { $( $(#[$field_meta:meta])* $field:ident: $ty:ty = $sample:expr ),* $(,)? } )?
            ),* $(,)?
        }
    ) => {
        $(#[$meta])* pub enum $name {
            $( $(#[$variant_meta])* $variant $( { $( $(#[$field_meta])* $field: $ty ),* } )? ),*
        }
        #[cfg(test)]
        impl $name {
            pub(crate) const NAMES: &'static [&'static str] = &[$(stringify!($variant)),*];
        }
        #[cfg(test)]
        pub(crate) fn $samples() -> Vec<$name> {
            vec![$( $name::$variant $( { $( $field: $sample ),* } )? ),*]
        }
    };
}
pub(crate) use sampled_enum;

macro_rules! vocabulary {
    ($name:ident, $doc:literal, $($variant:ident),+ $(,)?) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub enum $name { $(#[doc = stringify!($variant)] $variant),+ }
        #[cfg(test)]
        impl $name {
            pub(crate) const NAMES: &'static [&'static str] = &[$(stringify!($variant)),+];
        }
    };
}
pub(crate) use vocabulary;
