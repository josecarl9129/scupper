//! Narrow, bounded SSH deploy protocol. No caller-supplied command or path.
use crate::Identifier;
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

/// Maximum request size on SSH stdin.
pub const MAX_REMOTE_REQUEST: usize = 1024 * 1024;
/// Validated SHA256 digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ReleaseHash(String);
impl TryFrom<String> for ReleaseHash {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            Ok(Self(value))
        } else {
            Err("invalid sha256")
        }
    }
}
impl From<ReleaseHash> for String {
    fn from(value: ReleaseHash) -> Self {
        value.0
    }
}
impl ReleaseHash {
    /// Lowercase hexadecimal digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
/// Allow-listed operations, each with strictly typed arguments.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", content = "args", deny_unknown_fields)]
pub enum DeployOp {
    /// Create a unique staging directory; report installed/fresh.
    Prepare {
        /// Deployment identifier, using the socket identifier type.
        id: Identifier,
    },
    /// Verify the copied archive before extracting any member.
    Stage {
        /// Deployment identifier.
        id: Identifier,
        /// Expected release checksum from SHA256SUMS.
        sha256: ReleaseHash,
    },
    /// Run the staged installer's read-only plan.
    Plan {
        /// Deployment identifier.
        id: Identifier,
    },
    /// Apply the staged installer and restart services in order.
    Switch {
        /// Deployment identifier.
        id: Identifier,
        /// Digest returned with the exact confirmed plan.
        plan_sha256: ReleaseHash,
    },
    /// Run the installed gateway check.
    Check {
        /// Deployment identifier.
        id: Identifier,
    },
}
impl DeployOp {
    /// Validated staging identifier.
    #[must_use]
    pub fn id(&self) -> String {
        let (Self::Prepare { id }
        | Self::Stage { id, .. }
        | Self::Plan { id }
        | Self::Switch { id, .. }
        | Self::Check { id }) = self;
        String::from(id.clone())
    }
}
/// Read-only plan and the digest that must accompany Switch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployPlan {
    /// Human-readable installation plan.
    pub plan: String,
    /// Digest of the plan and all installation preconditions.
    pub plan_sha256: ReleaseHash,
}
/// Failed switch outcome, carried across re-exec and SSH by distinct exit codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchOutcome {
    /// No mutation was attempted; non-mutation is established.
    RefusedNoChange,
    /// This switch renamed at least one binary before failing.
    FailedAfterRename,
    /// Completed non-binary mutations preceded the failure.
    FailedAfterChange,
    /// A failed write or command may have partially changed state.
    PossiblyChanged,
    /// The child or connection was lost after starting the switch.
    Unknown,
}
impl SwitchOutcome {
    /// Reserved remote exit status for this outcome.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::RefusedNoChange => 20,
            Self::FailedAfterRename => 21,
            Self::Unknown => 22,
            Self::FailedAfterChange => 23,
            Self::PossiblyChanged => 24,
        }
    }
    /// Decode a remote outcome; unrecognized failures have an unknown outcome.
    #[must_use]
    pub const fn from_exit_code(code: u8) -> Self {
        match code {
            20 => Self::RefusedNoChange,
            21 => Self::FailedAfterRename,
            23 => Self::FailedAfterChange,
            24 => Self::PossiblyChanged,
            _ => Self::Unknown,
        }
    }
}
/// One correlated SSH request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployRequest {
    /// Same identifier validator used by the local control socket.
    pub request_id: Identifier,
    /// A fixed operation with typed data.
    #[serde(flatten)]
    pub operation: DeployOp,
}
/// Reads at most 1 MiB plus one sentinel, rejecting unknown fields and operations.
/// # Errors
/// Rejects oversized, malformed, extra-field and invalid-identifier requests.
pub fn read_deploy(reader: impl Read) -> io::Result<DeployRequest> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_REMOTE_REQUEST + 1) as u64)
        .read_to_end(&mut bytes)?;
    let invalid = || io::Error::other("invalid remote request");
    if bytes.len() > MAX_REMOTE_REQUEST {
        return Err(invalid());
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let object = value.as_object().ok_or_else(invalid)?;
    if object.len() != 3
        || !["request_id", "op", "args"]
            .iter()
            .all(|key| object.contains_key(*key))
    {
        return Err(invalid());
    }
    serde_json::from_slice(&bytes).map_err(|_| invalid())
}
