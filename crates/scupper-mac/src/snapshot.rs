//! Pure bounded storage model and A-first snapshot selection. No physical I/O.
use crate::platform::SysError;
use scupper_core::mac::{
    TunnelGeneration,
    lifecycle::{Durable, ReferenceEntry, ReferenceIntent, Step},
    policy::Form,
    verify::{Action, Context, Reason},
};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, DeserializeSeed, SeqAccess, Visitor},
};
use sha2::{Digest, Sha256};
use std::{fmt, marker::PhantomData, net::SocketAddrV4, ops::Deref};

/// Physical size of each independently stored copy.
pub const COPY_BYTES: usize = 16 * 1024;
/// Snapshot signature, including its family version.
pub const MAGIC: [u8; 8] = *b"SCPMACS\x02";
/// Supported storage format.
pub const FORMAT: u32 = 2;
/// Largest JSON body that fits with the header and digest.
pub const BODY_MAX: usize = COPY_BYTES - 24 - 32;
/// Exclusive upper limit for persistent counters.
pub const COUNTER_MAX: u64 = 1 << 62;

/// Failure to represent, decode, or validate a snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotError {
    /// A collection or text exceeds its storage limit.
    #[error("snapshot bound exceeded")]
    Bound,
    /// Invalid syntax, character, or identity.
    #[error("invalid snapshot value")]
    Invalid,
    /// A persistent counter is exhausted.
    #[error("snapshot counter exhausted")]
    Counter,
    /// The mirrored lifecycle state violates an invariant.
    #[error("invalid snapshot machine")]
    Machine,
    /// Evidence is not the canonical, exact core entry set.
    #[error("snapshot annotation mismatch")]
    AnnotationMismatch,
    /// The encoded JSON does not fit the physical copy.
    #[error("snapshot body too large")]
    BodyTooLarge,
}

/// Collection whose construction and deserialization enforce its element limit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct BoundedVec<T, const N: usize>(Vec<T>);
impl<T, const N: usize> Default for BoundedVec<T, N> {
    fn default() -> Self {
        Self(Vec::new())
    }
}
impl<T, const N: usize> TryFrom<Vec<T>> for BoundedVec<T, N> {
    type Error = SnapshotError;
    fn try_from(values: Vec<T>) -> Result<Self, Self::Error> {
        if values.len() > N {
            return Err(SnapshotError::Bound);
        }
        Ok(Self(values))
    }
}
impl<T, const N: usize> Deref for BoundedVec<T, N> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<T, const N: usize> BoundedVec<T, N> {
    /// Append without allowing an allocation beyond the element limit.
    ///
    /// # Errors
    /// Returns `Bound` if the collection is full.
    pub fn try_push(&mut self, value: T) -> Result<(), SnapshotError> {
        if self.len() == N {
            return Err(SnapshotError::Bound);
        }
        // Reserve exactly the next slot, rather than Vec's geometric growth.
        self.0.reserve_exact(1);
        self.0.push(value);
        Ok(())
    }
}
impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for BoundedVec<T, N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BoundedVisitor<T, const N: usize>(PhantomData<T>);
        // At N+1, fail before asking T to deserialize or allocate anything.
        struct RejectExtra;
        impl<'de> DeserializeSeed<'de> for RejectExtra {
            type Value = ();
            fn deserialize<D: Deserializer<'de>>(self, _: D) -> Result<(), D::Error> {
                Err(de::Error::custom("snapshot collection bound exceeded"))
            }
        }
        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for BoundedVisitor<T, N> {
            type Value = BoundedVec<T, N>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "at most {N} elements")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = BoundedVec::default();
                while values.len() < N {
                    let Some(value) = seq.next_element()? else {
                        return Ok(values);
                    };
                    values.try_push(value).map_err(de::Error::custom)?;
                }
                seq.next_element_seed(RejectExtra)?;
                Ok(values)
            }
        }
        deserializer.deserialize_seq(BoundedVisitor::<T, N>(PhantomData))
    }
}

/// ASCII diagnostic text with an allocation and JSON expansion bound.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct BoundedText<const N: usize>(String);
impl<const N: usize> BoundedText<N> {
    fn check(text: &str) -> Result<(), SnapshotError> {
        for (index, byte) in text.bytes().enumerate() {
            if index == N {
                return Err(SnapshotError::Bound);
            }
            if !diagnostic_byte(byte) {
                return Err(SnapshotError::Invalid);
            }
        }
        Ok(())
    }
}
impl<const N: usize> TryFrom<&str> for BoundedText<N> {
    type Error = SnapshotError;
    fn try_from(text: &str) -> Result<Self, Self::Error> {
        Self::check(text)?;
        Ok(Self(text.to_owned()))
    }
}
impl<const N: usize> TryFrom<String> for BoundedText<N> {
    type Error = SnapshotError;
    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::check(&text)?;
        Ok(Self(text))
    }
}
impl<const N: usize> Deref for BoundedText<N> {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}
impl<'de, const N: usize> Deserialize<'de> for BoundedText<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TextVisitor<const N: usize>;
        impl<const N: usize> Visitor<'_> for TextVisitor<N> {
            type Value = BoundedText<N>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "at most {N} bytes of snapshot diagnostic text")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                value.try_into().map_err(E::custom)
            }
        }
        // serde_json borrows unescaped text; check it before allocating our String.
        // Its parser scratch space for escapes is bounded by BODY_MAX in the codec.
        deserializer.deserialize_str(TextVisitor::<N>)
    }
}

/// Uppercase UUID spelling from kern.bootsessionuuid (never a boot timestamp).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct BootId(String);
impl TryFrom<&str> for BootId {
    type Error = SnapshotError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() != 36
            || !value.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'A'..=b'F').contains(&b)
                }
            })
        {
            return Err(SnapshotError::Invalid);
        }
        Ok(Self(value.to_owned()))
    }
}
impl Deref for BootId {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}
impl<'de> Deserialize<'de> for BootId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BootVisitor;
        impl Visitor<'_> for BootVisitor {
            type Value = BootId;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a 36-byte uppercase UUID")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<BootId, E> {
                value.try_into().map_err(E::custom)
            }
        }
        deserializer.deserialize_str(BootVisitor)
    }
}

/// Process start identity, in seconds and fractional microseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartTime {
    /// Whole seconds.
    pub seconds: u64,
    /// Fractional part, strictly below one million.
    #[serde(deserialize_with = "deserialize_microseconds")]
    pub microseconds: u32,
}
fn deserialize_microseconds<'de, D: Deserializer<'de>>(d: D) -> Result<u32, D::Error> {
    let value = u32::deserialize(d)?;
    microseconds(value).map_err(de::Error::custom)
}
fn microseconds(value: u32) -> Result<u32, SnapshotError> {
    (value < 1_000_000)
        .then_some(value)
        .ok_or(SnapshotError::Invalid)
}
/// A previously committed helper process identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperIncarnation {
    /// Helper process ID.
    pub pid: u32,
    /// Process start time, disambiguating PID reuse.
    pub start: StartTime,
    /// Owned process group.
    pub pgid: u32,
    /// Originating boot, when known.
    pub boot: Option<BootId>,
}
/// Qualified kernel reference fingerprint, independent of the helper identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefFingerprint {
    /// Acquiring pfctl process ID.
    pub pid: u32,
    /// Reference timestamp.
    pub timestamp: u64,
}
// Serde mirror only: accounting identities themselves belong to core.
#[derive(Serialize, Deserialize)]
#[serde(remote = "ReferenceEntry")]
enum ReferenceEntryDef {
    Token(u64),
    Acquire(u64),
}
/// Evidence annotating exactly one core accounting entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefEvidence {
    /// Core accounting identity.
    #[serde(with = "ReferenceEntryDef")]
    pub key: ReferenceEntry,
    /// Boot captured at reservation.
    pub boot: Option<BootId>,
    /// A release has been exposed without a settled outcome (Token only).
    pub release_unknown: bool,
    /// Qualified fingerprint (Token only).
    pub fingerprint: Option<RefFingerprint>,
}
/// Request type and durable outcome, without independent conflicting booleans.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestKind {
    /// Pending Join.
    Join,
    /// Pending Leave.
    Leave,
    /// Completed Join.
    JoinDone,
    /// Completed Leave.
    LeaveDone,
    /// A Join superseded by Leave.
    JoinCancelled,
    /// Completed Join also marked cancelled by a later Leave.
    JoinDoneCancelled,
}
/// Bounded request replay entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestRecord {
    /// Caller identity, below the persistent counter limit.
    #[serde(deserialize_with = "deserialize_counter")]
    pub id: u64,
    /// Request and outcome.
    pub kind: RequestKind,
}
/// Durable internal failure category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InternalError {
    /// The lifecycle mirror cannot represent its core state.
    InvariantViolation,
    /// Reference annotations differ from the accounting entries.
    AnnotationMismatch,
    /// Another internal failure.
    Other,
}
/// Maximum distinct spawned builds retained per boot. Overflow loses certainty.
pub const IMAGE_HISTORY_BOUND: usize = 8;
/// Durable negative-evidence history. Default/missing history is unknown, never empty.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageHistory {
    /// Boot to which these observations belong; unknown boot grants no evidence.
    pub boot: Option<BootId>,
    /// Whether every spawned build on this boot is represented.
    pub known: bool,
    /// Bounded set of observed builds, retained even after certainty is lost.
    pub uuids: BoundedVec<[u8; 16], IMAGE_HISTORY_BOUND>,
}
impl ImageHistory {
    /// Empty-known history requires a proven fresh installation or a new boot.
    #[must_use]
    pub fn empty_for_boot(boot: BootId) -> Self {
        Self {
            boot: Some(boot),
            known: true,
            uuids: BoundedVec::default(),
        }
    }
    /// Only a proven different boot resets history. An unknown lookup revokes
    /// certainty and clears the epoch; the next readable boot cannot prove a reset.
    pub fn observe_boot(&mut self, boot: Option<BootId>) {
        if let Some(boot) = boot {
            if self.boot.as_ref().is_some_and(|old| *old != boot) {
                *self = Self::empty_for_boot(boot);
            } else {
                self.boot = Some(boot);
            }
        } else {
            self.known = false;
            self.boot = None;
        }
    }
    /// Add before spawning, and after unexpected observed images. Never evict a
    /// build to make room: overflow makes the entire boot's history unknown.
    pub fn record(&mut self, uuid: [u8; 16]) {
        if uuid == [0; 16] {
            self.known = false;
            return;
        }
        if !self.uuids.contains(&uuid) && self.uuids.try_push(uuid).is_err() {
            self.known = false;
        }
    }
    /// Certainty is usable only with a currently proven matching boot.
    #[must_use]
    pub fn known_on(&self, boot: Option<&BootId>) -> bool {
        self.known && boot.is_some() && self.boot.as_ref() == boot
    }
}
/// One complete bounded authoritative storage model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    /// Installation owner, when known.
    pub owner_uid: Option<u32>,
    /// Core lifecycle state.
    pub machine: DurableRecord,
    /// Canonically ordered evidence followed by vacant slots.
    pub references: [Option<RefEvidence>; 2],
    /// Installation endpoint, when readable.
    pub endpoint: Option<SocketAddrV4>,
    /// Previous helper identity for the start fence.
    pub helper: Option<HelperIncarnation>,
    /// Durable request replay window.
    pub requests: BoundedVec<RequestRecord, 8>,
    /// Spawned image evidence, retained until a different boot is proven.
    pub image_history: ImageHistory,
    /// Failure recorded on entry to Stuck.
    pub internal_error: Option<InternalError>,
}
impl Snapshot {
    /// Left state for an independently proven fresh installation.
    /// Only the installer may write this, after independently proving no existing
    /// storage or install record. It writes both copies with identical bytes.
    /// Durable initialisation must complete before the helper is enabled. A retry
    /// preserves existing state and never overwrites it with `initial`. A known
    /// boot establishes known-empty image history.
    /// The backstop is load-bearing: owned children exec /opt/scupper/wireguard-go,
    /// `p_comm` cannot be changed by the process, and wireguard-go never execs;
    /// the wireguard-go name guard therefore withholds an owned orphan even if
    /// the fresh-install proof was wrong.
    #[must_use]
    pub fn initial(owner_uid: Option<u32>, boot: Option<BootId>) -> Self {
        Self {
            owner_uid,
            machine: DurableRecord::default(),
            references: [None, None],
            endpoint: None,
            helper: None,
            requests: BoundedVec::default(),
            internal_error: None,
            image_history: boot.map_or_else(ImageHistory::default, ImageHistory::empty_for_boot),
        }
    }
    /// Conservative Recovery accounting: two potentially live unknown acquisitions.
    #[must_use]
    pub fn recovery(
        boot: Option<BootId>,
        endpoint: Option<SocketAddrV4>,
        owner_uid: Option<u32>,
        helper: Option<HelperIncarnation>,
    ) -> Self {
        // The two fixed entries are within the statically known bound.
        let uncertain_acquires = BoundedVec(vec![1, 2]);
        Self {
            machine: DurableRecord {
                join_intended: true,
                hold: true,
                uncertain_acquires,
                reference_sequence: 2,
                ..DurableRecord::default()
            },
            references: [(1, boot.clone()), (2, boot.clone())].map(|(seq, boot)| {
                Some(RefEvidence {
                    key: ReferenceEntry::Acquire(seq),
                    boot,
                    release_unknown: false,
                    fingerprint: None,
                })
            }),
            endpoint,
            owner_uid,
            helper,
            requests: BoundedVec::default(),
            internal_error: None,
            image_history: ImageHistory {
                boot,
                ..ImageHistory::default()
            },
        }
    }
    /// Validate core facts and the exact, canonical annotation multiset.
    ///
    /// # Errors
    /// Rejects invalid core state, exhausted counters, and mismatched evidence.
    pub fn validate(&self) -> Result<Durable, SnapshotError> {
        let durable = self.machine.to_core().map_err(|_| SnapshotError::Machine)?;
        if self.image_history.known && self.image_history.boot.is_none()
            || self
                .image_history
                .uuids
                .iter()
                .enumerate()
                .any(|(i, uuid)| *uuid == [0; 16] || self.image_history.uuids[..i].contains(uuid))
        {
            return Err(SnapshotError::Invalid);
        }
        if self.requests.iter().any(|r| counter(r.id).is_err()) {
            return Err(SnapshotError::Counter);
        }
        if self
            .helper
            .as_ref()
            .is_some_and(|h| microseconds(h.start.microseconds).is_err())
        {
            return Err(SnapshotError::Invalid);
        }
        let keys: Vec<_> = durable
            .pf_reference
            .into_iter()
            .map(ReferenceEntry::Token)
            .chain(
                durable
                    .older_references
                    .iter()
                    .copied()
                    .map(ReferenceEntry::Token),
            )
            .chain(
                durable
                    .uncertain_acquires
                    .iter()
                    .copied()
                    .map(ReferenceEntry::Acquire),
            )
            .chain(match durable.reference_intent {
                Some(ReferenceIntent::Acquire(seq)) => Some(ReferenceEntry::Acquire(seq)),
                _ => None,
            })
            .collect();
        if keys.len() > 2
            || keys
                .iter()
                .enumerate()
                .any(|(i, key)| keys[..i].contains(key))
        {
            return Err(SnapshotError::AnnotationMismatch);
        }
        for (i, evidence) in self.references.iter().enumerate() {
            if evidence.as_ref().map(|e| &e.key) != keys.get(i) {
                return Err(SnapshotError::AnnotationMismatch);
            }
            if let Some(e) = evidence {
                match e.key {
                    ReferenceEntry::Token(0) => return Err(SnapshotError::Invalid),
                    ReferenceEntry::Acquire(seq)
                        if seq == 0
                            || seq > durable.reference_sequence
                            || e.release_unknown
                            || e.fingerprint.is_some() =>
                    {
                        return Err(SnapshotError::Invalid);
                    }
                    _ => {}
                }
            }
        }
        Ok(durable)
    }
}
fn counter(value: u64) -> Result<u64, SnapshotError> {
    (value < COUNTER_MAX)
        .then_some(value)
        .ok_or(SnapshotError::Counter)
}
fn deserialize_counter<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    counter(u64::deserialize(d)?).map_err(de::Error::custom)
}
fn deserialize_optional_counter<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    Option::<u64>::deserialize(d)?
        .map(counter)
        .transpose()
        .map_err(de::Error::custom)
}

/// Encode a validated state with a checksum over header and body only.
///
/// # Errors
/// Refuses invalid state, exhausted sequence numbers, or oversized JSON.
pub fn encode(seq: u64, snapshot: &Snapshot) -> Result<Box<[u8; COPY_BYTES]>, SnapshotError> {
    counter(seq)?;
    snapshot.validate()?;
    let body = serde_json::to_vec(snapshot).map_err(|_| SnapshotError::Invalid)?;
    if body.len() > BODY_MAX {
        return Err(SnapshotError::BodyTooLarge);
    }
    let mut bytes = Box::new([0; COPY_BYTES]);
    bytes[..8].copy_from_slice(&MAGIC);
    bytes[8..12].copy_from_slice(&FORMAT.to_le_bytes());
    bytes[12..20].copy_from_slice(&seq.to_le_bytes());
    let len = u32::try_from(body.len()).map_err(|_| SnapshotError::BodyTooLarge)?;
    bytes[20..24].copy_from_slice(&len.to_le_bytes());
    let end = 24 + body.len();
    bytes[24..end].copy_from_slice(&body);
    let digest = Sha256::digest(&bytes[..end]);
    bytes[end..end + 32].copy_from_slice(&digest);
    Ok(bytes)
}
/// Result of physical reading, supplied by the I/O layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CopyRead {
    /// The path does not exist.
    Missing,
    /// Reading remained unsuccessful.
    Unreadable,
    /// Full read result (length is still untrusted).
    Bytes(Vec<u8>),
}
/// Pure classification of one physical copy.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // Public storage model keeps the validated snapshot inline.
pub enum CopyClass {
    /// Checksum and semantics both valid; bytes include padding.
    V {
        /// Trusted sequence.
        seq: u64,
        /// Validated snapshot.
        snapshot: Snapshot,
        /// Full original copy, for exact equality and pair repair.
        bytes: Vec<u8>,
    },
    /// Checksum valid but semantics invalid. Retain only separately valid helper evidence.
    I {
        /// Checksum-authenticated sequence, possibly exhausted.
        seq: u64,
        /// Helper decoded independently of the otherwise invalid JSON object.
        helper: Option<HelperIncarnation>,
    },
    /// Recognizable magic but unsupported format; its sequence is never read.
    X,
    /// Torn length, magic, body length, or digest.
    T,
    /// Missing.
    M,
    /// Unreadable.
    U,
}
// Separate strict previous-format mirror: defaults on the current Snapshot
// would silently turn a missing v2 history into a valid v2 record.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacySnapshot {
    owner_uid: Option<u32>,
    machine: DurableRecord,
    references: [Option<RefEvidence>; 2],
    endpoint: Option<SocketAddrV4>,
    helper: Option<HelperIncarnation>,
    requests: BoundedVec<RequestRecord, 8>,
    internal_error: Option<InternalError>,
}
fn migrate_legacy(bytes: &[u8]) -> Option<Snapshot> {
    let old: LegacySnapshot = serde_json::from_slice(bytes).ok()?;
    if serde_json::to_vec(&old).ok()? != bytes {
        return None;
    }
    Some(Snapshot {
        owner_uid: old.owner_uid,
        machine: old.machine,
        references: old.references,
        endpoint: old.endpoint,
        helper: old.helper,
        requests: old.requests,
        internal_error: old.internal_error,
        image_history: ImageHistory::default(),
    })
}
/// Classify without trusting torn or unknown-format headers.
/// Padding is outside the checksum: nonzero padding is a semantic error (I).
#[must_use]
pub fn classify_copy(read: CopyRead) -> CopyClass {
    let bytes = match read {
        CopyRead::Missing => return CopyClass::M,
        CopyRead::Unreadable => return CopyClass::U,
        CopyRead::Bytes(bytes) => bytes,
    };
    let old = bytes.len() == COPY_BYTES
        && bytes[..8] == *b"SCPMACS\x01"
        && bytes[8..12] == 1_u32.to_le_bytes();
    if bytes.len() != COPY_BYTES || (bytes[..8] != MAGIC && !old) {
        return CopyClass::T;
    }
    if !old && bytes[8..12] != FORMAT.to_le_bytes() {
        return CopyClass::X;
    }
    let seq = u64::from_le_bytes(bytes[12..20].try_into().unwrap_or_default());
    let len = u32::from_le_bytes(bytes[20..24].try_into().unwrap_or_default()) as usize;
    if len > BODY_MAX {
        return CopyClass::T;
    }
    let end = 24 + len;
    if Sha256::digest(&bytes[..end])[..] != bytes[end..end + 32] {
        return CopyClass::T;
    }
    if old
        && seq < COUNTER_MAX
        && bytes[end + 32..].iter().all(|b| *b == 0)
        && let Some(snapshot) = migrate_legacy(&bytes[24..end])
        && snapshot.validate().is_ok()
    {
        return CopyClass::V {
            seq,
            snapshot,
            bytes,
        };
    }
    if !old
        && seq < COUNTER_MAX
        && bytes[end + 32..].iter().all(|b| *b == 0)
        && let Ok(snapshot) = serde_json::from_slice::<Snapshot>(&bytes[24..end])
        && snapshot.validate().is_ok()
        && serde_json::to_vec(&snapshot).is_ok_and(|body| body == bytes[24..end])
    {
        return CopyClass::V {
            seq,
            snapshot,
            bytes,
        };
    }
    let helper = serde_json::from_slice::<serde_json::Value>(&bytes[24..end])
        .ok()
        .and_then(|v| v.as_object()?.get("helper").cloned())
        .and_then(|v| serde_json::from_value(v).ok());
    CopyClass::I { seq, helper }
}
/// Physical slot, ordered by the writer's A-then-B protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Copy {
    /// First written copy.
    A,
    /// Second written copy.
    B,
}
/// Pure start decision; repair and Recovery writes are performed by the I/O layer.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // Same inline snapshot representation as CopyClass.
pub enum StartDecision {
    /// Use an authoritative copy, repairing the other if necessary before effects.
    Trust {
        /// Authoritative slot.
        source: Copy,
        /// Committed sequence.
        seq: u64,
        /// Validated state.
        snapshot: Snapshot,
        /// Slot to repair before effects; history annotations may be downgraded
        /// to unknown independently of the trusted lifecycle state.
        repair: Option<Copy>,
    },
    /// Persist a conservative Recovery snapshot before exposing effects.
    Recovery {
        /// Next sequence, resetting to one on exhaustion.
        seq: u64,
        /// Best checksum-authenticated helper identity for the start fence.
        helper: Option<HelperIncarnation>,
    },
}
/// Apply every row of the asymmetric A-first lifecycle start table. Image
/// history requires agreement between both readable validated copies; otherwise
/// its certainty is revoked independently of lifecycle trust.
#[must_use]
pub fn decide(a: CopyClass, b: CopyClass) -> StartDecision {
    // A single surviving copy still drives the lifecycle start table, but
    // absence from its history cannot certify a foreign build if the other
    // copy is missing, unreadable, corrupt or disagrees.
    // Spawn requires a full A+B commit containing its UUID. Histories only
    // grow within a boot, and a boot reset makes them unequal, so equal
    // histories at any sequences contain every spawned UUID of their boot.
    let consistent_history = matches!((&a, &b),
        (CopyClass::V {snapshot: a, ..}, CopyClass::V {snapshot: b, ..})
            if a.image_history == b.image_history);
    match (&a, &b) {
        (
            CopyClass::V {
                seq: ga, bytes: ba, ..
            },
            CopyClass::V {
                seq: gb, bytes: bb, ..
            },
        ) if ga == gb && ba == bb => return trust_history(a, Copy::A, None, consistent_history),
        (
            CopyClass::V { seq: ga, .. },
            CopyClass::V { seq: gb, .. } | CopyClass::I { seq: gb, .. },
        ) if gb < ga => return trust_history(a, Copy::A, Some(Copy::B), consistent_history),
        (CopyClass::V { .. }, CopyClass::T | CopyClass::M | CopyClass::U | CopyClass::X) => {
            return trust_history(a, Copy::A, Some(Copy::B), consistent_history);
        }
        (CopyClass::T | CopyClass::M | CopyClass::U, CopyClass::V { .. }) => {
            return trust_history(b, Copy::B, Some(Copy::A), consistent_history);
        }
        _ => {}
    }
    let seq = [&a, &b]
        .into_iter()
        .filter_map(|c| match c {
            CopyClass::V { seq, .. } | CopyClass::I { seq, .. } => Some(*seq),
            _ => None,
        })
        .max()
        .filter(|n| *n < COUNTER_MAX - 1)
        .map_or(1, |n| n + 1);
    let helper = [&b, &a]
        .into_iter()
        .filter_map(|c| match c {
            CopyClass::V { seq, snapshot, .. } => snapshot.helper.as_ref().map(|h| (*seq, h)),
            _ => None,
        })
        .max_by_key(|(seq, _)| *seq)
        .map(|(_, h)| h.clone())
        .or_else(|| {
            [&b, &a]
                .into_iter()
                .filter_map(|c| match c {
                    CopyClass::I { seq, helper } => helper.as_ref().map(|h| (*seq, h)),
                    _ => None,
                })
                .max_by_key(|(seq, _)| *seq)
                .map(|(_, h)| h.clone())
        });
    StartDecision::Recovery { seq, helper }
}
fn trust_history(
    class: CopyClass,
    source: Copy,
    repair: Option<Copy>,
    consistent: bool,
) -> StartDecision {
    let mut decision = trust(class, source, repair);
    if !consistent && let StartDecision::Trust { snapshot, .. } = &mut decision {
        snapshot.image_history.known = false;
        snapshot.image_history.boot = None; // Start observes the current uncertainty epoch.
    }
    decision
}
fn trust(class: CopyClass, source: Copy, repair: Option<Copy>) -> StartDecision {
    if let CopyClass::V { seq, snapshot, .. } = class {
        StartDecision::Trust {
            source,
            seq,
            snapshot,
            repair,
        }
    } else {
        unreachable!("trust requires a validated copy")
    }
}

/// Stable lifecycle step mirror; unknown tags are corruption.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepRecord {
    /// Version-one step tag.
    pub tag: u8,
    /// Deadline or policy form (zero pre-tunnel, one joined).
    pub argument: u64,
}
macro_rules! step_records {
    ($($tag:literal => $step:ident,)*) => {
        impl From<Step> for StepRecord {
            fn from(step: Step) -> Self {
                let (tag, argument) = match step {
                    $(Step::$step => ($tag, 0),)*
                    Step::Backoff { until } => (0, until),
                    Step::ReplaceAnchor(form) => (23, u64::from(form == Form::Joined)),
                    Step::VerifyReplacement(form) => (24, u64::from(form == Form::Joined)),
                };
                Self { tag, argument }
            }
        }
        impl StepRecord {
            /// Validate the stored tag and payload.
            ///
            /// # Errors
            /// Rejects unknown steps, nonzero unit payloads and unknown forms.
            pub fn to_core(self) -> Result<Step, SysError> {
                Ok(match (self.tag, self.argument) {
                    $(($tag, 0) => Step::$step,)*
                    (0, until) => Step::Backoff { until },
                    (23, 0) => Step::ReplaceAnchor(Form::PreTunnel),
                    (23, 1) => Step::ReplaceAnchor(Form::Joined),
                    (24, 0) => Step::VerifyReplacement(Form::PreTunnel),
                    (24, 1) => Step::VerifyReplacement(Form::Joined),
                    _ => return Err(SysError::Failed("journal step")),
                })
            }
        }
    };
}
step_records! {
    1 => PersistIntent,
    2 => PersistLeaving,
    3 => AcquireReference,
    4 => ReconcileReference,
    5 => LoadPreTunnel,
    6 => VerifyPreTunnelLoad,
    7 => FlushStates,
    8 => VerifyPreTunnel,
    9 => CheckTools,
    10 => ReserveGeneration,
    11 => StartChild,
    12 => ConfigureUapi,
    13 => ConfigureAddresses,
    14 => ConfigureMtu,
    15 => ConfigureEndpointRoute,
    16 => ConfigureSplitRoutes,
    17 => ConfigureDns,
    18 => VerifyIdentity,
    19 => LoadJoined,
    20 => VerifyJoinedLoad,
    21 => VerifyJoined,
    22 => RemoveVanishedInterfaceStates,
    25 => StopChild,
    26 => CleanupRoutes,
    27 => CleanupDns,
    28 => CleanupArtifacts,
    29 => RemoveAnchor,
    30 => ReleaseReference,
    31 => ClearIntent,
}

/// Version-one failure mirror; reason text is never treated as executable input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReasonRecord {
    /// Stable failure category.
    pub kind: u8,
    /// Optional validated interface name or static diagnostic.
    pub text: BoundedText<256>,
    /// Repair action tag or Unknown start time.
    pub argument: u64,
}
impl TryFrom<&Reason> for ReasonRecord {
    type Error = SnapshotError;

    fn try_from(reason: &Reason) -> Result<Self, Self::Error> {
        let mut record = Self {
            kind: 0,
            text: BoundedText::default(),
            argument: 0,
        };
        match reason {
            Reason::TranslationPresent => record.kind = 0,
            Reason::HookMissing => record.kind = 1,
            Reason::QuickPass => record.kind = 2,
            Reason::Skip(i) => {
                record.kind = 3;
                record.text = i.to_string().try_into()?;
            }
            Reason::Unsupported(s) => {
                record.kind = 4;
                record.text = (*s).try_into()?;
            }
            Reason::Observation(s) => {
                record.kind = 5;
                record.text = (*s).try_into()?;
            }
            Reason::Repair(a) => {
                record.kind = 6;
                record.argument = match a {
                    Action::Rejoin => 0,
                    Action::EnableAndRejoin => 1,
                    Action::RecreateChild => 2,
                    Action::Rerender {
                        form: Form::PreTunnel,
                    } => 3,
                    Action::Rerender { form: Form::Joined } => 4,
                };
            }
            Reason::Unknown { since } => {
                record.kind = 7;
                record.argument = *since;
            }
            Reason::RouteRecursion => record.kind = 8,
            Reason::MissingGateway => record.kind = 9,
            Reason::AmbiguousPath => record.kind = 10,
            Reason::ToolIntegrity => record.kind = 11,
        }
        Ok(record)
    }
}
impl ReasonRecord {
    fn to_core(&self) -> Result<Reason, SysError> {
        Ok(match self.kind {
            0 => Reason::TranslationPresent,
            1 => Reason::HookMissing,
            2 => Reason::QuickPass,
            3 => Reason::Skip(
                self.text
                    .parse()
                    .map_err(|_| SysError::Failed("journal interface"))?,
            ),
            4 => Reason::Unsupported(
                static_reason(&self.text).unwrap_or("persisted unsupported configuration"),
            ),
            5 => {
                Reason::Observation(static_reason(&self.text).unwrap_or("persisted effect failure"))
            }
            6 => Reason::Repair(match self.argument {
                0 => Action::Rejoin,
                1 => Action::EnableAndRejoin,
                2 => Action::RecreateChild,
                3 => Action::Rerender {
                    form: Form::PreTunnel,
                },
                4 => Action::Rerender { form: Form::Joined },
                _ => return Err(SysError::Failed("journal action")),
            }),
            7 => Reason::Unknown {
                since: self.argument,
            },
            8 => Reason::RouteRecursion,
            9 => Reason::MissingGateway,
            10 => Reason::AmbiguousPath,
            11 => Reason::ToolIntegrity,
            _ => return Err(SysError::Failed("journal reason")),
        })
    }
}
/// Complete serde mirror of the core durable record.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Mirrors independent core lifecycle facts.
pub struct DurableRecord {
    /// Persisted core `verification_context`.
    pub verification_context: [u64; 4],
    /// Persisted core `join_intended`.
    pub join_intended: bool,
    /// Persisted core hold for conservative recovery.
    pub hold: bool,
    /// Persisted core `retry_attempts`.
    pub retry_attempts: u8,
    /// Persisted core `leave_requested`.
    pub leave_requested: bool,
    /// Persisted core `leaving`.
    pub leaving: bool,
    /// Persisted core `pf_reference`.
    pub pf_reference: Option<u64>,
    /// Persisted core `older_references`.
    pub older_references: BoundedVec<u64, 1>,
    /// Persisted core `reference_intent`.
    pub reference_intent: Option<(bool, u64)>,
    /// Persisted core `uncertain_acquires`.
    pub uncertain_acquires: BoundedVec<u64, 2>,
    /// Persisted core `reference_needs_reconcile`.
    pub reference_needs_reconcile: bool,
    /// Persisted core `reference_error`.
    pub reference_error: Option<ReasonRecord>,
    /// Persisted core `reference_sequence`.
    #[serde(deserialize_with = "deserialize_counter")]
    pub reference_sequence: u64,
    /// Persisted core `enforcement_error`.
    pub enforcement_error: Option<ReasonRecord>,
    /// Persisted core `previous_generation`.
    #[serde(deserialize_with = "deserialize_optional_counter")]
    pub previous_generation: Option<u64>,
    /// Persisted core `pending_cleanup`.
    pub pending_cleanup: BoundedVec<StepRecord, 5>,
    /// Persisted core `cleanup_errors`.
    pub cleanup_errors: BoundedVec<(StepRecord, ReasonRecord), 8>,
    /// Persisted core `last_error`.
    pub last_error: Option<ReasonRecord>,
}
impl TryFrom<&Durable> for DurableRecord {
    type Error = SnapshotError;

    fn try_from(d: &Durable) -> Result<Self, Self::Error> {
        Ok(Self {
            verification_context: context_record(d.verification_context),
            join_intended: d.join_intended,
            hold: d.hold,
            retry_attempts: d.retry_attempts,
            leave_requested: d.leave_requested,
            leaving: d.leaving,
            pf_reference: d.pf_reference,
            older_references: d.older_references.clone().try_into()?,
            reference_intent: d.reference_intent.map(|i| match i {
                ReferenceIntent::Acquire(n) => (true, n),
                ReferenceIntent::Release => (false, 0),
            }),
            uncertain_acquires: d.uncertain_acquires.clone().try_into()?,
            reference_needs_reconcile: d.reference_needs_reconcile,
            reference_error: d
                .reference_error
                .as_ref()
                .map(ReasonRecord::try_from)
                .transpose()?,
            reference_sequence: d.reference_sequence,
            enforcement_error: d
                .enforcement_error
                .as_ref()
                .map(ReasonRecord::try_from)
                .transpose()?,
            previous_generation: d.previous_generation.map(TunnelGeneration::value),
            pending_cleanup: d
                .pending_cleanup
                .iter()
                .copied()
                .map(StepRecord::from)
                .collect::<Vec<_>>()
                .try_into()?,
            cleanup_errors: d
                .cleanup_errors
                .iter()
                .map(|(s, r)| Ok(((*s).into(), ReasonRecord::try_from(r)?)))
                .collect::<Result<Vec<_>, SnapshotError>>()?
                .try_into()?,
            last_error: d
                .last_error
                .as_ref()
                .map(ReasonRecord::try_from)
                .transpose()?,
        })
    }
}
impl DurableRecord {
    /// Validate and recover the pure lifecycle facts; no successful proof is restored.
    ///
    /// # Errors
    /// Rejects invalid generation, step, action and ownership combinations.
    pub fn to_core(&self) -> Result<Durable, SysError> {
        let d = self;
        let result = Durable {
            verification_context: Context {
                policy_generation: d.verification_context[0],
                lifecycle_revision: d.verification_context[1],
                state_epoch: d.verification_context[2],
                acquisition_revision: d.verification_context[3],
            },
            join_intended: d.join_intended,
            hold: d.hold,
            retry_attempts: d.retry_attempts,
            leave_requested: d.leave_requested,
            leaving: d.leaving,
            pf_reference: d.pf_reference,
            older_references: d.older_references.to_vec(),
            reference_intent: match d.reference_intent {
                Some((true, n)) if n > 0 => Some(ReferenceIntent::Acquire(n)),
                Some((false, 0)) => Some(ReferenceIntent::Release),
                None => None,
                _ => return Err(SysError::Failed("journal reference intent")),
            },
            uncertain_acquires: d.uncertain_acquires.to_vec(),
            reference_needs_reconcile: d.reference_needs_reconcile,
            reference_error: d
                .reference_error
                .as_ref()
                .map(ReasonRecord::to_core)
                .transpose()?,
            reference_sequence: d.reference_sequence,
            enforcement_error: d
                .enforcement_error
                .as_ref()
                .map(ReasonRecord::to_core)
                .transpose()?,
            previous_generation: d
                .previous_generation
                .map(TunnelGeneration::new)
                .transpose()
                .map_err(|_| SysError::Failed("journal generation"))?,
            pending_cleanup: d
                .pending_cleanup
                .iter()
                .copied()
                .map(StepRecord::to_core)
                .collect::<Result<_, _>>()?,
            cleanup_errors: d
                .cleanup_errors
                .iter()
                .map(|(s, r)| Ok((s.to_core()?, r.to_core()?)))
                .collect::<Result<_, SysError>>()?,
            last_error: d
                .last_error
                .as_ref()
                .map(ReasonRecord::to_core)
                .transpose()?,
        };
        validate_durable(result)
    }
}
fn validate_durable(result: Durable) -> Result<Durable, SysError> {
    const CLEANUP: [Step; 5] = [
        Step::StopChild,
        Step::CleanupRoutes,
        Step::CleanupDns,
        Step::CleanupArtifacts,
        Step::RemoveAnchor,
    ];
    if counter(result.reference_sequence).is_err()
        || result
            .previous_generation
            .map(TunnelGeneration::value)
            .is_some_and(|n| counter(n).is_err())
    {
        return Err(SysError::Failed("snapshot counter"));
    }
    if result.leaving && (result.join_intended || !result.leave_requested)
        || context_record(result.verification_context)
            .iter()
            .any(|n| *n > u64::MAX / 2)
    {
        return Err(SysError::Failed("journal inconsistent"));
    }
    if result.hold && !result.join_intended && !result.leaving {
        return Err(SysError::Failed("journal hold without join intent"));
    }
    let mut previous = None;
    for step in &result.pending_cleanup {
        let index = CLEANUP
            .iter()
            .position(|s| s == step)
            .ok_or(SysError::Failed("journal cleanup plan"))?;
        if previous.is_some_and(|p| index <= p) {
            return Err(SysError::Failed("journal cleanup order"));
        }
        previous = Some(index);
    }
    if !result.leaving && !result.pending_cleanup.is_empty()
        || result.older_references.len()
            + usize::from(result.pf_reference.is_some())
            + result.uncertain_acquires.len()
            > 2
        || result
            .older_references
            .iter()
            .any(|t| Some(*t) == result.pf_reference)
        || result
            .uncertain_acquires
            .iter()
            .enumerate()
            .any(|(i, n)| result.uncertain_acquires[..i].contains(n))
    {
        return Err(SysError::Failed("journal inconsistent"));
    }
    if result.pf_reference == Some(0)
        || result.older_references.contains(&0)
        || result.uncertain_acquires.contains(&0)
        || result.retry_attempts > 7
    {
        return Err(SysError::Failed("journal durable identity"));
    }
    Ok(result)
}

// Core reasons borrow static strings. Build their backing storage from the actual
// producers at compile time, rather than maintaining a second diagnostic list.
// Only bounded ASCII literal contents survive in the binary; source files do not.
const REASON_SOURCES: &[&str] = &[
    include_str!("../../scupper-core/src/mac/lifecycle.rs"),
    include_str!("../../scupper-core/src/mac/verify.rs"),
    include_str!("../../scupper-core/src/mac/parse.rs"),
    include_str!("../../scupper-core/src/mac/types.rs"),
    include_str!("engine.rs"),
    include_str!("engine/emergency.rs"),
    include_str!("engine/execute.rs"),
    include_str!("engine/lockless.rs"),
    include_str!("engine/protocol.rs"),
    include_str!("engine/reference.rs"),
];
const fn diagnostic_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b' ' | b'.' | b',' | b':' | b';' | b'(' | b')' | b'/' | b'_' | b'-'
        )
}
// This is a pool of bounded text, not a Rust parser. Tests below audit each
// diagnostic constructor (including forwarded Error/SysError literals) against it.
const fn reason_pool<const N: usize>() -> ([u8; N], usize) {
    let mut bytes = [0; N];
    let mut used = 0;
    let mut source = 0;
    while source < REASON_SOURCES.len() {
        let input = REASON_SOURCES[source].as_bytes();
        let mut i = 0;
        while i < input.len() {
            if input[i] != b'"' {
                i += 1;
                continue;
            }
            i += 1;
            let start = i;
            let mut valid = true;
            while i < input.len() && input[i] != b'"' {
                valid = valid && diagnostic_byte(input[i]);
                i += 1;
            }
            if valid && i - start <= 256 {
                let mut j = start;
                while j < i {
                    if N > 0 {
                        bytes[used] = input[j];
                    }
                    used += 1;
                    j += 1;
                }
                if N > 0 {
                    bytes[used] = 0;
                }
                used += 1;
            }
            i += 1;
        }
        source += 1;
    }
    (bytes, used)
}
const REASON_BYTES: [u8; reason_pool::<0>().1] = reason_pool().0;
fn static_reason(text: &str) -> Option<&'static str> {
    std::str::from_utf8(&REASON_BYTES)
        .ok()?
        .split('\0')
        .find(|reason| *reason == text)
}

/// Ordered context mirror, including acquisition identity.
#[must_use]
pub fn context_record(c: Context) -> [u64; 4] {
    [
        c.policy_generation,
        c.lifecycle_revision,
        c.state_epoch,
        c.acquisition_revision,
    ]
}

#[cfg(test)]
mod tests;
