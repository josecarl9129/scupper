//! Packed XNU starter records and the whole-record completeness protocol.
use crate::platform::{RefLine, ReferenceQualification, SysError};
use std::collections::BTreeSet;

/// Measured packed record stride, independent of the host C ABI.
pub const STRIDE: usize = 84;
#[cfg(target_os = "macos")]
const _: () = assert!(STRIDE == scupper_darwin::PF_TOKEN_SIZE);
/// Darwin `_IOWR('D', 5, struct pfioc_tokens)`.
pub const GETSTARTERS: u32 = super::iowr(b'D', 5, 16);
/// Evidence state for one independently qualified kernel assumption.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Assumption {
    /// No qualified record is available.
    #[default]
    Unknown,
    /// The assumption was established for this build.
    Established,
    /// Measurements refuted the assumption.
    Refuted,
}
/// Production defaults grant no assumptions. Native overrides are feature gated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Assumptions {
    /// Packed token ABI and complete enumeration protocol.
    pub pf_token_layout: Assumption,
    /// EEXIST establishes the single anonymous enable reference.
    pub eexist_establishes_anonymous: Assumption,
    /// Global disable voids all tokens.
    pub disable_voids_references: Assumption,
    /// PID/calendar timestamp can qualify numeric release ownership.
    pub fingerprints: Assumption,
}
impl Assumptions {
    /// Optional qualifications require both the layout and individual assumption.
    #[must_use]
    pub fn qualification(self) -> ReferenceQualification {
        ReferenceQualification {
            disable_voids_references: self.pf_token_layout == Assumption::Established
                && self.disable_voids_references == Assumption::Established,
            fingerprints: self.pf_token_layout == Assumption::Established
                && self.fingerprints == Assumption::Established,
        }
    }
}
/// Whole-record copy interpretation. Incomplete data never proves absence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Classification {
    /// At least one whole spare slot proves the copy did not fill the buffer.
    Complete,
    /// No whole spare slot; retry even if zero bytes were returned.
    Retry,
    /// Impossible returned length or unsupported stride.
    Layout,
}
/// Classify arbitrary capacities, including the sub-record `C < S, r = 0` case.
#[must_use]
pub fn classify(capacity: usize, returned: usize, stride: usize) -> Classification {
    if stride == 0 || returned > capacity || !returned.is_multiple_of(stride) {
        Classification::Layout
    } else if capacity >= stride && returned <= capacity - stride {
        Classification::Complete
    } else {
        Classification::Retry
    }
}
/// Decode packed little-endian records without unaligned references.
/// Process-name bytes are opaque: foreign starters belong in the inventory and
/// names never confer ownership.
///
/// # Errors
/// Reject partial records, duplicate/zero tokens or invalid PIDs.
pub fn decode(bytes: &[u8]) -> Result<Vec<RefLine>, SysError> {
    let layout = SysError::Failed("pf token layout");
    if !bytes.len().is_multiple_of(STRIDE) {
        return Err(layout);
    }
    let mut seen = BTreeSet::new();
    bytes
        .as_chunks::<STRIDE>()
        .0
        .iter()
        .map(|b| {
            let token = u64::from_le_bytes(b[0..8].try_into().map_err(|_| layout.clone())?);
            let timestamp = u64::from_le_bytes(b[8..16].try_into().map_err(|_| layout.clone())?);
            let pid = u32::from_le_bytes(b[16..20].try_into().map_err(|_| layout.clone())?);
            if token == 0 || !seen.insert(token) || pid == 0 || pid > i32::MAX.cast_unsigned() {
                return Err(layout.clone());
            }
            Ok(RefLine {
                token,
                pid,
                timestamp,
            })
        })
        .collect()
}
/// Failed ioctls carry no returned size: it must never be inspected on error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// Kernel reports no starter references.
    Noent,
    /// Any other syscall failure.
    Other,
}
/// Complete enumeration with at most eight copy attempts. Buffers are zeroed and
/// exactly sized; allocation capacity is never a foreign-call bound.
///
/// # Errors
/// Any malformed reply, exhausted deadline, allocation bound or persistent churn.
pub fn enumerate(
    read: impl FnMut(&mut [u8]) -> Result<usize, ReadError>,
    expired: impl FnMut() -> bool,
) -> Result<Vec<RefLine>, SysError> {
    enumerate_buffer(read, expired, |capacity| vec![0_u8; capacity], 16, |_| {})
}
/// Qualification alone may reduce the spare slots and observe copy decisions.
///
/// # Errors
/// The same incomplete/layout/deadline failures as ordinary enumeration.
#[cfg(feature = "qualification")]
pub fn enumerate_with_spare(
    read: impl FnMut(&mut [u8]) -> Result<usize, ReadError>,
    expired: impl FnMut() -> bool,
    spare: usize,
    observe: impl FnMut(Classification),
) -> Result<Vec<RefLine>, SysError> {
    enumerate_buffer(
        read,
        expired,
        |capacity| vec![0_u8; capacity],
        spare,
        observe,
    )
}
fn enumerate_buffer(
    mut read: impl FnMut(&mut [u8]) -> Result<usize, ReadError>,
    mut expired: impl FnMut() -> bool,
    mut allocate: impl FnMut(usize) -> Vec<u8>,
    spare: usize,
    mut observe: impl FnMut(Classification),
) -> Result<Vec<RefLine>, SysError> {
    let mut slots = 0_usize;
    for _ in 0..8 {
        if expired() {
            return Err(SysError::TimedOut);
        }
        let need = match read(&mut []) {
            Err(ReadError::Noent) => return Ok(Vec::new()),
            Err(ReadError::Other) => return Err(SysError::Failed("pf token ioctl")),
            Ok(need) if need.is_multiple_of(STRIDE) => need,
            Ok(_) => return Err(SysError::Failed("pf token layout")),
        };
        slots = slots.max(
            (need / STRIDE)
                .checked_add(spare)
                .ok_or(SysError::Failed("pf token bounds"))?,
        );
        let capacity = slots
            .checked_mul(STRIDE)
            .filter(|c| *c <= 16 * 1024 * 1024)
            .ok_or(SysError::Failed("pf token bounds"))?;
        let mut bytes = allocate(capacity);
        if expired() {
            return Err(SysError::TimedOut);
        }
        let Ok(returned) = read(&mut bytes) else {
            continue;
        };
        let classification = classify(capacity, returned, STRIDE);
        observe(classification);
        match classification {
            Classification::Complete => return decode(&bytes[..returned]),
            Classification::Layout => return Err(SysError::Failed("pf token layout")),
            Classification::Retry => {
                slots = slots
                    .checked_mul(2)
                    .ok_or(SysError::Failed("pf token bounds"))?;
            }
        }
    }
    Err(SysError::Failed("churn"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    fn record(token: u64) -> Vec<u8> {
        let mut b = vec![0; STRIDE];
        b[..8].copy_from_slice(&token.to_le_bytes());
        b[8..16].copy_from_slice(&123_u64.to_le_bytes());
        b[16..20].copy_from_slice(&42_u32.to_le_bytes());
        b[20..25].copy_from_slice(b"pfctl");
        b
    }
    #[test]
    fn literal_two_record_fixture_pins_byte_84_boundary() {
        // Literal 168 bytes, independent of STRIDE and record(). Token 9 begins at 84.
        let bytes: [u8; 168] = [
            7, 0, 0, 0, 0, 0, 0, 0, 123, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0,
            0, 0, 0, 0, 0, 0, 124, 0, 0, 0, 0, 0, 0, 0, 43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(
            decode(&bytes),
            Ok(vec![
                RefLine {
                    token: 7,
                    pid: 42,
                    timestamp: 123
                },
                RefLine {
                    token: 9,
                    pid: 43,
                    timestamp: 124
                },
            ])
        );
    }
    #[test]
    fn mixed_assumptions_require_layout_and_each_individual_gate() {
        for layout in [
            Assumption::Unknown,
            Assumption::Refuted,
            Assumption::Established,
        ] {
            for disable in [
                Assumption::Unknown,
                Assumption::Refuted,
                Assumption::Established,
            ] {
                for fingerprints in [
                    Assumption::Unknown,
                    Assumption::Refuted,
                    Assumption::Established,
                ] {
                    assert_eq!(
                        Assumptions {
                            pf_token_layout: layout,
                            disable_voids_references: disable,
                            fingerprints,
                            ..Assumptions::default()
                        }
                        .qualification(),
                        ReferenceQualification {
                            disable_voids_references: layout == Assumption::Established
                                && disable == Assumption::Established,
                            fingerprints: layout == Assumption::Established
                                && fingerprints == Assumption::Established,
                        }
                    );
                }
            }
        }
    }
    #[cfg(feature = "qualification")]
    #[test]
    fn small_spare_retries_full_copies_then_completes_without_losing_oldest() {
        for spare in [0, 1] {
            let mut copies = 0;
            let mut decisions = vec![];
            let result = enumerate_with_spare(
                |b| {
                    if b.is_empty() {
                        return Ok(84);
                    }
                    copies += 1;
                    if copies == 1 {
                        return Ok(b.len());
                    }
                    b[..84].copy_from_slice(&record(7));
                    Ok(84)
                },
                || false,
                spare,
                |d| decisions.push(d),
            );
            assert_eq!(result, decode(&record(7)));
            assert_eq!(
                decisions,
                vec![Classification::Retry, Classification::Complete]
            );
        }
    }
    #[test]
    fn boundary_cases_and_packed_stride() {
        assert_eq!(STRIDE, 84);
        assert_eq!(classify(83, 0, 84), Classification::Retry);
        assert_eq!(classify(84, 84, 84), Classification::Retry);
        assert_eq!(classify(85, 84, 84), Classification::Retry);
        assert_eq!(classify(168, 84, 84), Classification::Complete);
        assert_eq!(
            decode(&record(7)),
            Ok(vec![RefLine {
                token: 7,
                pid: 42,
                timestamp: 123
            }])
        );
        assert!(decode(&[record(7), record(7)].concat()).is_err());
        assert!(decode(&[0; 88]).is_err());
    }
    #[test]
    fn foreign_process_names_are_opaque_and_do_not_hide_references() {
        let mut bytes = record(7);
        let expected = decode(&bytes).unwrap();
        for name in [b'F', 0xff, 0] {
            bytes[20..84].fill(name);
            assert_eq!(decode(&bytes), Ok(expected.clone()));
        }
    }
    #[test]
    fn retry_errors_ignore_size_and_buffers_have_exact_initialized_length() {
        let mut calls = 0;
        let result = enumerate(
            |bytes| {
                calls += 1;
                match calls {
                    1 | 3 => {
                        assert_eq!(bytes, [0_u8; 0]);
                        Ok(84)
                    }
                    2 => {
                        assert_eq!(bytes.len(), 17 * 84);
                        Err(ReadError::Noent)
                    }
                    4 => {
                        assert_eq!(bytes.len(), 17 * 84);
                        assert!(bytes.iter().all(|b| *b == 0));
                        bytes[..84].copy_from_slice(&record(9));
                        Ok(84)
                    }
                    _ => unreachable!(),
                }
            },
            || false,
        );
        assert_eq!(result, decode(&record(9)));
        assert_eq!(calls, 4);
    }
    #[test]
    fn malformed_copy_replies_and_duplicates_never_complete() {
        for reply in [83, 17 * 84 + 84] {
            assert_eq!(
                enumerate(|b| if b.is_empty() { Ok(84) } else { Ok(reply) }, || false),
                Err(SysError::Failed("pf token layout"))
            );
        }
        assert_eq!(
            enumerate(
                |b| {
                    if b.is_empty() {
                        return Ok(168);
                    }
                    b[..168].copy_from_slice(&[record(7), record(7)].concat());
                    Ok(168)
                },
                || false
            ),
            Err(SysError::Failed("pf token layout"))
        );
        let mut calls = 0;
        assert_eq!(
            enumerate(
                |b| {
                    calls += 1;
                    if b.is_empty() {
                        Ok(84)
                    } else {
                        Err(ReadError::Other)
                    }
                },
                || false
            ),
            Err(SysError::Failed("churn"))
        );
        assert_eq!(calls, 16);
    }
    #[test]
    fn full_buffers_double_and_never_certify_absence() {
        let mut lengths = vec![];
        assert_eq!(
            enumerate(
                |b| {
                    if b.is_empty() {
                        return Ok(0);
                    }
                    lengths.push(b.len());
                    Ok(b.len())
                },
                || false
            ),
            Err(SysError::Failed("churn"))
        );
        assert_eq!(
            lengths,
            (0..8).map(|i| 16 * 84 * (1 << i)).collect::<Vec<_>>()
        );
        assert_eq!(enumerate(|_| Err(ReadError::Noent), || false), Ok(vec![]));
        assert!(enumerate(|_| Ok(88), || false).is_err());
        assert!(enumerate(|_| Err(ReadError::Other), || false).is_err());
        assert_eq!(
            enumerate(|_| unreachable!(), || true),
            Err(SysError::TimedOut)
        );
    }
    #[test]
    fn assumptions_default_and_refuted_grant_nothing() {
        for state in [Assumption::Unknown, Assumption::Refuted] {
            assert_eq!(
                Assumptions {
                    pf_token_layout: state,
                    eexist_establishes_anonymous: state,
                    disable_voids_references: state,
                    fingerprints: state
                }
                .qualification(),
                ReferenceQualification::default()
            );
        }
    }
    proptest! {
        #[test]
        fn full_copy_and_subrecord_buffers_never_prove_absence(s in 1_usize..160, slots in 1_usize..500) {
            prop_assert_eq!(classify(slots * s, slots * s, s), Classification::Retry);
            prop_assert_eq!(classify(s - 1, 0, s), Classification::Retry);
        }
        #[test]
        fn classify_matches_xnu_copy_loop(c in prop_oneof![0_usize..20000, any::<usize>()], n in 0_usize..500, s in prop_oneof![1_usize..160, 1_usize..=usize::MAX]) {
            let mut copied = 0;
            for _ in 0..n {
                if c - copied < s { break; }
                copied += s;
            }
            let decision = classify(c, copied, s);
            prop_assert_eq!(decision == Classification::Complete, c / s > n);
            if decision == Classification::Complete { prop_assert_eq!(copied / s, n); }
        }
        #[test]
        fn arbitrary_bytes_never_panic_and_success_is_exact(bytes in prop::collection::vec(any::<u8>(), 0..3000)) {
            if let Ok(lines) = decode(&bytes) {
                prop_assert_eq!(lines.len() * STRIDE, bytes.len());
                prop_assert_eq!(lines.iter().map(|l| l.token).collect::<BTreeSet<_>>().len(), lines.len());
            }
        }
        #[test]
        fn fields_decode_little_endian(token in 1_u64..u64::MAX, timestamp in any::<u64>(), pid in 1_u32..i32::MAX.cast_unsigned()) {
            prop_assert_eq!(STRIDE, 84);
            let mut b = record(token);
            b[8..16].copy_from_slice(&timestamp.to_le_bytes());
            b[16..20].copy_from_slice(&pid.to_le_bytes());
            prop_assert_eq!(decode(&b), Ok(vec![RefLine { token, pid, timestamp }]));
        }
    }
}

/// One abandonable reader. A timed-out syscall retains its slot until return.
#[derive(Default)]
pub struct Reader {
    busy: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
struct Slot(std::sync::Arc<std::sync::atomic::AtomicBool>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}
impl Reader {
    /// Bound waiting without cancelling or sharing an outstanding syscall buffer.
    ///
    /// # Errors
    /// Busy, deadline expiry, worker failure or the operation's own error.
    pub fn read(
        &self,
        budget: std::time::Duration,
        operation: impl FnOnce() -> Result<Vec<RefLine>, SysError> + Send + 'static,
    ) -> Result<Vec<RefLine>, SysError> {
        use std::sync::{atomic::Ordering, mpsc};
        if budget.is_zero() {
            return Err(SysError::TimedOut);
        }
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| SysError::Failed("busy"))?;
        let slot = Slot(self.busy.clone());
        let (tx, rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("pf-references".into())
            .spawn(move || {
                let result = operation();
                drop(slot);
                let _ = tx.send(result);
            })
            .map_err(|_| SysError::Failed("pf token worker"))?;
        rx.recv_timeout(budget).map_err(|e| match e {
            mpsc::RecvTimeoutError::Timeout => SysError::TimedOut,
            mpsc::RecvTimeoutError::Disconnected => SysError::Failed("pf token worker"),
        })?
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod worker_tests {
    use super::*;
    #[test]
    fn timed_out_worker_keeps_slot_and_cannot_deliver_stale_result() {
        use std::{sync::mpsc, time::Duration};
        let reader = Reader::default();
        let (tx, rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        assert_eq!(
            reader.read(Duration::from_millis(20), move || {
                let _ = rx.recv();
                let _ = done_tx.send(());
                Ok(vec![RefLine {
                    token: 9,
                    pid: 1,
                    timestamp: 2,
                }])
            }),
            Err(SysError::TimedOut)
        );
        assert_eq!(
            reader.read(Duration::from_secs(1), || unreachable!()),
            Err(SysError::Failed("busy"))
        );
        tx.send(()).unwrap();
        done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let until = std::time::Instant::now() + Duration::from_secs(1);
        while reader.busy.load(std::sync::atomic::Ordering::Acquire) {
            assert!(std::time::Instant::now() < until);
            std::thread::yield_now();
        }
        assert_eq!(
            reader.read(Duration::from_secs(1), || Ok(vec![])),
            Ok(vec![])
        );
    }
}

/// Qualification selection; production has only the zero-sized default variant.
#[derive(Clone, Copy, Debug, Default)]
pub enum Override {
    /// No qualified record reader exists yet (R11).
    #[default]
    None,
    /// Per-instance disposable-runner assumptions.
    #[cfg(feature = "qualification")]
    Qualification(Assumptions),
}
impl Override {
    /// Resolve only compiled-in evidence sources.
    #[must_use]
    pub fn assumptions(self) -> Assumptions {
        match self {
            Self::None => Assumptions::default(),
            #[cfg(feature = "qualification")]
            Self::Qualification(assumptions) => assumptions,
        }
    }
}
#[cfg(all(test, not(feature = "qualification")))]
mod production_tests {
    #[test]
    fn production_override_has_only_none() {
        match super::Override::default() {
            super::Override::None => (),
        }
        assert_eq!(std::mem::size_of::<super::Override>(), 0);
        let mut copies = 0;
        assert_eq!(
            super::enumerate(
                |bytes| {
                    if bytes.is_empty() {
                        return Ok(0);
                    }
                    copies += 1;
                    assert_eq!(bytes.len(), 16 * 84);
                    Ok(0)
                },
                || false
            ),
            Ok(vec![])
        );
        assert_eq!(copies, 1);
        assert_eq!(
            super::Override::None.assumptions(),
            super::Assumptions::default()
        );
    }
}
#[cfg(test)]
mod allocation_tests {
    use super::*;
    use proptest::prelude::*;
    proptest! {
        #[test]
        fn allocation_capacity_is_never_the_ioctl_length(spare in 1_usize..2048) {
            let mut calls = 0;
            assert_eq!(
                enumerate_buffer(
                    |bytes| {
                        calls += 1;
                        if calls == 1 {
                            assert_eq!(bytes, [0_u8; 0]);
                            return Ok(84);
                        }
                        assert_eq!(bytes.len(), 17 * 84);
                        assert!(bytes.iter().all(|b| *b == 0));
                        Ok(0)
                    },
                    || false,
                    |length| {
                        let mut bytes = Vec::with_capacity(length + spare);
                        bytes.resize(length, 0);
                        bytes
                    },
                    16,
                    |_| {}
                ),
                Ok(vec![])
            );
            assert_eq!(calls, 2);
        }
    }
}
