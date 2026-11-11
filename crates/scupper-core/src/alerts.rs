//! Typed, destination-free alert rendering and caller-clock delivery policy.
pub use crate::config::Severity;
use crate::config::{AlertSink as Settings, WebhookPreset};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Stable operational grouping; never a network address or external string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKey {
    /// No usable exit.
    FailClosed,
    /// Exit selection changed.
    Failover,
    /// Containment needs attention.
    Unprotected,
    /// Repair budget exhausted.
    RepairSuppressed,
    /// Persistent audit storage unavailable.
    Persistence,
    /// Exit instability.
    Flapping,
    /// Persisted containment quarantine.
    Quarantine,
    /// Explicit delivery test.
    Test,
}
/// Incident lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertState {
    /// Incident active.
    Firing,
    /// Incident ended.
    Resolved,
}
/// Pure event adapter input. No arbitrary text is accepted.
#[derive(Debug, Clone, Copy)]
pub struct AlertEvent {
    /// Operational grouping.
    pub key: AlertKey,
    /// Operational importance.
    pub severity: Severity,
    /// Lifecycle transition.
    pub state: AlertState,
    /// Audit sequence.
    pub seq: u64,
    /// Audit timestamp, seconds.
    pub at: u64,
    /// Known incident duration in seconds.
    pub duration: u64,
}
/// Closed audit projection; payload-bearing audit fields are deliberately absent.
#[derive(Debug, Clone, Copy)]
pub enum OperationalEvent {
    /// Fail-closed transition.
    FailClosedStarted,
    /// Recovery with measured duration.
    FailClosedEnded(u64),
    /// Automatic exit switch.
    Failover,
    /// Return to preferred exit.
    Failback,
    /// Repair budget reached.
    RepairSuppressed,
    /// A repair succeeded after suppression.
    RepairRestored,
    /// Containment drift observed.
    Unprotected,
    /// Verified containment restored.
    ProtectionRestored,
    /// Quarantine latch set.
    QuarantineSet,
    /// Quarantine latch cleared.
    QuarantineCleared,
    /// Audit storage failure.
    PersistenceFailed,
    /// Audit storage recovered.
    PersistenceRecovered,
    /// Repeated exit switches.
    Flapping,
}
/// Map the typed event projection to the alert key, severity and lifecycle.
#[must_use]
pub fn map(event: OperationalEvent, seq: u64, at: u64) -> Alert {
    use AlertKey as K;
    use AlertState::{Firing, Resolved};
    use OperationalEvent as E;
    use Severity::{Critical, Warning};
    let (key, severity, state, duration) = match event {
        E::FailClosedStarted => (K::FailClosed, Critical, Firing, 0),
        E::FailClosedEnded(duration) => (K::FailClosed, Critical, Resolved, duration),
        E::Failover => (K::Failover, Warning, Firing, 0),
        E::Failback => (K::Failover, Warning, Resolved, 0),
        E::RepairSuppressed => (K::RepairSuppressed, Warning, Firing, 0),
        E::RepairRestored => (K::RepairSuppressed, Warning, Resolved, 0),
        E::Unprotected => (K::Unprotected, Critical, Firing, 0),
        E::ProtectionRestored => (K::Unprotected, Critical, Resolved, 0),
        E::QuarantineSet => (K::Quarantine, Critical, Firing, 0),
        E::QuarantineCleared => (K::Quarantine, Critical, Resolved, 0),
        E::PersistenceFailed => (K::Persistence, Warning, Firing, 0),
        E::PersistenceRecovered => (K::Persistence, Warning, Resolved, 0),
        E::Flapping => (K::Flapping, Warning, Firing, 0),
    };
    AlertEvent {
        key,
        severity,
        state,
        seq,
        at,
        duration,
    }
    .into()
}
/// An alert contains only bounded vocabulary and numeric operational fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    /// Grouping.
    pub key: AlertKey,
    /// Importance.
    pub severity: Severity,
    /// Lifecycle.
    pub state: AlertState,
    /// Originating sequence.
    pub seq: u64,
    /// Originating wall time.
    pub at: u64,
    /// Incident duration in seconds.
    pub duration: u64,
    /// Coalesced occurrences.
    pub count: u64,
    /// Suppressed notifications since the previous delivery.
    pub suppressed: u64,
}
impl From<AlertEvent> for Alert {
    fn from(e: AlertEvent) -> Self {
        Self {
            key: e.key,
            severity: e.severity,
            state: e.state,
            seq: e.seq,
            at: e.at,
            duration: e.duration,
            count: 1,
            suppressed: 0,
        }
    }
}
impl Alert {
    /// Fixed title, derived exclusively from an enum.
    #[must_use]
    pub fn title(&self) -> &'static str {
        match self.key {
            AlertKey::FailClosed => "Scupper failing closed",
            AlertKey::Failover => "Scupper exit changed",
            AlertKey::Unprotected => "Scupper protection changed",
            AlertKey::RepairSuppressed => "Scupper repair suppressed",
            AlertKey::Persistence => "Scupper persistence failed",
            AlertKey::Flapping => "Scupper exits flapping",
            AlertKey::Quarantine => "Scupper quarantined",
            AlertKey::Test => "Scupper test alert",
        }
    }
    /// Bounded body, with no caller-supplied strings.
    #[must_use]
    pub fn body(&self) -> String {
        format!(
            "{}: {}; severity={}; seq={}; duration={}s; count={}; suppressed={}",
            self.title(),
            self.state,
            self.severity,
            self.seq,
            self.duration,
            self.count,
            self.suppressed
        )
    }
    /// Explicit Info test; bypasses configured minimum severity.
    #[must_use]
    pub fn test(at: u64) -> Self {
        AlertEvent {
            key: AlertKey::Test,
            severity: Severity::Info,
            state: AlertState::Firing,
            seq: 0,
            at,
            duration: 0,
        }
        .into()
    }
}
impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        })
    }
}
impl std::fmt::Display for AlertState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Firing => "firing",
            Self::Resolved => "resolved",
        })
    }
}
fn rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Critical => 2,
    }
}
/// Minimum importance filter.
#[must_use]
pub fn eligible(alert: &Alert, minimum: Severity) -> bool {
    rank(alert.severity) >= rank(minimum)
}
/// Rendered HTTP entity and safe header values. No URL enters this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    /// MIME type.
    pub content_type: String,
    /// Fixed-name headers.
    pub headers: BTreeMap<String, String>,
    /// Serialized entity.
    pub body: String,
}
/// Render only typed fields; authentication remains exclusively in the URL.
#[must_use]
pub fn render(settings: &Settings, alert: &Alert) -> Payload {
    let mut headers = BTreeMap::new();
    let (content_type, body) = match settings {
        Settings::Ntfy {..} => {
            headers.insert("Title".into(),alert.title().into());
            headers.insert("Priority".into(),match (alert.severity, alert.state) {(Severity::Critical, AlertState::Firing)=>"5",(Severity::Critical, AlertState::Resolved)|(Severity::Warning, AlertState::Firing)=>"4",_=>"3"}.into());
            ("text/plain; charset=utf-8",alert.body())
        }
        Settings::Webhook {preset,..} => ("application/json", match preset {
            WebhookPreset::Generic => serde_json::json!({"key":alert.key,"severity":alert.severity,"state":alert.state,"seq":alert.seq,"at":alert.at,"duration":alert.duration,"count":alert.count,"suppressed":alert.suppressed,"title":alert.title(),"body":alert.body()}).to_string(),
            WebhookPreset::Telegram => serde_json::json!({"text":alert.body()}).to_string(),
            WebhookPreset::Pushover => serde_json::json!({"title":alert.title(),"message":alert.body(),"priority":i32::from(alert.severity == Severity::Critical && alert.state == AlertState::Firing)}).to_string(),
        }),
    };
    Payload {
        content_type: content_type.into(),
        headers,
        body,
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Incident {
    first: u64,
    window: u64,
    count: u64,
    resolved: Option<Alert>,
}
/// Same-key ten-minute incident window, driven by audit time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coalescer {
    #[serde(skip, default = "default_hold")]
    hold: u64,
    incidents: BTreeMap<AlertKey, Incident>,
}
fn default_hold() -> u64 {
    600
}
impl Default for Coalescer {
    fn default() -> Self {
        Self {
            hold: 600,
            incidents: BTreeMap::new(),
        }
    }
}
impl Coalescer {
    /// Shorten the hold only in testing builds for the real-worker lab.
    #[cfg(feature = "testing")]
    pub fn set_test_hold(&mut self, seconds: u64) {
        self.hold = seconds.clamp(1, 600);
    }

    /// Apply a transition using an explicit monotonic policy clock.
    pub fn push_at(&mut self, mut alert: Alert, now: u64) -> Vec<Alert> {
        let mut ready = self.flush(now);
        let critical = alert.severity == Severity::Critical;
        match self.incidents.get_mut(&alert.key) {
            Some(incident) if alert.state == AlertState::Firing => {
                incident.count = incident.count.saturating_add(1);
                incident.resolved = None;
                if !critical && now.saturating_sub(incident.window) >= self.hold {
                    incident.window = now;
                    alert.count = incident.count;
                    alert.duration = alert.duration.max(now.saturating_sub(incident.first));
                    ready.push(alert);
                }
            }
            Some(incident) => {
                alert.count = incident.count;
                alert.duration = alert.duration.max(now.saturating_sub(incident.first));
                if critical {
                    self.incidents.remove(&alert.key);
                    ready.push(alert);
                } else {
                    incident.resolved = Some(alert);
                }
            }
            None if alert.state == AlertState::Firing => {
                self.incidents.insert(
                    alert.key,
                    Incident {
                        first: now,
                        window: now,
                        count: 1,
                        resolved: None,
                    },
                );
                ready.push(alert);
            }
            None => {}
        }
        ready
    }
    /// Caller-clock convenience for pure policy tests.
    pub fn push(&mut self, alert: Alert) -> Vec<Alert> {
        let now = alert.at;
        self.push_at(alert, now)
    }
    /// Translate persisted monotonic ages after a clock origin reset.
    pub fn rebase(&mut self, from: u64, to: u64) {
        for incident in self.incidents.values_mut() {
            incident.first = to.saturating_sub(from.saturating_sub(incident.first));
            incident.window = to.saturating_sub(from.saturating_sub(incident.window));
        }
    }
    /// Earliest retained resolution, which must precede later notifications.
    #[must_use]
    pub fn pending_seq(&self) -> Option<u64> {
        self.incidents
            .values()
            .filter_map(|v| v.resolved.as_ref().map(|a| a.seq))
            .min()
    }
    /// Emit completed windows; keep active incidents until recovery.
    pub fn flush(&mut self, now: u64) -> Vec<Alert> {
        let keys: Vec<_> = self
            .incidents
            .iter()
            .filter(|(_, v)| now.saturating_sub(v.window) >= self.hold && v.resolved.is_some())
            .map(|(k, _)| *k)
            .collect();
        let mut ready = Vec::new();
        for key in keys {
            if let Some(Incident {
                resolved: Some(alert),
                ..
            }) = self.incidents.remove(&key)
            {
                ready.push(alert);
            }
        }
        ready.sort_by_key(|a| a.seq);
        ready
    }
}
/// Per-sink burst five, refill one per 300 seconds, including Critical.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBucket {
    tokens: u64,
    refilled: u64,
}
impl TokenBucket {
    /// Start full at the caller's clock.
    #[must_use]
    pub fn new(now: u64) -> Self {
        Self {
            tokens: 5,
            refilled: now,
        }
    }
    /// Translate the refill age when the monotonic clock origin resets.
    pub fn rebase(&mut self, from: u64, to: u64) {
        self.refilled = to.saturating_sub(from.saturating_sub(self.refilled));
    }
    /// Charge one admitted notification. Refusals must be suppressed.
    pub fn take(&mut self, now: u64) -> bool {
        self.refilled = self.refilled.min(now);
        let refill = now.saturating_sub(self.refilled) / 300;
        if refill > 0 {
            self.tokens = 5.min(self.tokens.saturating_add(refill));
            self.refilled = self.refilled.saturating_add(refill.saturating_mul(300));
        }
        if self.tokens == 0 {
            false
        } else {
            self.tokens -= 1;
            true
        }
    }
}
/// Retry delay, starting at five seconds and capped at fifteen minutes.
#[must_use]
pub fn backoff(attempt: u32) -> u64 {
    5u64.saturating_mul(1u64.checked_shl(attempt).unwrap_or(u64::MAX))
        .min(900)
}
/// Twenty-four hours is the maximum retry lifetime.
#[must_use]
pub fn exhausted(start: u64, now: u64) -> bool {
    now.saturating_sub(start) >= 86_400
}
/// Value-free failure category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SinkError {
    /// Retry with backoff.
    #[error("alert delivery transient failure")]
    Transient,
    /// Do not retry this notification.
    #[error("alert delivery permanent failure")]
    Permanent,
    /// Local secret configuration is unusable.
    #[error("secret")]
    Secret,
    /// Dedicated delivery account is unavailable.
    #[error("account")]
    Account,
    /// Child execution failed.
    #[error("exec")]
    Exec,
    /// Local delivery protocol failed.
    #[error("internal")]
    Internal,
}
/// Delivery implementation boundary, used outside the safety loop.
pub trait AlertSink: Send {
    /// Configured sink identity.
    fn name(&self) -> &str;
    /// One bounded attempt.
    /// # Errors
    /// Returns a value-free retry classification.
    fn deliver(&self, alert: &Alert) -> Result<(), SinkError>;
}
/// HTTP status retry classification; redirects are refused permanently.
/// # Errors
/// Non-success statuses return their retry class.
pub fn http_status(code: u16) -> Result<(), SinkError> {
    match code {
        200..=299 => Ok(()),
        408 | 429 | 500..=599 => Err(SinkError::Transient),
        _ => Err(SinkError::Permanent),
    }
}
