//! Audit-to-alert adapter: external strings and identities never enter alerts.
use crate::{Event, EventKind, Outcome, VerdictCode};
use scupper_core::alerts::{self, Alert, OperationalEvent as E};
impl Event {
    /// Derive an operational alert from the closed event alphabet.
    #[must_use]
    pub fn alert(&self) -> Option<Alert> {
        let projection = match &self.kind {
            EventKind::FailClosedStarted {
                reason: crate::Reason::NoHealthyExit | crate::Reason::PinnedExitDown,
                ..
            } => E::FailClosedStarted,
            EventKind::FailClosedStarted {
                reason: crate::Reason::Quarantined,
                ..
            }
            | EventKind::QuarantineChanged { active: true } => E::QuarantineSet,
            EventKind::FailClosedEnded { duration } => E::FailClosedEnded(duration.as_secs()),
            EventKind::Failover { .. } => E::Failover,
            EventKind::Failback { .. } => E::Failback,
            EventKind::RepairSuppressed { .. } => E::RepairSuppressed,
            EventKind::Repair {
                result: Outcome::Succeeded,
                ..
            } => E::RepairRestored,
            EventKind::CheckVerdictChanged {
                to: VerdictCode::Unprotected,
                ..
            } => E::Unprotected,
            EventKind::CheckVerdictChanged {
                to: VerdictCode::Protected,
                ..
            } => E::ProtectionRestored,
            EventKind::QuarantineChanged { active: false } => E::QuarantineCleared,
            EventKind::PersistenceFailed { .. } => E::PersistenceFailed,
            EventKind::Flapping {} => E::Flapping,
            EventKind::Boot {
                result: Outcome::Recovered,
                step: crate::StepKind::EventLog,
            } => E::PersistenceRecovered,
            _ => return None,
        };
        let mut alert = alerts::map(projection, self.seq, self.at.0);
        if let EventKind::CheckVerdictChanged {
            to: VerdictCode::Unprotected,
            reason,
            ..
        } = self.kind
        {
            use alerts::ProtectionReason as R;
            alert.reason = Some(match reason {
                crate::ObjectKind::Ruleset => R::Ruleset,
                crate::ObjectKind::ForeignLink => R::ForeignLink,
                crate::ObjectKind::TcHook => R::TcHook,
                crate::ObjectKind::Peer => R::Peer,
                crate::ObjectKind::ExitIp => R::ExitIp,
                _ => R::Other,
            });
        }
        Some(alert)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::too_many_lines)]
mod tests {
    use super::*;
    use crate::{Actor, Command, Identifier, Reason, UnixSeconds};
    #[test]
    fn audit_free_text_and_ids_cannot_enter_alerts_or_payloads() {
        let mut event = Event {
            seq: 1,
            at: UnixSeconds(10),
            kind: EventKind::AdminAction {
                command: Command::Disconnect,
                reason: Some("https://fixture.invalid/secret 10.99.0.2 destination.invalid".into()),
            },
            actor: Actor::Daemon,
            gateway: Identifier::try_from("gw1".to_owned()).unwrap(),
            config_version: None,
        };
        assert!(event.alert().is_none());
        event.kind = EventKind::FailClosedStarted {
            reason: Reason::NoHealthyExit,
            exit: Some(Identifier::try_from("secret-destination".to_owned()).unwrap()),
        };
        let alert = event.alert().unwrap();
        assert!(!alert.body().contains("secret"));
        assert_eq!(alert.severity, scupper_core::config::Severity::Critical);
        event.kind = EventKind::CheckVerdictChanged {
            reason: crate::ObjectKind::Unknown,
            from: VerdictCode::Unprotected,
            to: VerdictCode::ObservationError,
        };
        assert!(event.alert().is_none()); // Unknown observations do not prove recovery.
        event.kind = EventKind::SinkFailed {
            sink: Identifier::try_from("fixture".to_owned()).unwrap(),
            reason: Reason::ExecutionFailed,
        };
        assert!(event.alert().is_none()); // No recursive sink-failure storm.
    }
    fn event(kind: EventKind) -> Event {
        Event {
            seq: 1,
            at: UnixSeconds(10),
            kind,
            actor: Actor::Daemon,
            gateway: Identifier::try_from("fixture".to_owned()).unwrap(),
            config_version: None,
        }
    }
    #[test]
    fn all_drift_object_reason_pairs_are_observations_never_unprotected_verdicts() {
        for object in crate::ObjectKind::NAMES {
            for reason in crate::Reason::NAMES {
                let object = serde_json::from_value(serde_json::json!(object)).unwrap();
                let reason = serde_json::from_value(serde_json::json!(reason)).unwrap();
                assert!(
                    event(EventKind::DriftDetected { object, reason })
                        .alert()
                        .is_none()
                );
            }
        }
    }
    #[test]
    fn decision_mapping_table_covers_critical_lifecycles_and_warning_rows() {
        use scupper_core::{
            alerts::{AlertKey as K, AlertState as S},
            config::Severity as V,
        };
        for (kind, key, severity, state) in [
            (
                EventKind::FailClosedStarted {
                    reason: Reason::NoHealthyExit,
                    exit: None,
                },
                K::FailClosed,
                V::Critical,
                S::Firing,
            ),
            (
                EventKind::FailClosedStarted {
                    reason: Reason::PinnedExitDown,
                    exit: None,
                },
                K::FailClosed,
                V::Critical,
                S::Firing,
            ),
            (
                EventKind::FailClosedEnded {
                    duration: std::time::Duration::from_secs(1),
                },
                K::FailClosed,
                V::Critical,
                S::Resolved,
            ),
            (
                EventKind::CheckVerdictChanged {
                    reason: crate::ObjectKind::Unknown,
                    from: VerdictCode::Protected,
                    to: VerdictCode::Unprotected,
                },
                K::Unprotected,
                V::Critical,
                S::Firing,
            ),
            (
                EventKind::CheckVerdictChanged {
                    reason: crate::ObjectKind::Unknown,
                    from: VerdictCode::ObservationError,
                    to: VerdictCode::Protected,
                },
                K::Unprotected,
                V::Critical,
                S::Resolved,
            ),
            (
                EventKind::QuarantineChanged { active: true },
                K::Quarantine,
                V::Critical,
                S::Firing,
            ),
            (
                EventKind::QuarantineChanged { active: false },
                K::Quarantine,
                V::Critical,
                S::Resolved,
            ),
            (
                EventKind::Failover {
                    from: Identifier::try_from("first".to_owned()).unwrap(),
                    to: Identifier::try_from("second".to_owned()).unwrap(),
                    cause: Reason::HealthFailure,
                },
                K::Failover,
                V::Warning,
                S::Firing,
            ),
            (
                EventKind::Failback {
                    from: Identifier::try_from("second".to_owned()).unwrap(),
                    to: Identifier::try_from("first".to_owned()).unwrap(),
                },
                K::Failover,
                V::Warning,
                S::Resolved,
            ),
            (
                EventKind::RepairSuppressed {
                    object: crate::ObjectKind::Ruleset,
                },
                K::RepairSuppressed,
                V::Warning,
                S::Firing,
            ),
            (
                EventKind::Repair {
                    kind: crate::StepKind::LoadRuleset,
                    class: crate::RepairClass::Restore,
                    result: Outcome::Succeeded,
                },
                K::RepairSuppressed,
                V::Warning,
                S::Resolved,
            ),
            (
                EventKind::PersistenceFailed {
                    reason: Reason::EventWrite,
                },
                K::Persistence,
                V::Warning,
                S::Firing,
            ),
            (
                EventKind::Boot {
                    result: Outcome::Recovered,
                    step: crate::StepKind::EventLog,
                },
                K::Persistence,
                V::Warning,
                S::Resolved,
            ),
            (EventKind::Flapping {}, K::Flapping, V::Warning, S::Firing),
        ] {
            let alert = event(kind).alert().unwrap();
            assert_eq!(
                (alert.key, alert.severity, alert.state),
                (key, severity, state)
            );
        }
        for verdict in [
            VerdictCode::ObservationError,
            VerdictCode::Degraded,
            VerdictCode::FailClosed,
            VerdictCode::Unsupervised,
        ] {
            assert!(
                event(EventKind::CheckVerdictChanged {
                    reason: crate::ObjectKind::Unknown,
                    from: VerdictCode::Unprotected,
                    to: verdict
                })
                .alert()
                .is_none()
            );
        }
        assert!(
            event(EventKind::FailClosedStarted {
                reason: Reason::AdminDisconnected,
                exit: None
            })
            .alert()
            .is_none()
        );
    }
    proptest::proptest! {
        #[test]
        fn every_variant_discards_injected_external_strings(octets in proptest::prelude::any::<[u8;4]>(), suffix in "[a-z]{16,24}") {
            let client = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
            let secret = format!("secret-{suffix}");
            let destination = format!("destination-{suffix}.invalid");
            let url = format!("https://fixture.invalid/{secret}");
            let id = Identifier::try_from(secret.clone()).unwrap();
            for mut kind in crate::event::event_samples() {
                match &mut kind {
                    EventKind::Failover { from, to, .. } | EventKind::Failback { from, to } => { *from=id.clone(); *to=id.clone(); }
                    EventKind::ExitHealthChanged { exit, .. } | EventKind::FailClosedStarted { exit: Some(exit), .. } => *exit=id.clone(),
                    EventKind::SinkFailed { sink, .. } => *sink=id.clone(),
                    EventKind::AdminAction { reason, .. } => *reason=Some(format!("{client} {destination} {url} {secret}")),
                    _ => {}
                }
                let mut event = event(kind); event.gateway=id.clone();
                event.actor=Actor::Device { id:id.clone(), user:id.clone() };
                let input=serde_json::to_string(&event).unwrap();
                proptest::prop_assert!(input.contains(&secret));
                if let Some(alert)=event.alert() {
                    let mut output=format!("{alert:?}{}", serde_json::to_string(&alert).unwrap());
                    for preset in ["generic", "telegram", "pushover", "ntfy"] {
                        let settings: scupper_core::config::AlertSink = serde_json::from_value(if preset=="ntfy" {
                            serde_json::json!({"kind":"ntfy","url_ref":secret,"min_severity":"info"})
                        } else { serde_json::json!({"kind":"webhook","preset":preset,"url_ref":secret,"min_severity":"info"}) }).unwrap();
                        output.push_str(&serde_json::to_string(&scupper_core::alerts::render(&settings, &alert)).unwrap());
                    }
                    for forbidden in [&client, &destination, &url, &secret] { proptest::prop_assert!(!output.contains(forbidden)); }
                }
            }
        }
    }
}
