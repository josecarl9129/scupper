//! Independent checks for the legacy safety contracts.
use super::*;

#[test]
fn capture_after_release_contains_the_completed_effect() {
    let mut e = joined();
    let token = e.machine.durable().pf_reference.unwrap();
    leave(&mut e, 2);
    before_pending(&mut e, Step::StopChild);
    e.platform.capture_after(Call::Release(token), 1);
    let deadline = Deadline(e.platform.now() + 5);
    let _ = e.platform.release(token, deadline);
    let p = e.platform.take_capture().unwrap();
    assert!(!p.tokens.contains_key(&token));
    assert!(!p.enabled);
}

#[test]
fn capture_after_kill_process_contains_the_dispatched_signal() {
    let mut e = joined();
    let child = e.child.clone().unwrap();
    let call = Call::KillProcess(child.pid, child.start_time);
    e.platform.capture_after(call, 1);
    let deadline = Deadline(e.platform.now() + 5);
    e.platform
        .kill_process(child.pid, child.start_time, deadline)
        .unwrap();
    let mut p = e.platform.take_capture().unwrap();
    assert!(p.signals.contains(&(child.pid, child.start_time)));
    p.tick();
    assert_eq!(p.procs[&child.pid].state, ProcState::Zombie);
}

#[test]
fn capture_after_kill_group_contains_the_dispatched_signal() {
    let e = joined();
    let child = e.child.clone().unwrap();
    let mut p = e.into_platform();
    p.abandon_process_group = true;
    p.restart();
    p.capture_after(Call::Kill(child.pid, child.start_time), 1);
    let deadline = Deadline(p.now() + 5);
    p.kill_group(child.pgid, child.pid, child.start_time, deadline)
        .unwrap();
    let mut p = p.take_capture().unwrap();
    assert!(p.signals.contains(&(child.pid, child.start_time)));
    p.tick();
    assert_eq!(p.procs[&child.pid].state, ProcState::Zombie);
}

#[test]
fn capture_after_uapi_contains_the_completed_setting() {
    let mut e = joined();
    let value = e.platform.settings.remove(&ConfigKey::Uapi).unwrap();
    e.platform
        .capture_after(Call::Configure(ConfigKey::Uapi), 1);
    let deadline = Deadline(e.platform.now() + 5);
    e.platform
        .configure(ConfigKey::Uapi, &value, deadline)
        .unwrap();
    let p = e.platform.take_capture().unwrap();
    assert_eq!(p.settings.get(&ConfigKey::Uapi), Some(&value));
}

#[test]
fn capture_after_artifact_cleanup_contains_the_completed_effect() {
    let mut e = joined();
    e.platform.artifacts.insert("socket".into());
    e.platform.capture_after(Call::CleanupArtifacts, 1);
    let deadline = Deadline(e.platform.now() + 5);
    e.platform.cleanup_artifacts(deadline).unwrap();
    assert!(e.platform.take_capture().unwrap().artifacts.is_empty());
}

#[test]
fn capture_after_child_reaping_contains_the_completed_effect() {
    let mut e = joined();
    let child = e.child.clone().unwrap();
    e.platform.procs.get_mut(&child.pid).unwrap().state = ProcState::Zombie;
    e.platform.capture_after(Call::ReapChildren, 1);
    let deadline = Deadline(e.platform.now() + 5);
    e.platform.reap_children(deadline).unwrap();
    let p = e.platform.take_capture().unwrap();
    assert!(!p.procs.contains_key(&child.pid));
    assert!(!p.children.contains_key(&child.pid));
}

#[test]
fn healthy_fresh_leave_completes_without_installing_enforcement() {
    let mut e = fresh();
    leave(&mut e, 1);
    drive(&mut e, 500);
    assert_left(&mut e, 1);
    assert_eq!(e.mode, Mode::Normal);
    assert!(e.platform.tokens.is_empty());
    assert!(!e.platform.calls.iter().any(|call| matches!(
        call,
        Call::LoadAnchor | Call::Acquire | Call::Spawn | Call::Flush
    )));
}

#[test]
fn reboot_during_durable_leave_with_unknown_flush_finishes_without_old_boot_release() {
    for reused in [false, true] {
        let mut e = joined();
        let old_tokens = e.platform.tokens.clone();
        let old_boot = e.platform.boot.clone();
        e.apply(Event::Repair(verify::Action::Rejoin));
        before_pending(&mut e, Step::FlushStates);
        e.platform.inject(
            Call::Flush,
            1,
            Fault::ToolHang {
                reaped: false,
                effect: true,
            },
        );
        e.dispatch(Step::FlushStates);
        assert!(matches!(e.platform.fence(), Fence::Open(_)));
        leave(&mut e, 2);
        before_pending(&mut e, Step::StopChild);
        assert!(e.machine.durable().leaving);
        let mut p = e.into_platform();
        p.mutate(Mutation::Reboot);
        assert_ne!(p.boot, old_boot);
        if reused {
            // A new-boot foreign owner can receive the same numeric token and even
            // the same fingerprint. Only boot evidence distinguishes ownership.
            p.tokens.clone_from(&old_tokens);
            p.enabled = true;
        }
        p.restart();
        p.calls.clear();
        let mut e = Engine::start(p).unwrap();
        drive(&mut e, 700);
        assert_left(&mut e, 2);
        if reused {
            assert_eq!(e.platform.tokens, old_tokens);
        } else {
            assert!(e.platform.tokens.is_empty());
        }
        assert!(!e.platform.calls.contains(&Call::Spawn));
        for token in old_tokens.keys() {
            assert!(!e.platform.calls.contains(&Call::Release(*token)));
        }
    }
}

#[test]
fn crash_after_spawn_sweeps_the_unacknowledged_child_before_retry() {
    let mut e = fresh();
    e.platform.abandon_process_group = true;
    e.platform.capture_after(Call::Spawn, 1);
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    drive(&mut e, 500);
    let mut p = e.platform.take_capture().unwrap();
    let orphan = p.children.values().next().unwrap().clone();
    assert!(p.settings.is_empty(), "capture must precede configuration");
    p.restart();
    assert!(p.procs.contains_key(&orphan.pid));
    p.calls.clear();
    let mut e = Engine::start(p).unwrap();
    drive(&mut e, 700);
    oracle(&mut e);
    assert_eq!(e.platform.children.len(), 1);
    assert!(!e.platform.procs.contains_key(&orphan.pid));
    assert!(
        matches!(e.status().enforcement, Verdict::Protected(ref proof) if proof.form() == Form::Joined)
    );
    let spawn = e
        .platform
        .calls
        .iter()
        .position(|call| *call == Call::Spawn)
        .unwrap();
    assert!(e.platform.calls[..spawn].iter().any(
        |call| matches!(call, Call::Kill(pid, _) | Call::KillProcess(pid, _) if *pid == orphan.pid)
    ));
}

#[test]
fn leave_with_unknown_anchor_removal_waits_for_reaping_before_acknowledgment() {
    let mut e = joined();
    e.platform.inject(
        Call::RemoveAnchor,
        1,
        Fault::ToolHang {
            reaped: false,
            effect: false,
        },
    );
    leave(&mut e, 2);
    elapse(&mut e, 10);
    assert!(!e.request_completed(2));
    assert!(!e.left_verified);
    assert!(matches!(e.platform.fence(), Fence::Open(_)));
    assert!(
        e.submit(Request {
            id: 3,
            kind: RequestKind::Join
        })
        .is_err()
    );
    e.platform.clear_faults();
    e.platform.release_unreaped();
    drive(&mut e, 700);
    assert_left(&mut e, 2);
}

fn configuration_readback_mismatch(key: ConfigKey, step: Step) {
    let mut e = fresh();
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    before_pending(&mut e, step);
    let spawns = e
        .platform
        .calls
        .iter()
        .filter(|call| **call == Call::Spawn)
        .count();
    e.platform
        .inject(Call::ReadConfig(key), 1, Fault::ReadbackDiffers);
    e.dispatch(step);
    e.run_until_quiescent(1);
    assert!(e.machine.failure().is_some(), "{key:?}");
    assert!(
        !matches!(e.status().enforcement, Verdict::Protected(_)),
        "{key:?}"
    );
    assert!(
        e.platform.settings.contains_key(&key),
        "Configure must have succeeded: {key:?}"
    );
    // All six configuration steps follow StartChild in the current plan.
    assert_eq!(
        e.platform
            .calls
            .iter()
            .filter(|call| **call == Call::Spawn)
            .count(),
        spawns
    );
}

macro_rules! readback_case {
    ($name:ident, $key:ident, $step:ident) => {
        #[test]
        fn $name() {
            configuration_readback_mismatch(ConfigKey::$key, Step::$step);
        }
    };
}
readback_case!(configuration_readback_mismatch_uapi, Uapi, ConfigureUapi);
readback_case!(
    configuration_readback_mismatch_addresses,
    Addresses,
    ConfigureAddresses
);
readback_case!(configuration_readback_mismatch_mtu, Mtu, ConfigureMtu);
readback_case!(
    configuration_readback_mismatch_endpoint_route,
    EndpointRoute,
    ConfigureEndpointRoute
);
readback_case!(
    configuration_readback_mismatch_split_routes,
    SplitRoutes,
    ConfigureSplitRoutes
);
readback_case!(configuration_readback_mismatch_dns, Dns, ConfigureDns);

fn assert_oracle_rejects_drift(drift: usize) {
    let mut e = joined();
    match drift {
        0 => e.platform.main_rules.clear(),
        1 => e.platform.main_rules.push_str("pass quick all\n"),
        2 => {
            e.platform.skipped.insert("en0".parse().unwrap());
        }
        3 => {
            e.platform.anchor = Some(
                policy::render_pre_tunnel(&e.inputs().unwrap())
                    .as_str()
                    .to_owned(),
            );
        }
        4 => e.platform.states.push(true),
        _ => {
            e.platform
                .interface_states
                .insert("en0".parse().unwrap(), vec![true]);
        }
    }
    // No engine boundary has run since the external mutation. A cached
    // verifier result must not make the independent test oracle agree.
    assert!(matches!(e.status().enforcement, Verdict::Protected(_)));
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| oracle(&mut e))).is_err(),
        "drift {drift}"
    );
}

macro_rules! oracle_case {
    ($name:ident, $drift:expr) => {
        #[test]
        fn $name() {
            assert_oracle_rejects_drift($drift);
        }
    };
}
oracle_case!(oracle_rejects_missing_hook, 0);
oracle_case!(oracle_rejects_quick_pass, 1);
oracle_case!(oracle_rejects_skip, 2);
oracle_case!(oracle_rejects_stale_anchor, 3);
oracle_case!(oracle_rejects_global_states, 4);
oracle_case!(oracle_rejects_interface_states, 5);

#[test]
fn fake_records_conflicting_writers_before_reaping() {
    for (call, tool) in [
        (Call::LoadAnchor, Tool::Pfctl),
        (Call::RemoveAnchor, Tool::Pfctl),
        (Call::Configure(ConfigKey::EndpointRoute), Tool::Route),
        (Call::Configure(ConfigKey::Dns), Tool::Scutil),
        (Call::Configure(ConfigKey::Mtu), Tool::Ifconfig),
    ] {
        let mut e = joined();
        e.platform
            .unreaped
            .push(crate::platform::Unreaped { tool, pid: 8001 });
        let deadline = Deadline(e.platform.now() + 5);
        match call {
            Call::LoadAnchor => {
                let _ = e
                    .platform
                    .load_anchor(&policy::render_pre_tunnel(&e.inputs().unwrap()), deadline);
            }
            Call::Configure(key) => {
                let value = e.platform.settings[&key].clone();
                let _ = e.platform.configure(key, &value, deadline);
            }
            _ => {
                let _ = e.platform.remove_anchor(deadline);
            }
        }
        assert_eq!(
            e.platform.violations,
            ["mutation before same-family writer reaped"]
        );
    }
}

#[test]
fn fake_records_current_reference_release_without_durable_leave() {
    let mut e = joined();
    let token = e.machine.durable().pf_reference.unwrap();
    let deadline = Deadline(e.platform.now() + 5);
    let _ = e.platform.release(token, deadline);
    assert_eq!(
        e.platform.violations,
        ["current reference released before durable Leave"]
    );
}

#[test]
fn fake_records_reference_release_without_same_boot_evidence() {
    for boot in [
        None,
        Some(BootId::try_from("99999999-9999-9999-9999-999999999999").unwrap()),
    ] {
        let mut e = joined();
        let token = e.machine.durable().pf_reference.unwrap();
        leave(&mut e, 2);
        before_pending(&mut e, Step::StopChild);
        e.platform.boot = boot;
        let deadline = Deadline(e.platform.now() + 5);
        let _ = e.platform.release(token, deadline);
        assert_eq!(
            e.platform.violations,
            ["reference released without same-boot evidence"]
        );
    }
}

#[test]
fn numeric_release_requires_qualified_matching_fingerprint() {
    for qualified in [false, true] {
        for mismatch in [0, 1, 2, 3] {
            let mut e = joined();
            let token = e.machine.durable().pf_reference.unwrap();
            e.platform.fingerprints_qualified = qualified;
            match mismatch {
                1 => e.platform.tokens.get_mut(&token).unwrap().pid += 1,
                2 => e.platform.tokens.get_mut(&token).unwrap().timestamp += 1,
                3 => {
                    e.snapshot
                        .references
                        .iter_mut()
                        .flatten()
                        .find(|r| r.key == ReferenceEntry::Token(token))
                        .unwrap()
                        .fingerprint = None;
                }
                _ => (),
            }
            // Same numeric value, new foreign PID or timestamp must be retained.
            let holder = e.platform.tokens[&token].clone();
            leave(&mut e, 2);
            e.platform.calls.clear();
            drive(&mut e, 400);
            let allowed = qualified && mismatch == 0;
            assert_eq!(
                e.platform.calls.contains(&Call::Release(token)),
                allowed,
                "qualified={qualified}, mismatch={mismatch}"
            );
            if !allowed {
                assert_eq!(e.platform.tokens.get(&token), Some(&holder));
            }
        }
    }
}
