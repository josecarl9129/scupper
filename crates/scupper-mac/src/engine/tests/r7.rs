use super::*;

#[test]
fn r7_left_commits_incarnation_without_pf_mutation_or_spawn_and_lists_calls() {
    let p = FakePlatform::new().unwrap();
    let snapshot = Snapshot::initial(Some(501), p.boot.clone());
    let mut p = fixture(&snapshot);
    p.method_trace = Some(std::cell::RefCell::new(vec![]));
    p.install_error = Some("install record: no writer before 5a3");
    let mut e = Engine::start(p).unwrap();
    drive(&mut e, 400);
    let methods: std::collections::BTreeSet<_> = e
        .platform
        .method_trace
        .as_ref()
        .unwrap()
        .borrow()
        .iter()
        .copied()
        .collect();
    assert!(e.helper_committed);
    assert_eq!(e.committed.helper, Some(e.platform.helper.clone()));
    for copy in [Copy::A, Copy::B] {
        assert_eq!(
            read_snapshot(&mut e.platform, copy).helper,
            Some(e.platform.helper.clone())
        );
    }
    assert!(!e.platform.calls.iter().any(|c| matches!(
        c,
        Call::Acquire
            | Call::EnablePf
            | Call::Release(_)
            | Call::LoadAnchor
            | Call::Flush
            | Call::RemoveAnchor
            | Call::Spawn
    )));
    let actual: std::collections::BTreeSet<_> =
        e.platform.calls.iter().map(|c| format!("{c:?}")).collect();
    eprintln!("Left effect calls: {actual:?}");
    eprintln!("Every Left Platform method: {methods:?}");
    let expected_methods = crate::platform::tests::LEFT_METHODS
        .iter()
        .copied()
        .collect();
    assert_eq!(methods, expected_methods);
    let expected = [
        "AcquireInstanceLock",
        "BootId",
        "CreateControlSocket",
        "ExecutableId",
        "Fence",
        "ImageUuid",
        "Incarnation",
        "Install",
        "Now",
        "Processes",
        "Read(A)",
        "Read(B)",
        "ReapChildren",
        "Write(A)",
        "Write(B)",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(actual, expected);
    assert!(e.platform.children.is_empty());
    let d = Deadline(e.platform.now() + 5);
    assert!(
        matches!(e.platform.processes(d),Enumeration::Complete(ref entries) if !entries.iter().any(|p|p.pid!=e.platform.helper.pid && p.path.as_deref()==Some(Path::new(CHILD_PATH))))
    );
}

#[test]
fn r7_install_no_writer_selects_lockdown_for_sixty_seconds_without_protected() {
    for qualified in [false, true] {
        install_no_writer(qualified);
    }
}
fn install_no_writer(qualified: bool) {
    let p = FakePlatform::new().unwrap();
    let mut snapshot = Snapshot::initial(Some(501), p.boot.clone());
    snapshot.machine.join_intended = true;
    snapshot.machine.hold = true;
    let mut p = fixture(&snapshot);
    p.install_error = Some("install record: no writer before 5a3");
    p.qualification_trace = Some(vec![]);
    // Exercise current native support and the future qualified-firewall path.
    if !qualified {
        p.firewall_qualification = None;
    }
    let mut e = Engine::start(p).unwrap();
    assert!(e.platform.calls.contains(&Call::Install));
    assert_eq!(e.machine.pre_tunnel_policy(), Kind::Lockdown);
    let started = e.platform.now();
    for _ in 0..1200 {
        tick(&mut e);
        assert!(!matches!(e.status().enforcement, Verdict::Protected(_)));
        assert!(e.committed.machine.hold);
        assert!(!e.platform.calls.contains(&Call::Spawn));
    }
    assert!(e.platform.now() >= started + 60);
    assert!(
        e.platform.calls.contains(&Call::Acquire),
        "assertion failed: fresh-state reserved -E must occur"
    );
    let copies = [
        read_snapshot(&mut e.platform, Copy::A),
        read_snapshot(&mut e.platform, Copy::B),
    ];
    let trace = e.platform.qualification_trace.as_ref().unwrap();
    assert!(crate::decode::qualification_trace::acquisitions(trace, &copies).unwrap() > 0);
    assert!(crate::decode::qualification_trace::installed_candidates_safe(trace));
    assert_eq!(
        trace
            .iter()
            .any(|s| s == "verification_kind:Lockdown:verification_protected:true"),
        qualified
    );
    for line in trace
        .iter()
        .filter_map(|s| s.strip_prefix("snapshot_write:"))
    {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(value["snapshot"]["machine"]["hold"], true);
        assert!(value["snapshot"]["machine"]["previous_generation"].is_null());
    }
    assert_eq!(
        e.platform.anchor.as_deref(),
        Some(policy::render_lockdown().as_str())
    );
    for call in [Call::LoadAnchor, Call::ReadAnchor, Call::Flush] {
        assert!(e.platform.calls.contains(&call), "{call:?}");
    }
    assert_eq!(
        e.platform.install_error,
        Some("install record: no writer before 5a3")
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Keep explicit failure, repair and publication evidence together.
fn r7_selective_failure_repairs_with_reload_and_global_flush_before_protected() {
    let mut e = fresh();
    let original = e.install.as_ref().unwrap().config.inputs.clone();
    let mut physical = original.physical().clone();
    physical.insert(
        "en9".parse().unwrap(),
        scupper_core::mac::DhcpPhase::AcquiringRebinding,
    );
    let old = scupper_core::mac::Inputs::new(
        original.selected().clone(),
        original.endpoint().clone(),
        physical,
        original.tunnel().clone(),
        original.hop_limit().clone(),
    )
    .unwrap();
    e.install.as_mut().unwrap().config.inputs = old.clone();
    e.install
        .as_mut()
        .unwrap()
        .config
        .qualification
        .physical
        .insert("en9".parse().unwrap());
    e.platform.install.config = e.install.as_ref().unwrap().config.clone();
    e.platform
        .additional_interfaces
        .insert("en9".parse().unwrap());
    e.submit(Request {
        id: 1,
        kind: RequestKind::Join,
    })
    .unwrap();
    drive(&mut e, 400);
    assert!(matches!(e.status().enforcement, Verdict::Protected(_)));
    e.install.as_mut().unwrap().config.inputs = original;
    e.platform.install.config = e.install.as_ref().unwrap().config.clone();
    e.platform.additional_interfaces.clear();
    e.platform.selective_unqualified = true;
    e.platform.calls.clear();
    e.platform.qualification_trace = Some(vec![]);
    let mut publications = vec![];
    e.apply(Event::Repair(verify::Action::Rerender {
        form: Form::Joined,
    }));
    for _ in 0..600 {
        tick(&mut e);
        publications.push((e.platform.calls.clone(), e.status().enforcement));
        if let Some(removed) = e
            .platform
            .calls
            .iter()
            .position(|c| *c == Call::InterfaceStates)
        {
            let after = &e.platform.calls[removed + 1..];
            if !after.contains(&Call::Flush) {
                assert!(
                    !matches!(e.status().enforcement, Verdict::Protected(_)),
                    "fresh Protected before repair flush"
                );
            }
        }
        if e.is_quiescent() && e.machine.pending().is_none() {
            break;
        }
    }
    assert_eq!(
        e.platform.selective_results,
        vec![Err(crate::decode::pfanchor::SELECTIVE_UNQUALIFIED)]
    );
    // Publication trace associates every observed verdict with effects already completed.
    for (calls, verdict) in publications {
        if matches!(verdict, Verdict::Protected(_)) {
            let selective = calls
                .iter()
                .position(|c| *c == Call::InterfaceStates)
                .unwrap();
            assert!(
                calls[selective + 1..].contains(&Call::Flush),
                "publication before repair flush"
            );
        }
    }
    // Inspect every durable publication request, including create_copy and failures.
    let trace = e.platform.qualification_trace.as_ref().unwrap();
    assert!(trace.iter().any(|s| s.starts_with("snapshot_write:")));
    let selective = trace
        .iter()
        .position(|s| s.starts_with("selective_result:Err("))
        .unwrap();
    let repair_flush = trace
        .iter()
        .enumerate()
        .skip(selective + 1)
        .find(|(_, s)| s.as_str() == "effect_result:Flush:Ok(())")
        .map(|(i, _)| i)
        .unwrap();
    assert!(
        trace[selective + 1..repair_flush]
            .iter()
            .all(|s| !s.ends_with("verification_protected:true"))
    );
    assert!(
        trace[repair_flush + 1..]
            .iter()
            .any(|s| s.ends_with("verification_protected:true"))
    );
    for body in trace
        .iter()
        .filter_map(|s| s.strip_prefix("snapshot_write:"))
    {
        let value: serde_json::Value = serde_json::from_str(body).unwrap();
        let published: Snapshot = serde_json::from_value(value["snapshot"].clone()).unwrap();
        assert!(published.validate().is_ok());
    }
    let selective = e
        .platform
        .calls
        .iter()
        .position(|c| *c == Call::InterfaceStates)
        .unwrap();
    let later = &e.platform.calls[selective + 1..];
    let load = later.iter().position(|c| *c == Call::LoadAnchor).unwrap();
    let flush = later.iter().position(|c| *c == Call::Flush).unwrap();
    assert!(load < flush);
    assert!(matches!(e.status().enforcement, Verdict::Protected(_)));
}

#[test]
fn clear_intent_only_none_clears_even_for_nonconforming_adapter() {
    for text in ["", " \n"] {
        let mut e = joined();
        leave(&mut e, 2);
        before_pending(&mut e, Step::ClearIntent);
        e.platform.anchor_readback_raw = Some(text.into());
        assert_eq!(e.verify_clear_intent(), Err(SysError::Failed("anchor")));
        tick(&mut e);
        assert!(e.machine.durable().leaving);
        assert!(!e.left_verified);
        e.platform.anchor_readback_raw = None;
        elapse(&mut e, 4);
        assert_eq!(e.status().text, "left");
    }
}

#[test]
fn installed_protected_candidate_under_hold_fails_trace_check() {
    // Obtain an actual qualified verdict through the fake Lockdown collector.
    let p = FakePlatform::new().unwrap();
    let mut snapshot = Snapshot::initial(Some(501), p.boot.clone());
    snapshot.machine.join_intended = true;
    snapshot.machine.hold = true;
    let mut p = fixture(&snapshot);
    p.install_error = Some("install record: no writer before 5a3");
    p.qualification_trace = Some(vec![]);
    let mut e = Engine::start(p).unwrap();
    drive(&mut e, 400);
    assert!(e.machine.durable().hold);
    let event = e.collect_verdict(Form::PreTunnel).unwrap();
    let Event::Observed { verdict, .. } = event else {
        panic!("expected observation")
    };
    assert!(matches!(verdict, Verdict::Protected(_)));
    for form in [Form::PreTunnel, Form::Joined] {
        e.platform.qualification_trace = Some(vec![]);
        e.platform.trace_verification(Kind::Lockdown, &verdict);
        assert!(
            crate::decode::qualification_trace::installed_candidates_safe(
                e.platform.qualification_trace.as_ref().unwrap()
            )
        );
        e.platform
            .trace_verification(Kind::Installed(form), &verdict);
        assert!(
            !crate::decode::qualification_trace::installed_candidates_safe(
                e.platform.qualification_trace.as_ref().unwrap()
            )
        );
    }
}
