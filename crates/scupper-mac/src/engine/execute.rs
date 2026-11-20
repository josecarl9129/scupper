//! Core step mapping and observation cadence over Platform only.
use super::{
    Clock, Completion, Engine, Event, Form, Inputs, Mode, Platform, QueueEvent, Reason,
    RefEvidence, Step, SysError, Tunnel, TunnelGeneration, Verdict, verify,
};
use crate::platform::{Collection, ConfigKey, Setting, SpawnAttributes};

pub(super) const CHILD_SPAWN_ATTRIBUTES: SpawnAttributes = SpawnAttributes {
    default_signals: true,
    empty_signal_mask: true,
    cloexec_default: true,
    synchronous: true,
};
use scupper_core::mac::{
    policy,
    verify::{Action, Expected, StateEvidence},
};

impl<P: Platform> Engine<P> {
    pub(super) fn dispatch(&mut self, step: Step) {
        if step == Step::ReleaseReference {
            self.enter_stuck();
            return;
        }
        if self.start_fence != super::StartFence::Closed {
            return;
        }
        if step == Step::LoadPreTunnel
            && !self.reuse_lockdown_load()
            && self
                .emergency_last_load_at
                .is_some_and(|at| self.platform.now() <= at)
        {
            return;
        }
        // Acquire's intent is prepared by the core at the preceding boundary.
        // Re-commit all lagging N facts before exposing this D effect.
        if step == Step::AcquireReference && !self.commit_if_changed() {
            if self.mode == Mode::Normal {
                self.block_storage();
            }
            return;
        }
        let Some(next) = self.next_dispatch.checked_add(1) else {
            self.enter_stuck();
            return;
        };
        let id = self.next_dispatch;
        self.next_dispatch = next;
        self.in_flight = Some((id, step));
        let (event, acquired, not_started) = match self.execute(step) {
            Ok(result) => result,
            Err(SysError::Failed(reason)) => {
                (Event::Failed(Reason::Observation(reason)), None, None)
            }
            Err(_) => (
                Event::Failed(Reason::Unknown {
                    since: self.platform.now(),
                }),
                None,
                None,
            ),
        };
        let completion = Completion {
            dispatch: id,
            event,
            acquired,
            not_started,
        };
        if self
            .enqueue(QueueEvent::Completion(completion.clone()))
            .is_err()
        {
            // Backpressure must not discard the only evidence of a real ioctl.
            self.retained_completion = Some((step, completion));
            self.in_flight = None;
            self.enter_stuck();
        }
    }
    #[allow(clippy::too_many_lines)] // Exhaustive effect table, intentionally auditable together.
    pub(super) fn execute(
        &mut self,
        step: Step,
    ) -> Result<(Event, Option<RefEvidence>, Option<u64>), SysError> {
        let d = self.deadline();
        let completed = || Ok((Event::Completed(step), None, None));
        match step {
            Step::PersistIntent | Step::PersistLeaving | Step::Backoff { .. } => completed(),
            Step::ClearIntent => {
                self.verify_clear_intent()?;
                self.verified_enforcement = false;
                completed()
            }
            Step::AcquireReference => self.acquire_reference(),
            Step::ReconcileReference | Step::ReleaseReference => {
                let event = self.reconcile_references()?;
                Ok((event, None, None))
            }
            Step::ReserveGeneration => {
                let generation = self
                    .machine
                    .durable()
                    .previous_generation
                    .map_or(0, TunnelGeneration::value)
                    .checked_add(1)
                    .ok_or(SysError::Failed("generation exhausted"))?;
                let generation = TunnelGeneration::new(generation)
                    .map_err(|_| SysError::Failed("generation exhausted"))?;
                Ok((Event::GenerationReserved(generation), None, None))
            }
            Step::StartChild => {
                let generation = self
                    .machine
                    .durable()
                    .previous_generation
                    .ok_or(SysError::Failed("missing generation"))?;
                if self.committed.machine.previous_generation != Some(generation.value()) {
                    return Err(SysError::Failed("uncommitted generation"));
                }
                if !self.confirm_sweep() {
                    return Err(SysError::Failed("child sweep unconfirmed"));
                }
                let d = self.deadline();
                let child = match self.platform.spawn(generation, CHILD_SPAWN_ATTRIBUTES, d) {
                    Ok(child) => child,
                    Err(error) => {
                        self.confirm_sweep();
                        return Err(error);
                    }
                };
                let tunnel = Tunnel {
                    name: child.utun.parse().map_err(|_| SysError::Unknown)?,
                    generation,
                };
                self.child = Some(child);
                Ok((Event::ChildStarted(tunnel), None, None))
            }
            Step::StopChild => {
                // Signal the current unreaped child before sweeping historical
                // records and other owned survivors with a fresh start recheck.
                if let Some(child) = self.child.clone() {
                    let d = self.deadline();
                    let _ = self.platform.kill_process(child.pid, child.start_time, d);
                }
                if !self.confirm_sweep() {
                    return Err(SysError::Failed("child sweep unconfirmed"));
                }
                self.child = None;
                self.confirm_cleanup_fence()?;
                completed()
            }
            Step::LoadPreTunnel | Step::LoadJoined | Step::ReplaceAnchor(_) => {
                let text = if step_form(step) == Form::PreTunnel
                    && self.machine.pre_tunnel_policy() == super::Kind::Lockdown
                {
                    policy::render_lockdown()
                } else {
                    let inputs = self.inputs()?;
                    if step_form(step) == Form::Joined {
                        policy::render_joined(&inputs)
                    } else {
                        policy::render_pre_tunnel(&inputs)
                    }
                };
                let reuse = step == Step::LoadPreTunnel && self.reuse_lockdown_load();
                if self.emergency_proof.take().is_some() {
                    // The core may resume its prefix after held debt settles.
                    // Revoke the independent proof before changing its anchor.
                    self.verified_enforcement = false;
                }
                // Ordinary policy supersedes any pre-fence containment load.
                // Its readback and retry state cannot describe this new anchor.
                self.emergency_loaded = false;
                self.emergency_readback = None;
                self.emergency_baseline = None;
                self.emergency_states_clean_at = None;
                self.emergency_last_load_at = None;
                self.emergency_next_reload = self.platform.now();
                self.emergency_reload_delay = 1;
                if !reuse {
                    let loaded = self.platform.load_anchor(&text, d);
                    self.last_ordinary_load_at = Some(self.platform.now());
                    loaded?;
                }
                completed()
            }
            Step::VerifyPreTunnelLoad | Step::VerifyJoinedLoad | Step::VerifyReplacement(_) => {
                let kind = if step_form(step) == Form::PreTunnel {
                    self.machine.pre_tunnel_policy()
                } else {
                    super::Kind::Installed(step_form(step))
                };
                let qualification = self
                    .policy_qualification(kind)
                    .ok_or(SysError::Failed("firewall unqualified"))?;
                let text = self
                    .platform
                    .read_anchor(d)?
                    .ok_or(SysError::Failed("anchor missing on readback"))?;
                let baseline = if step_form(step) == Form::PreTunnel
                    && self.machine.pre_tunnel_policy() == super::Kind::Lockdown
                {
                    verify::capture_lockdown_baseline(&text, &qualification.normalization)
                } else {
                    verify::capture_baseline(
                        &text,
                        &self.inputs()?,
                        step_form(step),
                        &qualification.normalization,
                    )
                }
                .map_err(|_| SysError::Failed("anchor readback mismatch"))?;
                self.baseline = Some(baseline.clone());
                Ok((Event::ReadbackValidated(baseline), None, None))
            }
            Step::FlushStates => {
                self.platform.flush_states(d)?;
                Ok((
                    Event::StatesClean {
                        epoch: self.machine.context().state_epoch,
                        completed_at: self.platform.now(),
                    },
                    None,
                    None,
                ))
            }
            Step::RemoveVanishedInterfaceStates => {
                let interfaces = self.machine.vanished_interfaces().clone();
                self.platform.remove_interface_states(&interfaces, d)?;
                Ok((
                    Event::InterfaceStatesRemoved {
                        interfaces,
                        completed_at: self.platform.now(),
                    },
                    None,
                    None,
                ))
            }
            Step::VerifyPreTunnel | Step::VerifyJoined => {
                let event = self.collect_verdict(step_form(step))?;
                Ok((event, None, None))
            }
            Step::CheckTools => {
                self.platform.check_tools(d)?;
                completed()
            }
            Step::ConfigureUapi
            | Step::ConfigureAddresses
            | Step::ConfigureMtu
            | Step::ConfigureEndpointRoute
            | Step::ConfigureSplitRoutes
            | Step::ConfigureDns => {
                let (key, value) = self.setting(step)?;
                self.platform.configure(key, &value, d)?;
                let d = self.deadline();
                if self.platform.read_config(key, d)? != Some(value) {
                    return Err(SysError::Failed("configuration readback mismatch"));
                }
                completed()
            }
            Step::VerifyIdentity => {
                let child = self
                    .child
                    .clone()
                    .ok_or(SysError::Failed("missing child identity"))?;
                let tunnel = self.platform.identity(&child, d)?;
                Ok((Event::IdentityVerified(tunnel), None, None))
            }
            Step::CleanupRoutes => {
                let endpoint = self
                    .snapshot
                    .endpoint
                    .or_else(|| self.install.as_ref().map(|r| endpoint(&r.config.inputs)));
                self.platform.cleanup_owned_routes(endpoint, d)?;
                self.confirm_cleanup_fence()?;
                completed()
            }
            Step::CleanupDns => {
                self.platform.cleanup_dns(d)?;
                self.confirm_cleanup_fence()?;
                completed()
            }
            Step::CleanupArtifacts => {
                self.platform.cleanup_artifacts(d)?;
                self.confirm_cleanup_fence()?;
                completed()
            }
            Step::RemoveAnchor => {
                self.verified_enforcement = false;
                self.platform.remove_anchor(d)?;
                self.confirm_cleanup_fence()?;
                completed()
            }
        }
    }
    // An own, read-back-verified Lockdown load can satisfy the identical core
    // load in this second. The core still performs its own readback and flush.
    fn reuse_lockdown_load(&mut self) -> bool {
        self.machine.pre_tunnel_policy() == super::Kind::Lockdown
            && self.emergency_loaded
            && self.emergency_readback.as_deref() == Some(policy::render_lockdown().as_str())
            && self
                .emergency_last_load_at
                .is_some_and(|at| self.platform.now() <= at)
    }

    fn confirm_cleanup_fence(&mut self) -> Result<(), SysError> {
        // A late tool can recreate a resource after a successful cleanup. Keep
        // that C1 step in the core's pending_cleanup until reaping makes the
        // absence durable against this incarnation's outstanding effects.
        if self.platform.fence() != super::Fence::Closed {
            return Err(SysError::Unknown);
        }
        Ok(())
    }
    fn setting(&self, step: Step) -> Result<(ConfigKey, Setting), SysError> {
        let inputs = self.inputs()?;
        let config = &self
            .install
            .as_ref()
            .ok_or(SysError::Failed("install record unreadable"))?
            .config;
        Ok(match step {
            Step::ConfigureUapi => (
                ConfigKey::Uapi,
                Setting::Uapi(inputs.tunnel().generation.value()),
            ),
            Step::ConfigureAddresses => (
                ConfigKey::Addresses,
                Setting::Addresses(config.addresses.clone()),
            ),
            Step::ConfigureMtu => (ConfigKey::Mtu, Setting::Mtu(config.mtu)),
            Step::ConfigureEndpointRoute => (
                ConfigKey::EndpointRoute,
                Setting::Route {
                    destination: inputs.endpoint().address().into(),
                    interface: inputs.selected().to_string(),
                    gateway: config.transport.endpoint_route.gateway,
                },
            ),
            Step::ConfigureSplitRoutes => (
                ConfigKey::SplitRoutes,
                Setting::SplitRoutes(vec![
                    std::net::Ipv4Addr::UNSPECIFIED.into(),
                    std::net::Ipv4Addr::new(128, 0, 0, 0).into(),
                ]),
            ),
            Step::ConfigureDns => (ConfigKey::Dns, Setting::Dns(config.dns.clone())),
            _ => return Err(SysError::Failed("configuration plan")),
        })
    }
    pub(super) fn collection(&self) -> Result<Collection, SysError> {
        let context = self.machine.context();
        Ok(Collection {
            context,
            inputs: self.inputs()?,
            child: self.child.clone(),
            states: self.machine.states_clean_at().map_or(
                StateEvidence::Unproven,
                |completed_at| StateEvidence::Clean {
                    epoch: context.state_epoch,
                    completed_at,
                },
            ),
        })
    }
    pub(super) fn policy_qualification(&self, kind: super::Kind) -> Option<verify::Qualification> {
        if kind == super::Kind::Lockdown {
            self.platform.firewall_qualification()
        } else {
            self.install
                .as_ref()
                .map(|install| install.config.qualification.clone())
        }
    }
    pub(super) fn collect_verdict(&mut self, form: Form) -> Result<Event, SysError> {
        if form == Form::PreTunnel && self.machine.pre_tunnel_policy() == super::Kind::Lockdown {
            let context = self.machine.context();
            let states =
                self.machine
                    .states_clean_at()
                    .map_or(StateEvidence::Unproven, |completed_at| {
                        StateEvidence::Clean {
                            epoch: context.state_epoch,
                            completed_at,
                        }
                    });
            let expected = verify::LockdownExpected {
                context,
                baseline: self
                    .baseline
                    .clone()
                    .ok_or(SysError::Failed("missing readback baseline"))?,
                qualification: self
                    .platform
                    .firewall_qualification()
                    .ok_or(SysError::Failed("firewall unqualified"))?,
                max_age: self.timings.max_age,
            };
            let d = self.deadline();
            let observations = self.platform.collect_lockdown(context, states, d)?;
            let verdict =
                verify::verify_lockdown(&observations, &expected, &Clock(self.platform.now()));
            return Ok(Event::Observed {
                context,
                form,
                verdict,
            });
        }
        let collection = self.collection()?;
        let config = self
            .install
            .as_ref()
            .ok_or(SysError::Failed("install record unreadable"))?
            .config
            .clone();
        let expected = Expected {
            context: collection.context,
            inputs: collection.inputs.clone(),
            transport: config.transport,
            form,
            baseline: self
                .baseline
                .clone()
                .ok_or(SysError::Failed("missing readback baseline"))?,
            qualification: config.qualification,
            max_age: self.timings.max_age,
            join_intended: self.machine.durable().join_intended,
        };
        let d = self.deadline();
        let observation = self.platform.collect(&collection, d)?;
        let clock = Clock(self.platform.now());
        let verdict = verify::verify(&observation, &expected, &clock);
        Ok(Event::Observed {
            context: collection.context,
            form,
            verdict,
        })
    }
    #[allow(clippy::too_many_lines)] // Keep cheap, full and maintenance cadence in one auditable table.
    pub(super) fn poll_monitors(&mut self) {
        if !self.runnable()
            || !self.machine.durable().join_intended
            || self.machine.durable().leaving
            || self.machine.durable().leave_requested
        {
            return;
        }
        let now = self.platform.now();
        // In-flight core steps carry their own checked observations. Cheap checks
        // continue during Backoff, and never turn a positive check into a proof.
        if self.in_flight.is_some()
            || self.machine.pending().is_some_and(|s| {
                !(matches!(s, Step::Backoff { .. })
                    || self.mode == Mode::PersistBlocked && super::step_class(s) == super::Class::D)
            })
        {
            return;
        }
        if now >= self.next_cheap {
            self.next_cheap = now.saturating_add(self.timings.cheap_check);
            let d = self.deadline();
            let cheap = self.platform.cheap_check(self.child.as_ref(), d);
            let action = match cheap {
                Ok(o) if !o.pf_enabled => Some(Action::EnableAndRejoin),
                Ok(o) if !o.anchor_present => Some(Action::Rejoin),
                Ok(o) if self.machine.tunnel().is_some() && !o.child_alive => {
                    Some(Action::RecreateChild)
                }
                Ok(o) if self.machine.tunnel().is_some() && !o.route_present => {
                    Some(Action::Rejoin)
                }
                Ok(_) => {
                    // Check reachability and normalized hash using the captured
                    // baseline; a cheap read cannot replace the full proof.
                    if let (Some(baseline), Some(qualification)) = (
                        self.baseline.clone(),
                        self.baseline
                            .as_ref()
                            .and_then(|b| self.policy_qualification(b.kind())),
                    ) {
                        let d = self.deadline();
                        let matched = match self.platform.read_anchor(d) {
                            Ok(Some(text)) => {
                                let captured = if baseline.kind() == super::Kind::Lockdown {
                                    verify::capture_lockdown_baseline(
                                        &text,
                                        &qualification.normalization,
                                    )
                                } else if let Ok(inputs) = self.inputs() {
                                    verify::capture_baseline(
                                        &text,
                                        &inputs,
                                        baseline.form(),
                                        &qualification.normalization,
                                    )
                                } else {
                                    return;
                                };
                                captured.is_ok_and(|b| b.hash() == baseline.hash())
                            }
                            _ => false,
                        };
                        if matched { None } else { Some(Action::Rejoin) }
                    } else {
                        None
                    }
                }

                Err(_) => {
                    self.apply(Event::InvalidateObservations { since: now });
                    return;
                }
            };
            if let Some(action) = action {
                self.apply(Event::Observed {
                    context: self.machine.context(),
                    form: self.machine.installed_form().unwrap_or(Form::PreTunnel),
                    verdict: Verdict::Repair(action),
                });
                return;
            }
        }
        let background = (self.machine.installed_form() == Some(Form::Joined)
            || self.machine.durable().hold && self.machine.blocking_verified_at(&Clock(now)))
            && self
                .machine
                .plan()
                .iter()
                .all(|step| matches!(step, Step::Backoff { .. } | Step::ReconcileReference));
        if self.machine.pending().is_some() && !background {
            if now >= self.next_full {
                self.next_full = now.saturating_add(self.timings.full_walk);
                // Observe during a closing retry without letting a monitor
                // impersonate the pending verification's completion.
                if self.mode == Mode::PersistBlocked && self.waiting.is_some() {
                    match self
                        .collect_verdict(self.machine.installed_form().unwrap_or(Form::PreTunnel))
                    {
                        Ok(
                            event @ Event::Observed {
                                verdict:
                                    Verdict::NotProtected(_)
                                    | Verdict::Repair(_)
                                    | Verdict::Unknown { .. },
                                ..
                            },
                        ) => self.apply(event),
                        Err(_) => self.apply(Event::InvalidateObservations { since: now }),
                        _ => {}
                    }
                } else if let Ok(collection) = self.collection() {
                    let d = self.deadline();
                    let _ = self.platform.collect(&collection, d);
                }
            }
            return;
        }
        if now >= self.next_flush && !self.tool_blocked(Step::FlushStates) {
            self.next_flush = now.saturating_add(self.timings.state_flush);
            match self.execute(Step::FlushStates) {
                Ok((event, _, _)) => self.apply(event),
                Err(_) => self.apply(Event::InvalidateObservations { since: now }),
            }
            self.next_full = now;
        }
        if now >= self.next_full {
            self.next_full = now.saturating_add(self.timings.full_walk);
            let form = self.machine.installed_form().unwrap_or(Form::PreTunnel);
            match self.collect_verdict(form) {
                Ok(event) => self.apply(event),
                Err(_) => self.apply(Event::InvalidateObservations { since: now }),
            }
        }
    }
    pub(super) fn observe_only(&mut self) {
        let d = self.deadline();
        let _ = self.platform.reap(d);
        let d = self.deadline();
        let _ = self.platform.reap_children(d);
        let now = self.platform.now();
        if self.start_fence != super::StartFence::Closed {
            // Before the start fence closes, observe through native process
            // enumeration only. After closure, PersistBlocked may run N-class
            // tools even if the helper commit failed. The next start fence must
            // kill every orphan of a pinned tool before any new effect.
            if now >= self.next_cheap || now >= self.next_full {
                self.next_cheap = now.saturating_add(self.timings.cheap_check);
                self.next_full = now.saturating_add(self.timings.full_walk);
                let d = self.deadline();
                let _ = self.platform.processes(d);
            }
            return;
        }
        if now >= self.next_cheap {
            self.next_cheap = now.saturating_add(self.timings.cheap_check);
            let d = self.deadline();
            let _ = self.platform.cheap_check(self.child.as_ref(), d);
        }
        if now >= self.next_full {
            self.next_full = now.saturating_add(self.timings.full_walk);
            if let Ok(collection) = self.collection() {
                let d = self.deadline();
                let _ = self.platform.collect(&collection, d);
            } else {
                let context = self.machine.context();
                let d = self.deadline();
                if self
                    .platform
                    .collect_lockdown(context, StateEvidence::Unproven, d)
                    .is_err()
                {
                    let d = self.deadline();
                    let _ = self.platform.pf_info(d);
                    let d = self.deadline();
                    let _ = self.platform.processes(d);
                    let d = self.deadline();
                    let _ = self.platform.read_anchor(d);
                }
            }
        }
    }
}
fn step_form(step: Step) -> Form {
    match step {
        Step::LoadJoined | Step::VerifyJoinedLoad | Step::VerifyJoined => Form::Joined,
        Step::ReplaceAnchor(form) | Step::VerifyReplacement(form) => form,
        _ => Form::PreTunnel,
    }
}
pub(super) fn endpoint(inputs: &Inputs) -> std::net::SocketAddrV4 {
    std::net::SocketAddrV4::new(inputs.endpoint().address(), inputs.endpoint().port())
}
