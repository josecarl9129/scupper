//! Generated N-exit models without relaxing M2's singleton release restriction.
#![allow(clippy::unwrap_used)]
use crate::{
    config::{ExitId, GatewayId, parse_site},
    failover::MonoTime,
    planner::*,
    render::{RouteTarget, VersionStamp},
    verdict::v2::{DefaultRouteObs, Selection},
};
use proptest::prelude::*;
use std::{collections::BTreeSet, time::Duration};

proptest! {
    #![proptest_config(ProptestConfig {cases:128,failure_persistence:None,..ProptestConfig::default()})]
    #[test]
    fn one_to_four_exit_prefixes_and_failure_cuts(
        count in 1_usize..5, selected in 0_usize..4, disconnected in any::<bool>(),
        fingerprint in any::<[u8;32]>(), drift_bits in any::<u32>(), latched in any::<bool>(),
        attempts in 0_usize..5, sighted in any::<bool>(), seconds in 0_u64..1201,
    ) {
        let mut cfg=parse_site(include_str!("../../tests/fixtures/site-m2.toml")).unwrap();
        let gateway=GatewayId("gw1".into());
        let prototype=cfg.gateways[&gateway].exits[0].clone();
        cfg.gateways.get_mut(&gateway).unwrap().exits=(0..count).map(|i|{
            let mut exit=prototype.clone();exit.id=ExitId(format!("e{i}"));exit.ifname=format!("ex-e{i}");exit
        }).collect();
        cfg.policy.exits=(0..count).map(|i|ExitId(format!("e{i}"))).collect();
        let site=super::build(cfg).unwrap();
        let target=RouteTarget::Exit(site.gateway(&gateway).unwrap().exits()[selected%count].ifname().clone());
        let selection=if disconnected {Selection::Disconnected} else {Selection::Auto};
        let d=Desired::new(&site,&gateway,&VersionStamp {version:43,sha256:[5;32]},fingerprint,&target,&selection).unwrap();
        let mut m=KernelModel::desired(&d);
        if drift_bits&1!=0 {m.ruleset=Known::Unknown;}
        if drift_bits&2!=0 {m.default_v4=Known::Value(DefaultRouteObs::Dev("eth0".into()));}
        if drift_bits&4!=0 {m.forwarding_v4=Known::Unknown;}
        if drift_bits&8!=0 {m.links_complete=false;}
        for (i,name) in d.exits().values().enumerate() {
            if drift_bits&(16<<i)!=0 {m.links.get_mut(name).unwrap().tc_hooks=Known::Value(vec!["egress".into()]);}
            if drift_bits&(256<<i)!=0 {m.links.remove(name);}
        }
        // A stale old exit must not remain the default when failover requests
        // a configured replacement that has not been recreated yet.
        let target_name=d.exits().values().nth(selected%count).unwrap();
        if count>1 && !m.links.contains_key(target_name) && drift_bits&16384!=0
            && let Some(other)=d.exits().values().find(|name|m.links.contains_key(*name)) {
            m.default_v4=Known::Value(DefaultRouteObs::Dev(other.clone()));
        }
        if drift_bits&4096!=0 {m.extra_rules=Known::Unknown;}
        if drift_bits&8192!=0 {m.extra_routes=Known::Unknown;}
        if drift_bits & (1<<16) != 0 {
            let mut foreign=m.links["wg0"].clone();foreign.kind=Known::Value("veth".into());foreign.ours=Known::Value(false);
            foreign.tc_hooks=Known::Value(vec!["ingress/fresh".into()]);m.links.insert("foreign0".into(),foreign);
        }
        if drift_bits & (1<<17) != 0 {
            let mut leftover=m.links["wg0"].clone();leftover.up=Known::Value(false);leftover.addresses=Known::Value(vec![]);leftover.peers=Known::Value(vec![]);
            m.host_links.insert("wg0".into(),leftover);
        }
        if drift_bits & (1<<18) != 0 {m.links.get_mut("wg0").unwrap().tc_hooks=Known::Unknown;}
        if drift_bits & (1<<19) != 0 {m.ruleset=Known::Value(Ruleset::Absent);}
        if latched {m.latch=Some(Latch {reason:"test".into(),object:"ruleset".into()});}
        let now=MonoTime(Duration::from_secs(seconds));
        let mut budgets=Budgets::default();
        for class in [SafetyClass::Ruleset,SafetyClass::TcHook,SafetyClass::ForeignLink] {
            budgets.attempts.insert(class.key().into(),vec![MonoTime(Duration::ZERO);attempts]);
        }
        let debounce=if sighted {plan(&d,&m,&Budgets::default(),None,&Debounce::default(),now).debounce} else {Debounce::default()};
        let p=plan(&d,&m,&budgets,m.latch.as_ref(),&debounce,now);
        prop_assert_eq!(&p,&plan(&d,&m,&budgets,m.latch.as_ref(),&debounce,now));
        if !disconnected && !m.links.contains_key(target_name) && matches!(m.default_v4,Known::Value(DefaultRouteObs::Dev(_))) {
            prop_assert!(p.steps.iter().any(|step|matches!(step,Step::RouteReplace {family:crate::render::Family::V4,target:RouteTarget::Unreachable})),"unready desired exit must close the default");
        }
        let set_latch=p.steps.iter().any(|s|matches!(s,Step::PersistLatch {..}));
        let mut current=m.clone();let mut reached=safe(&current,&d);
        let mut verified=m.ruleset==Known::Value(Ruleset::Verified(fingerprint));
        let mut targets=BTreeSet::new();
        for (index,step) in p.steps.iter().enumerate() {
            match step {
                Step::ForwardingOn {requires}=>{prop_assert!(index>0 && p.steps[index-1]==Step::FlushConntrack);prop_assert!(!latched && !set_latch && verified);prop_assert_eq!(*requires,fingerprint);},
                Step::VerifyRuleset {fingerprint:f}=>verified=*f==fingerprint,
                Step::RouteReplace {target:RouteTarget::Exit(name),..}=>{prop_assert!(d.exits().values().any(|n|n==name.as_str()));targets.insert(name.as_str());},
                _=>{},
            }
            current=current.apply(step); // Failure at index+1 leaves exactly this model.
            if reached {prop_assert!(safe(&current,&d),"unsafe prefix {:?}",step);}
            reached|=safe(&current,&d);
            prop_assert!(![&current.forwarding_v4,&current.forwarding_v6,&current.client_forwarding_v4].contains(&&Known::Value(1)) || current.ruleset==Known::Value(Ruleset::Verified(fingerprint)) && current.latch.is_none());
        }
        let mut normalized=current.clone();
        normalized.links_complete=true;
        if normalized.ruleset==Known::Unknown {normalized.ruleset=Known::Value(Ruleset::Absent);}
        if normalized.extra_routes==Known::Unknown {normalized.extra_routes=Known::Value(vec![]);}
        if normalized.extra_rules==Known::Unknown {normalized.extra_rules=Known::Value(vec![]);}
        for link in normalized.links.values_mut() {if link.tc_hooks==Known::Unknown {link.tc_hooks=Known::Value(vec![]);}}
        prop_assert!(safe(&current,&d) || current.forwarding_off() && safe(&normalized,&d));
        if p.steps.iter().any(|s|matches!(s,Step::Emit(PlannerEvent::RepairSuppressed {..}))) {prop_assert!(current.forwarding_off());}
        prop_assert!(targets.len()<=count);
    }
}
