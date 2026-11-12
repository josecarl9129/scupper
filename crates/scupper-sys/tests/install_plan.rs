//! Stable install plans collected from the fake System adapter.
#![allow(clippy::unwrap_used)]
#[path = "support/install.rs"]
mod support;
use scupper_core::{
    config::{SecretKind, SecretName},
    install as model,
};
use scupper_sys::{bundle, install::Options, secrets::SecretFile};
use std::fs;
use support::{Fake, Host, PRIVATE};

#[test]
fn fresh_host_plan() {
    let host = Host::new();
    let fake = Fake::default();
    let before = host.snapshot();
    let text = host.prepare(&fake).unwrap().plan.text();
    assert_eq!(host.snapshot(), before);
    assert_eq!(
        text,
        include_str!("../../../tests/golden/install/host-fresh.txt")
    );
}

#[test]
fn verified_bundle_host_plan() {
    let source = Host::new();
    fs::create_dir_all(source.paths.at(model::CONFIG_ROOT)).unwrap();
    SecretFile::write_new(
        &source.paths.at(model::CONFIG_ROOT),
        &SecretName::new(SecretKind::Wg, "wg0").unwrap(),
        PRIVATE.as_bytes(),
    )
    .unwrap();
    source.apply(&Fake::default());
    let archive = bundle::export(&source.paths.at(model::STATE_ROOT), None).unwrap();
    let mut host = Host::new();
    let file = host.root.join("bundle.tar");
    fs::write(&file, archive).unwrap();
    host.options = Options {
        binaries: host.options.binaries.clone(),
        bundle: Some(file),
        ..Options::default()
    };
    fs::create_dir_all(host.paths.at(model::CONFIG_ROOT)).unwrap();
    for (name, bytes) in [
        ("wg0", source.key()),
        ("exit-ch1-v1", PRIVATE.as_bytes().to_vec()),
    ] {
        SecretFile::write_new(
            &host.paths.at(model::CONFIG_ROOT),
            &SecretName::new(SecretKind::Wg, name).unwrap(),
            &bytes,
        )
        .unwrap();
    }
    let before = host.snapshot();
    let text = host.prepare(&Fake::default()).unwrap().plan.text();
    assert_eq!(host.snapshot(), before);
    assert_eq!(
        text,
        include_str!("../../../tests/golden/install/host-bundle.txt")
    );
}
