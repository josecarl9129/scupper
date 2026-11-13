//! Installation execution, refusals, crash recovery and key confidentiality.
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
#[path = "support/install.rs"]
mod support;
use scupper_core::{
    config::{self, SecretKind, SecretName},
    install as model,
};
use scupper_sys::{
    install::{self, Options},
    system::Program,
};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
};
use support::*;

#[test]
fn fresh_rerun_noop_identity_preserved_and_drift_repaired() {
    let host = Host::new();
    let fake = Fake::default();
    let before = host.snapshot();
    let prepared = host.prepare(&fake).unwrap();
    assert!(prepared.plan.text().contains("generate wg0"));
    assert_eq!(host.snapshot(), before);
    let peer = install::apply(&fake, &host.paths, prepared).unwrap();
    assert!(peer.contains(&public_for(&host.key())));
    assert!(peer.contains("198.51.100.7:51820"));
    let key = host.key();
    let before = host.snapshot();
    assert_eq!(host.prepare(&fake).unwrap().plan.steps, []);
    host.apply(&fake);
    assert_eq!(host.snapshot(), before);
    assert_eq!(host.key(), key);
    for (path, mode) in model::DIRECTORIES {
        assert_eq!(
            fs::metadata(host.paths.at(path)).unwrap().mode() & 0o7777,
            mode
        );
    }
    fs::set_permissions(
        host.paths.at(model::CONFIG_ROOT),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fake.users.borrow_mut().remove(model::USERS[0]);
    fs::write(
        host.paths.at("/etc/systemd/system/scupperd.service"),
        "changed",
    )
    .unwrap();
    let drift = host.prepare(&fake).unwrap();
    assert!(
        drift
            .plan
            .steps
            .iter()
            .any(|s| matches!(s.change, model::Change::User(_)))
    );
    assert!(
        drift
            .plan
            .steps
            .iter()
            .any(|s| matches!(s.change, model::Change::Directory(..)))
    );
    assert!(
        drift
            .plan
            .steps
            .iter()
            .any(|s| matches!(s.change, model::Change::DaemonReload))
    );
    host.apply(&fake);
    assert_eq!(host.prepare(&fake).unwrap().plan.steps, []);
    assert_eq!(host.key(), key);
}
#[test]
fn every_preflight_refusal_is_read_only() {
    for case in [
        "ubuntu",
        "debian",
        "os",
        "kernel",
        "arch",
        "uid",
        "namespace",
        "namespace-mismatched-failed",
        "namespace-mismatched-success",
        "unit",
        "table",
        "link",
        "ex-0",
        "proton0-leftover",
        "v1-before-packages",
        "binary",
        "packages",
    ] {
        let host = Host::new();
        let mut fake = Fake::default();
        match case {
            "ubuntu" => fs::write(
                host.root.join("etc/os-release"),
                "ID=ubuntu\nVERSION_ID=20.04",
            )
            .unwrap(),
            "debian" => {
                fs::write(host.root.join("etc/os-release"), "ID=debian\nVERSION_ID=11").unwrap();
            }
            "os" => fs::write(host.root.join("etc/os-release"), "ID=other\nVERSION_ID=99").unwrap(),
            "kernel" => fake.os_kernel = "5.14.99".into(),
            "arch" => fake.arch = "riscv64".into(),
            "uid" => fake.uid = 1000,
            "namespace" | "namespace-mismatched-failed" | "namespace-mismatched-success" => {
                fs::create_dir_all(host.root.join("run/netns")).unwrap();
                fs::write(host.root.join("run/netns/scupper"), "foreign").unwrap();
                if case != "namespace" {
                    write_boot_report(&host, false, case == "namespace-mismatched-success");
                }
            }
            "packages" => fake.missing_packages = true,
            "ex-0" => fake.host_link = Some("ex-0"),
            "proton0-leftover" => {
                fake.host_link = Some("proton0");
                fake.leftover = true;
            }
            "v1-before-packages" => {
                fake.missing_packages = true;
                fake.marker = Some("unit");
            }
            marker => {
                fake.marker = Some(marker);
                if marker == "binary" {
                    fs::create_dir_all(host.root.join("usr/local/bin")).unwrap();
                    fs::write(host.root.join("usr/local/bin/scupper"), "old").unwrap();
                }
            }
        }
        let before = host.snapshot();
        let error = host.prepare(&fake).unwrap_err();
        let expected = match case {
            "ubuntu" | "debian" | "os" | "kernel" | "arch" | "uid" => model::Refusal::Host,
            "namespace" | "namespace-mismatched-failed" | "namespace-mismatched-success" => {
                model::Refusal::ForeignNamespace
            }
            "packages" => model::Refusal::Packages(
                "apt-get install -y wireguard-tools nftables iproute2 conntrack".into(),
            ),
            _ => model::Refusal::V1,
        };
        assert_eq!(error, expected, "{case}");
        assert_eq!(host.snapshot(), before, "{case}");
        assert!(
            !fake
                .calls
                .borrow()
                .iter()
                .any(|(p, _)| matches!(p, Program::Useradd | Program::Groupadd))
        );
    }
}
#[test]
fn existing_identity_is_never_rotated_and_missing_historical_identity_refuses() {
    let host = Host::new();
    let fake = Fake::default();
    let reference = SecretName::new(SecretKind::Wg, "wg0").unwrap();
    fs::create_dir_all(host.paths.at(model::CONFIG_ROOT)).unwrap();
    scupper_sys::secrets::SecretFile::write_new(
        &host.paths.at(model::CONFIG_ROOT),
        &reference,
        PRIVATE.as_bytes(),
    )
    .unwrap();
    let prepared = host.prepare(&fake).unwrap();
    assert!(
        !prepared
            .plan
            .steps
            .iter()
            .any(|s| matches!(s.change, model::Change::GenerateIdentity))
    );
    install::apply(&fake, &host.paths, prepared).unwrap();
    assert_eq!(host.key(), PRIVATE.as_bytes());
    fs::remove_file(host.paths.at(model::WG0_FILE)).unwrap();
    let before = host.snapshot();
    assert_eq!(
        host.prepare(&fake).unwrap_err(),
        model::Refusal::MissingIdentity
    );
    assert_eq!(host.snapshot(), before);
}
#[test]
fn changed_config_refuses_before_changes_and_firewall_only_warns() {
    let mut host = Host::new();
    let fake = Fake {
        firewall: true,
        ..Fake::default()
    };
    assert_eq!(host.prepare(&fake).unwrap().plan.warnings.len(), 1);
    host.apply(&fake);
    host.options.uplink = Some("eth1".into());
    let before = host.snapshot();
    assert_eq!(
        host.prepare(&fake).unwrap_err(),
        model::Refusal::ExistingConfiguration
    );
    assert_eq!(host.snapshot(), before);
}
#[test]
fn binaries_replaced_with_previous_bytes_kept_and_no_temporary_files() {
    let host = Host::new();
    let fake = Fake::default();
    host.apply(&fake);
    for name in model::BINARIES {
        fs::write(
            host.root.join("source").join(name),
            format!("updated-{name}"),
        )
        .unwrap();
    }
    let mut old_inode = fs::File::open(host.paths.at("/usr/local/bin/scupper")).unwrap();
    host.apply(&fake);
    let mut retained = String::new();
    std::io::Read::read_to_string(&mut old_inode, &mut retained).unwrap();
    assert_eq!(retained, "new-scupper");
    assert_ne!(
        old_inode.metadata().unwrap().ino(),
        fs::metadata(host.paths.at("/usr/local/bin/scupper"))
            .unwrap()
            .ino()
    );
    for name in model::BINARIES {
        assert_eq!(
            fs::read_to_string(host.paths.at(&format!("/usr/local/bin/{name}.prev"))).unwrap(),
            format!("new-{name}")
        );
        assert_eq!(
            fs::read_to_string(host.paths.at(&format!("/usr/local/bin/{name}"))).unwrap(),
            format!("updated-{name}")
        );
    }
    assert!(
        !host
            .snapshot()
            .keys()
            .any(|p| p.file_name().unwrap().to_string_lossy().ends_with(".tmp"))
    );
}
#[test]
fn bundle_verified_before_changes_restores_original_identity_and_is_idempotent() {
    let source = Host::new();
    let source_fake = Fake::default();
    source.apply(&source_fake);
    let guard = scupper_sys::lock::WriterLock::acquire(source.paths.at(model::RUN_ROOT)).unwrap();
    scupper_sys::state::StateFile::open(source.paths.at(model::STATE_ROOT), Some(&guard))
        .unwrap()
        .write(
            &guard,
            &scupper_sys::state::State {
                applied_version: Some(1),
                ..scupper_sys::state::State::default()
            },
        )
        .unwrap();
    drop(guard);
    let store = scupper_sys::store::VersionStore::read_only(
        &source.paths.at(model::STATE_ROOT),
        &source.paths.at(model::CONFIG_ROOT),
    );
    let mut second = config::parse_site(&store.read(1).unwrap().0).unwrap();
    second
        .gateways
        .get_mut(&config::GatewayId("gw1".into()))
        .unwrap()
        .exits[0]
        .ifname = "ex-rebuild".into();
    second
        .gateways
        .get_mut(&config::GatewayId("gw1".into()))
        .unwrap()
        .exits[0]
        .private_key_ref = SecretName::new(SecretKind::Wg, "exit-ch1-v2").unwrap();
    scupper_sys::secrets::SecretFile::write_new(
        &source.paths.at(model::CONFIG_ROOT),
        &SecretName::new(SecretKind::Wg, "exit-ch1-v2").unwrap(),
        PRIVATE.as_bytes(),
    )
    .unwrap();
    let guard = scupper_sys::lock::WriterLock::acquire(source.paths.at(model::RUN_ROOT)).unwrap();
    store
        .commit(
            &guard,
            Some(1),
            &toml::to_string(&second).unwrap(),
            scupper_sys::store::MetaInput {
                actor: "root".into(),
                at: 1001,
                reason: "replacement".into(),
            },
        )
        .unwrap();
    drop(guard);
    let archive = scupper_sys::bundle::export(&source.paths.at(model::STATE_ROOT), None).unwrap();
    let mut host = Host::new();
    let fake = Fake::default();
    let bundle_file = host.root.join("bundle.tar");
    fs::write(&bundle_file, &archive).unwrap();
    host.options = Options {
        binaries: host.options.binaries.clone(),
        bundle: Some(bundle_file.clone()),
        ..Options::default()
    };
    let before = host.snapshot();
    let collision = Fake {
        host_link: Some("ex-rebuild"),
        ..Fake::default()
    };
    assert_eq!(host.prepare(&collision).unwrap_err(), model::Refusal::V1);
    assert_eq!(host.snapshot(), before);
    let removable = Fake {
        host_link: Some("ex-rebuild"),
        leftover: true,
        ..Fake::default()
    };
    assert_eq!(
        host.prepare(&removable).unwrap_err(),
        model::Refusal::MissingIdentity
    );
    assert_eq!(host.snapshot(), before);

    assert_eq!(
        host.prepare(&fake).unwrap_err(),
        model::Refusal::MissingIdentity
    );
    assert_eq!(host.snapshot(), before);
    for (reference, bytes) in [
        ("wg0", source.key()),
        ("exit-ch1-v2", PRIVATE.as_bytes().to_vec()),
    ] {
        fs::create_dir_all(host.paths.at(model::CONFIG_ROOT)).unwrap();
        scupper_sys::secrets::SecretFile::write_new(
            &host.paths.at(model::CONFIG_ROOT),
            &SecretName::new(SecretKind::Wg, reference).unwrap(),
            &bytes,
        )
        .unwrap();
    }
    let before = host.snapshot();
    assert!(
        host.prepare(&fake)
            .unwrap_err()
            .to_string()
            .contains("missing configured secret")
    );
    assert_eq!(host.snapshot(), before);
    scupper_sys::secrets::SecretFile::write_new(
        &host.paths.at(model::CONFIG_ROOT),
        &SecretName::new(SecretKind::Wg, "exit-ch1-v1").unwrap(),
        PRIVATE.as_bytes(),
    )
    .unwrap();
    let good = fs::read(&bundle_file).unwrap();
    fs::write(&bundle_file, b"corrupt archive").unwrap();
    let before = host.snapshot();
    assert!(host.prepare(&fake).is_err());
    assert_eq!(host.snapshot(), before);
    fs::write(&bundle_file, good).unwrap();
    assert!(host.prepare(&fake).unwrap().plan.text().contains("Bundle"));
    host.apply(&fake);
    assert_eq!(host.key(), source.key());
    assert_eq!(host.prepare(&fake).unwrap().plan.steps, []);
}

#[test]
fn failed_initial_import_cleans_new_key_and_matching_crash_leftover_is_reused() {
    use scupper_sys::{
        lock::WriterLock,
        provider,
        secrets::SecretFile,
        store::{MetaInput, VersionStore},
    };
    let host = Host::new();
    fs::create_dir_all(host.paths.at(model::CONFIG_ROOT)).unwrap();
    let mut site = config::parse_site(include_str!(
        "../../scupper-core/tests/fixtures/site-m2.toml"
    ))
    .unwrap();
    site.identities.get_mut("edge").unwrap().public_key =
        config::PublicKey(public_for(PRIVATE.as_bytes()));
    site.alerts.sinks.clear();
    site.heartbeat = None;
    site.devices.clear();
    site.gateways
        .get_mut(&config::GatewayId("gw1".into()))
        .unwrap()
        .exits
        .clear();
    site.policy.exits.clear();
    let guard = WriterLock::acquire(host.paths.at(model::RUN_ROOT)).unwrap();
    let store = VersionStore::open_with_mirror_root(
        host.paths.at(model::STATE_ROOT),
        host.paths.at(model::CONFIG_ROOT),
        Some(&guard),
    )
    .unwrap();
    let import = || {
        provider::import_initial(
            &store,
            &guard,
            &host.paths.at(model::CONFIG_ROOT),
            site.clone(),
            &config::GatewayId("gw1".into()),
            &host.root.join("provider.conf"),
            MetaInput {
                actor: "root".into(),
                at: 1000,
                reason: "install".into(),
            },
        )
    };
    assert!(import().is_err());
    assert!(
        !host
            .paths
            .at("/etc/scupper/secrets/wg/exit-ch-1234-v1")
            .exists()
    );
    SecretFile::write_new(
        &host.paths.at(model::CONFIG_ROOT),
        &SecretName::new(SecretKind::Wg, "wg0").unwrap(),
        PRIVATE.as_bytes(),
    )
    .unwrap();
    let key = SecretName::new(SecretKind::Wg, "exit-ch-1234-v1").unwrap();
    SecretFile::write_new(&host.paths.at(model::CONFIG_ROOT), &key, PUBLIC.as_bytes()).unwrap();
    assert!(import().unwrap_err().contains("differs"));
    assert_eq!(store.head().unwrap(), None);
    SecretFile::remove(&host.paths.at(model::CONFIG_ROOT), &key).unwrap();
    SecretFile::write_new(&host.paths.at(model::CONFIG_ROOT), &key, PRIVATE.as_bytes()).unwrap();
    assert_eq!(import().unwrap(), 1);
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(16))]
    #[test]
    fn install_diagnostics_never_contain_private_keys(value in 10u8..=200) {
        let host = Host::new(); let fake = Fake::default();
        // Repeated-byte fake keys with canonical base64 padding.
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut key = String::new();
        for chunk in [value; 32].chunks(3) {
            let a=chunk[0]; let b=chunk.get(1).copied().unwrap_or(0); let c=chunk.get(2).copied().unwrap_or(0);
            key.push(char::from(alphabet[usize::from(a>>2)])); key.push(char::from(alphabet[usize::from((a&3)<<4|b>>4)]));
            key.push(char::from(alphabet[usize::from((b&15)<<2|c>>6)])); key.push(if chunk.len()>2 {char::from(alphabet[usize::from(c&63)])} else {'='});
        }
        host.provider(&key);
        let prepared = host.prepare(&fake).unwrap();
        let debug = format!("{prepared:?}"); let plan = prepared.plan.text();
        let peer = install::apply(&fake, &host.paths, prepared).unwrap();
        let wg0 = String::from_utf8(host.key()).unwrap();
        let mut failing = Fake { fail_pubkey: true, ..Fake::default() }; failing.users = fake.users.clone(); failing.group = fake.group.clone(); failing.enabled = fake.enabled.clone();
        let error = host.prepare(&failing).unwrap_err();
        let output = format!("{debug}{plan}{peer}{error}{error:?}{:?}", fake.calls.borrow());
        proptest::prop_assert!(!output.contains(&key)); proptest::prop_assert!(!output.contains(&wg0));
    }
}

#[test]
fn crashed_initial_install_reuses_matching_keys_and_repairs_secret_modes() {
    let host = Host::new();
    let fake = Fake::default();
    fs::create_dir_all(host.paths.at(model::CONFIG_ROOT)).unwrap();
    for reference in ["wg0", "exit-ch1-v1"] {
        scupper_sys::secrets::SecretFile::write_new(
            &host.paths.at(model::CONFIG_ROOT),
            &SecretName::new(SecretKind::Wg, reference).unwrap(),
            PRIVATE.as_bytes(),
        )
        .unwrap();
    }
    host.apply(&fake);
    assert_eq!(host.key(), PRIVATE.as_bytes());
    for path in [model::WG0_FILE, "/etc/scupper/secrets/wg/exit-ch1-v1"] {
        fs::set_permissions(host.paths.at(path), fs::Permissions::from_mode(0o644)).unwrap();
    }
    fs::set_permissions(
        host.paths.at("/etc/scupper/secrets/wg"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let plan = host.prepare(&fake).unwrap().plan;
    assert_eq!(
        plan.steps
            .iter()
            .filter(|s| matches!(s.change, model::Change::Permissions(..)))
            .count(),
        2
    );
    host.apply(&fake);
    assert_eq!(host.prepare(&fake).unwrap().plan.steps, []);
    assert_eq!(host.key(), PRIVATE.as_bytes());
}

#[test]
fn different_initial_crash_key_refuses_without_changes() {
    let host = Host::new();
    let fake = Fake::default();
    fs::create_dir_all(host.paths.at(model::CONFIG_ROOT)).unwrap();
    scupper_sys::secrets::SecretFile::write_new(
        &host.paths.at(model::CONFIG_ROOT),
        &SecretName::new(SecretKind::Wg, "exit-ch1-v1").unwrap(),
        PUBLIC.as_bytes(),
    )
    .unwrap();
    let before = host.snapshot();
    assert!(
        host.prepare(&fake)
            .unwrap_err()
            .to_string()
            .contains("differs")
    );
    assert_eq!(host.snapshot(), before);
}

fn write_boot_report(host: &Host, matching: bool, succeeded: bool) {
    use scupper_sys::boot::{BootReport, BootStep, NamespaceIdentity, StepResult};
    let m = fs::metadata(host.paths.at(model::NETNS_FILE)).unwrap();
    let steps = [
        BootStep::Lock,
        BootStep::Modules,
        BootStep::Inputs,
        BootStep::Close,
        BootStep::Ruleset,
        BootStep::Links,
        BootStep::Routes,
        BootStep::Forwarding,
        BootStep::Record,
    ];
    let report = BootReport {
        netns: Some(NamespaceIdentity {
            dev: m.dev(),
            ino: if matching { m.ino() } else { m.ino() + 1 },
        }),
        steps: if succeeded {
            steps
                .into_iter()
                .map(|step| StepResult {
                    step,
                    error: None,
                    adopted: false,
                })
                .collect()
        } else {
            vec![StepResult {
                step: BootStep::Links,
                error: Some("injected boot failure".into()),
                adopted: false,
            }]
        },
        ..BootReport::default()
    };
    fs::create_dir_all(host.paths.at(model::RUN_ROOT)).unwrap();
    fs::write(
        host.paths.at(model::BOOT_FILE),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
}

#[test]
fn failed_boot_namespace_and_removable_host_link_allow_rerun() {
    let host = Host::new();
    let mut fake = Fake::default();
    host.apply(&fake);
    let key = host.key();
    fs::create_dir_all(host.root.join("run/netns")).unwrap();
    fs::write(host.paths.at(model::NETNS_FILE), "owned namespace").unwrap();
    write_boot_report(&host, true, false);
    fake.host_link = Some("wg0");
    fake.leftover = true;
    // Force a real repair so this proves apply completes, beyond a no-op plan.
    fs::write(
        host.paths.at("/etc/systemd/system/scupper-net.service"),
        "damaged",
    )
    .unwrap();
    host.apply(&fake);
    assert_eq!(host.key(), key);
    assert_eq!(host.prepare(&fake).unwrap().plan.steps, []);
}

#[test]
fn endpoint_requires_unambiguous_address_and_peer_uses_explicit_value() {
    let mut host = Host::new();
    let fake = Fake {
        addresses: vec!["198.51.100.9", "192.0.2.7"],
        ..Fake::default()
    };
    let before = host.snapshot();
    assert_eq!(
        host.prepare(&fake).unwrap_err(),
        model::Refusal::EndpointCandidates("192.0.2.7, 198.51.100.9".into())
    );
    assert_eq!(host.snapshot(), before);
    for invalid in ["example.invalid", "2001:db8::1", "192.0.2.1:51820"] {
        host.options.endpoint = Some(invalid.into());
        assert_eq!(
            host.prepare(&fake).unwrap_err(),
            model::Refusal::Input("--endpoint must be a literal IPv4 address")
        );
        assert_eq!(host.snapshot(), before);
    }
    host.options.endpoint = Some("203.0.113.7".into());
    let peer = host.apply(&fake);
    assert!(peer.contains("Endpoint = 203.0.113.7:51820"));
    assert_eq!(host.prepare(&fake).unwrap().plan.steps, []);
    host.options.endpoint = Some("192.0.2.99".into());
    let before = host.snapshot();
    assert_eq!(
        host.prepare(&fake).unwrap_err(),
        model::Refusal::ExistingConfiguration
    );
    assert_eq!(host.snapshot(), before);
    host.options.endpoint = None;
    assert_eq!(host.apply(&fake), peer);
}

#[test]
fn generated_identity_is_canonical_clamped_and_matches_derived_public_key() {
    use sha2::{Digest, Sha256};
    let host = Host::new();
    let fake = Fake::default();
    let peer = host.apply(&fake);
    let key = host.key();
    assert_eq!(key.len(), 44);
    assert_eq!(key[43], b'=');
    let decoded = config::PublicKey(String::from_utf8(key.clone()).unwrap())
        .bytes()
        .unwrap();
    assert_eq!(decoded[0] & 7, 0);
    assert_eq!(decoded[31] & 0xc0, 0x40);
    assert_eq!(base64(&decoded).as_bytes(), key);
    assert_eq!(
        *fake.pubkey_inputs.borrow(),
        vec![<[u8; 32]>::from(Sha256::digest(&key))]
    );
    let store = scupper_sys::store::VersionStore::read_only(
        &host.paths.at(model::STATE_ROOT),
        &host.paths.at(model::CONFIG_ROOT),
    );
    let site = config::parse_site(&store.read(1).unwrap().0).unwrap();
    assert_eq!(site.identities["edge"].public_key.0, public_for(&key));
    assert!(peer.contains(&site.identities["edge"].public_key.0));
}

#[test]
fn runtime_is_not_drift_and_host_binary_directory_is_never_repaired() {
    let host = Host::new();
    let fake = Fake::default();
    fs::set_permissions(
        host.paths.at(model::BIN_ROOT),
        fs::Permissions::from_mode(0o705),
    )
    .unwrap();
    host.apply(&fake);
    assert_eq!(
        fs::metadata(host.paths.at(model::BIN_ROOT)).unwrap().mode() & 0o7777,
        0o705
    );
    fs::remove_dir_all(host.paths.at(model::RUN_ROOT)).unwrap();
    let before = host.snapshot();
    assert_eq!(host.prepare(&fake).unwrap().plan.steps, []);
    assert_eq!(host.snapshot(), before);
    fs::set_permissions(
        host.paths.at(model::BIN_ROOT),
        fs::Permissions::from_mode(0o2775),
    )
    .unwrap();
    let before = host.snapshot();
    assert_eq!(
        host.prepare(&fake).unwrap_err(),
        model::Refusal::Input(
            "/usr/local/bin must exist, be root-owned and not group- or world-writable"
        )
    );
    assert_eq!(host.snapshot(), before);
}

#[test]
fn enable_failure_names_public_command_and_never_child_stderr() {
    let host = Host::new();
    let fake = Fake {
        enable_failure: true,
        ..Fake::default()
    };
    let prepared = host.prepare(&fake).unwrap();
    let error = install::apply(&fake, &host.paths, prepared).unwrap_err();
    assert_eq!(
        error,
        "/usr/bin/systemctl enable --now scupper-net scupperd failed (exit 1)"
    );
}

#[test]
fn scupperd_ping_proves_namespace_ownership_despite_mismatching_boot_report() {
    use std::{
        io::{BufRead, BufReader, Write},
        os::{fd::AsRawFd, unix::net::UnixListener},
    };
    for matching in [true, false] {
        let host = Host::new();
        fs::create_dir_all(host.root.join("run/netns")).unwrap();
        fs::write(host.paths.at(model::NETNS_FILE), "namespace").unwrap();
        write_boot_report(&host, false, false);
        let meta = fs::metadata(host.paths.at(model::NETNS_FILE)).unwrap();
        let directory = fs::File::open(host.paths.at(model::RUN_ROOT)).unwrap();
        let listener = UnixListener::bind(format!(
            "/proc/self/fd/{}/control.sock",
            directory.as_raw_fd()
        ))
        .unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let connection = loop {
                let result = listener.accept();
                if result
                    .as_ref()
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::WouldBlock)
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                break result;
            };
            let (mut stream, _) = connection.unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request: scupper_proto::Request = serde_json::from_str(&line).unwrap();
            assert!(matches!(request.op, scupper_proto::Op::Ping {}));
            let reply = scupper_proto::Response {
                schema: scupper_proto::Schema,
                replayed: false,
                observed_at: None,
                request_id: request.request_id,
                result: Ok(scupper_proto::OpResult::Ping {
                    last_complete_iteration_age: Some(1),
                    current_iteration_age: None,
                    operation: None,
                    netns: scupper_core::verdict::v2::NetnsIdentity {
                        device: meta.dev(),
                        inode: meta.ino() + u64::from(!matching),
                    },
                    version: 1,
                    quarantined: false,
                    selection: scupper_core::verdict::v2::Selection::Auto,
                }),
            };
            writeln!(stream, "{}", serde_json::to_string(&reply).unwrap()).unwrap();
        });
        // snapshot() is deliberately not used with a live Unix socket.
        let result = host.prepare(&Fake::default());
        server.join().unwrap();
        if matching {
            assert!(result.is_ok(), "{result:?}");
        } else {
            assert_eq!(result.unwrap_err(), model::Refusal::ForeignNamespace);
        }
    }
}

#[test]
fn endpoints_reject_local_and_non_unicast_addresses_before_changes() {
    for address in [
        "0.0.0.0",
        "127.0.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "169.254.1.2",
    ] {
        let mut host = Host::new();
        let fake = Fake {
            addresses: vec![address],
            ..Fake::default()
        };
        let before = host.snapshot();
        let expected = model::Refusal::Input(
            "endpoint must be a unicast IPv4 address, excluding loopback and link-local",
        );
        assert_eq!(host.prepare(&fake).unwrap_err(), expected);
        assert_eq!(host.snapshot(), before);
        host.options.endpoint = Some(address.into());
        assert_eq!(host.prepare(&fake).unwrap_err(), expected);
        assert_eq!(host.snapshot(), before);
    }
}

#[test]
fn sole_private_or_shared_address_warns_and_explicit_endpoint_overrides_it() {
    for address in [
        "10.0.0.7",
        "172.16.0.7",
        "192.168.0.7",
        "100.64.0.7",
        "100.127.255.254",
    ] {
        let mut host = Host::new();
        let fake = Fake {
            addresses: vec![address],
            ..Fake::default()
        };
        let prepared = host.prepare(&fake).unwrap();
        assert!(prepared.plan.text().contains("private or shared"));
        assert!(prepared.plan.text().contains("--endpoint IP"));
        let peer = install::apply(&fake, &host.paths, prepared).unwrap();
        assert!(peer.contains(&format!("Endpoint = {address}:51820")));
        // Only automatic selection warns; an explicit choice is intentional.
        host.options.endpoint = Some(address.into());
        assert_eq!(host.prepare(&fake).unwrap().plan.warnings, [] as [&str; 0]);
    }
    let mut host = Host::new();
    let fake = Fake {
        addresses: vec!["100.64.0.7"],
        ..Fake::default()
    };
    host.options.endpoint = Some("192.0.2.7".into());
    assert_eq!(host.prepare(&fake).unwrap().plan.warnings, [] as [&str; 0]);
    assert!(host.apply(&fake).contains("Endpoint = 192.0.2.7:51820"));
}

#[test]
fn writer_lock_creates_private_runtime_directory() {
    let host = Host::new();
    let root = host.paths.at(model::RUN_ROOT);
    assert!(!root.exists());
    let _guard = scupper_sys::lock::WriterLock::acquire(&root).unwrap();
    assert_eq!(fs::metadata(root).unwrap().mode() & 0o7777, 0o700);
}

#[test]
fn active_ufw_decides_despite_opaque_nft_and_names_its_warning() {
    let mut host = Host::new();
    let mut fake = Fake {
        firewall: true,
        ufw_status: Some(include_str!("fixtures/firewall/ufw-status-default.txt")),
        ..Fake::default()
    };
    let plan = host.prepare(&fake).unwrap().plan;
    assert_eq!(
        plan.warnings,
        ["ufw status: ufw is active and does not allow UDP 51820 on eth0"]
    );
    assert_eq!(plan.text().matches("provider/cloud firewalls").count(), 1);
    assert!(
        !fake
            .calls
            .borrow()
            .iter()
            .any(|(program, args)| *program == Program::Nft && args == &["-j", "list", "ruleset"])
    );
    host.options.uplink = Some("up0".into());
    fake.ufw_status = Some(include_str!(
        "fixtures/firewall/ufw-status-uplink-allow.txt"
    ));
    assert_eq!(
        host.prepare(&fake).unwrap().plan.warnings,
        [] as [String; 0]
    );
    host.options.uplink = Some("eth0".into());
    assert_eq!(host.prepare(&fake).unwrap().plan.warnings.len(), 1);
    fake.ufw_status = Some(include_str!("fixtures/firewall/ufw-status-any-allow.txt"));
    assert_eq!(
        host.prepare(&fake).unwrap().plan.warnings,
        [] as [String; 0]
    );
    fake.ufw_status = Some(include_str!("fixtures/firewall/ufw-status-inactive.txt"));
    let plan = host.prepare(&fake).unwrap().plan;
    assert_eq!(plan.warnings.len(), 1);
    assert!(plan.warnings[0].starts_with("nft rules:"));
    fake.ufw_status = None;
    assert_eq!(host.prepare(&fake).unwrap().plan.warnings, plan.warnings);
}

#[test]
fn fresh_install_checks_exit_port_and_rerun_preserves_both_direction_warnings() {
    const BLOCKED: &str =
        "Status: active\nDefault: deny (incoming), reject (outgoing), disabled (routed)\n";
    const EXIT_ALLOW: &str = "Status: active\nDefault: deny (incoming), deny (outgoing), disabled (routed)\n\nTo Action From\n-- ------ ----\n203.0.113.10 51820/udp ALLOW OUT Anywhere\n";
    let host = Host::new();
    let mut fake = Fake {
        ufw_status: Some(BLOCKED),
        ..Fake::default()
    };
    let before = host.snapshot();
    let plan = host.prepare(&fake).unwrap().plan;
    assert_eq!(host.snapshot(), before);
    assert_eq!(plan.warnings.len(), 2);
    assert_eq!(plan.text().matches("provider/cloud firewalls").count(), 1);
    assert!(plan.warnings[1].contains("outgoing UDP to 203.0.113.10:51820 on eth0"));
    host.apply(&fake);
    assert_eq!(host.prepare(&fake).unwrap().plan.warnings, plan.warnings);
    fake.ufw_status = Some(EXIT_ALLOW);
    assert_eq!(host.prepare(&fake).unwrap().plan.warnings.len(), 1);
}

#[test]
fn modules_file_is_managed_and_drift_is_repaired() {
    let host = Host::new();
    let fake = Fake::default();
    assert!(
        host.prepare(&fake)
            .unwrap()
            .plan
            .text()
            .contains(model::MODULES_FILE)
    );
    host.apply(&fake);
    let path = host.paths.at(model::MODULES_FILE);
    assert_eq!(fs::read_to_string(&path).unwrap(), model::modules_config());
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o644);
    assert_eq!(
        fs::metadata(&path).unwrap().uid(),
        rustix::process::geteuid().as_raw()
    );
    // A production hand-file containing exactly these bytes needs no migration.
    fs::write(&path, "nf_conntrack\nwireguard\n").unwrap();
    let before = host.snapshot();
    assert_eq!(host.prepare(&fake).unwrap().plan.steps, []);
    host.apply(&fake);
    assert_eq!(host.snapshot(), before);
    for contents in [Some("wireguard\n"), None] {
        if let Some(contents) = contents {
            fs::write(&path, contents).unwrap();
        } else {
            fs::remove_file(&path).unwrap();
        }
        assert!(
            host.prepare(&fake)
                .unwrap()
                .plan
                .text()
                .contains(model::MODULES_FILE)
        );
        host.apply(&fake);
        assert_eq!(fs::read_to_string(&path).unwrap(), model::modules_config());
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        host.prepare(&fake)
            .unwrap()
            .plan
            .text()
            .contains(model::MODULES_FILE)
    );
    host.apply(&fake);
    assert_eq!(host.prepare(&fake).unwrap().plan.steps, []);
}
