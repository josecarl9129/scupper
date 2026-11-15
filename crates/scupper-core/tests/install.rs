//! Pure install plans and refusal ordering.
#![allow(clippy::unwrap_used)]
use scupper_core::install::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[test]
fn boot_modules_and_modules_load_file_are_exactly_the_safe_list() {
    assert_eq!(BOOT_MODULES, ["nf_conntrack", "wireguard"]);
    assert_eq!(modules_config(), "nf_conntrack\nwireguard\n");
}

fn facts() -> Facts {
    Facts {
        os: "ubuntu".into(),
        os_version: (22, 4),
        kernel: (5, 15),
        arch: "x86_64".into(),
        packages: PACKAGES.into_iter().map(Into::into).collect(),
        ..Facts::default()
    }
}
fn request(bundle: bool) -> Request {
    let modules = modules_config();
    Request {
        gateway_id: "gw1".into(),
        configuration: if bundle {
            Configuration::Bundle {
                sha256: "44".repeat(32),
            }
        } else {
            Configuration::Initial {
                sha256: "33".repeat(32),
            }
        },
        config_inputs: BTreeMap::new(),
        binaries: BTreeMap::from([
            ("scupper".into(), "11".repeat(32)),
            ("scupperd".into(), "22".repeat(32)),
        ]),
        files: [
            (MODULES_FILE, modules.as_str()),
            (GATEWAY_FILE, "gw1\n"),
            (
                "/etc/systemd/system/scupper-net.service",
                scupper_core::render::units::scupper_net(),
            ),
            (
                "/etc/systemd/system/scupperd.service",
                scupper_core::render::units::scupperd(),
            ),
        ]
        .into_iter()
        .map(|(path, text)| {
            (
                path.into(),
                Node {
                    uid: 0,
                    mode: PUBLIC_MODE,
                    sha256: Some(format!("{:x}", Sha256::digest(text.as_bytes()))),
                },
            )
        })
        .collect(),
    }
}
#[test]
fn fresh_and_bundle_goldens() {
    for (bundle, expected) in [
        (
            false,
            include_str!("../../../tests/golden/install/fresh.txt"),
        ),
        (
            true,
            include_str!("../../../tests/golden/install/bundle.txt"),
        ),
    ] {
        let mut host = facts();
        if bundle {
            host.nodes.insert(
                WG0_FILE.into(),
                Node {
                    uid: 0,
                    mode: KEY_MODE,
                    sha256: None,
                },
            );
            host.identity_named = true;
        }
        assert_eq!(plan(&host, &request(bundle)).unwrap().text(), expected);
    }
}
#[test]
fn simulate_result_is_empty_and_drift_has_exact_preconditions() {
    let mut host = facts();
    let mut wanted = request(false);
    let initial = plan(&host, &wanted).unwrap();
    for step in initial.steps {
        match step.change {
            Change::Group => {
                host.groups.insert(ADMIN_GROUP.into());
            }
            Change::User(name) => {
                host.users.insert(name);
            }
            Change::Directory(path, mode) => {
                host.nodes.insert(
                    path,
                    Node {
                        uid: 0,
                        mode,
                        sha256: None,
                    },
                );
            }
            Change::Binary(name, sha256) => {
                host.nodes.insert(
                    format!("{BIN_ROOT}/{name}"),
                    Node {
                        uid: 0,
                        mode: BINARY_MODE,
                        sha256: Some(sha256),
                    },
                );
            }
            Change::GenerateIdentity => {
                host.nodes.insert(
                    WG0_FILE.into(),
                    Node {
                        uid: 0,
                        mode: KEY_MODE,
                        sha256: None,
                    },
                );
            }
            Change::InitializeState => {
                host.nodes.insert(
                    STATE_FILE.into(),
                    Node {
                        uid: 0,
                        mode: KEY_MODE,
                        sha256: None,
                    },
                );
            }
            Change::Configuration(_) => {
                host.head = Some(1);
                host.identity_named = true;
            }
            Change::File(path, node) => {
                host.nodes.insert(path, node);
            }
            Change::Enable => {
                host.enabled.extend(UNITS.into_iter().map(Into::into));
            }
            Change::ProvisionSessions | Change::DaemonReload | Change::Permissions(..) => {}
        }
    }
    wanted.configuration = Configuration::Existing;
    // The production hand fix is already root-owned mode 0644. Keep it as-is.
    host.nodes.insert(
        MODULES_FILE.into(),
        Node {
            uid: 0,
            mode: 0o644,
            sha256: Some(format!(
                "{:x}",
                Sha256::digest(b"nf_conntrack\nwireguard\n")
            )),
        },
    );
    assert_eq!(plan(&host, &wanted).unwrap().steps, []);
    host.nodes.get_mut(CONFIG_ROOT).unwrap().mode = 0o755;
    let drift = plan(&host, &wanted).unwrap();
    assert_eq!(drift.steps.len(), 1);
    assert_eq!(
        drift.steps[0].before,
        Condition::Node(CONFIG_ROOT.into(), host.nodes.get(CONFIG_ROOT).cloned())
    );
    host.users.remove(USERS[0]);
    assert_eq!(plan(&host, &wanted).unwrap().steps.len(), 2);
}
#[test]
fn refusals_are_typed_and_keep_facts_unchanged() {
    for (field, expected) in [
        (0, Refusal::Host),
        (1, Refusal::ForeignNamespace),
        (2, Refusal::V1),
        (3, Refusal::MissingIdentity),
    ] {
        let mut host = facts();
        match field {
            0 => host.uid = 1000,
            1 => host.foreign_namespace = true,
            2 => host.v1_markers.push("host table".into()),
            _ => host.identity_named = true,
        }
        let before = host.clone();
        assert_eq!(plan(&host, &request(false)), Err(expected));
        assert_eq!(host, before);
    }
    let mut host = facts();
    host.packages.clear();
    assert_eq!(
        plan(&host, &request(false)).unwrap_err(),
        Refusal::Packages("apt-get install -y wireguard-tools nftables iproute2 conntrack".into())
    );
}

#[test]
fn changed_flags_on_existing_store_are_a_pure_refusal() {
    let mut host = facts();
    host.head = Some(1);
    host.config_inputs.insert("uplink".into(), "eth0".into());
    let mut wanted = request(false);
    wanted.configuration = Configuration::Existing;
    wanted.config_inputs.insert("uplink".into(), "eth1".into());
    assert_eq!(plan(&host, &wanted), Err(Refusal::ExistingConfiguration));
}
