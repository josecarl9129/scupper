//! Filesystem discovery never infers absence from a failed systemctl command.
#![allow(clippy::unwrap_used)]
use scupper_sys::{
    system::{ExecError, ExecOutput, Program, System},
    v1_detect::{self, V1Marker},
};
use std::{cell::Cell, collections::BTreeSet, io, path::Path, time::Duration};
struct Fake {
    unreadable: bool,
    units: Vec<String>,
    calls: Cell<usize>,
}
impl System for Fake {
    fn wg_quick_units(&self) -> io::Result<Vec<String>> {
        if self.unreadable {
            Err(io::ErrorKind::PermissionDenied.into())
        } else {
            Ok(self.units.clone())
        }
    }
    fn run(&self, _: Program, _: &[String], _: Duration) -> Result<ExecOutput, ExecError> {
        self.calls.set(self.calls.get() + 1);
        Ok(ExecOutput {
            status: Some(1),
            stdout: String::new(),
            stderr: String::new(),
        })
    }
    fn now_unix_secs(&self) -> u64 {
        0
    }
}
#[test]
fn filesystem_inventory_is_authoritative_even_when_systemctl_would_fail_empty() {
    for unreadable in [false, true] {
        for units in [vec![], vec!["wg-quick@custom.service".into()]] {
            let fake = Fake {
                unreadable,
                units: units.clone(),
                calls: Cell::new(0),
            };
            let result = v1_detect::detect_install_layout(&fake, &[], &BTreeSet::new());
            if unreadable {
                assert!(result.is_err());
            } else {
                assert_eq!(
                    result.unwrap(),
                    units
                        .into_iter()
                        .map(V1Marker::EnabledWgQuick)
                        .collect::<Vec<_>>()
                );
            }
            assert_eq!(fake.calls.get(), 0);
        }
    }
}
#[test]
fn templates_enablement_dangling_symlinks_and_unreadable_inventory() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/tmp/v1-files")
        .join(std::process::id().to_string());
    std::fs::create_dir_all(&root).unwrap();
    assert_eq!(
        v1_detect::wg_quick_units_at(&root).unwrap(),
        Vec::<String>::new()
    );
    for directory in [
        "lib/systemd/system",
        "usr/lib/systemd/system",
        "etc/systemd/system",
    ] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
        std::fs::write(root.join(directory).join("wg-quick@.service"), "[Unit]\n").unwrap();
    }
    assert_eq!(
        v1_detect::wg_quick_units_at(&root).unwrap(),
        Vec::<String>::new()
    );
    let wants = root.join("etc/systemd/system/multi-user.target.wants");
    std::fs::create_dir(&wants).unwrap();
    std::os::unix::fs::symlink("/missing/template", wants.join("wg-quick@custom.service")).unwrap();
    assert_eq!(
        v1_detect::wg_quick_units_at(&root).unwrap(),
        ["wg-quick@custom.service"]
    );
    std::fs::remove_dir_all(&wants).unwrap();
    std::fs::write(&wants, "not an enumerable directory").unwrap();
    assert!(v1_detect::wg_quick_units_at(&root).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn runtime_wants_requires_and_masked_templates_are_readable() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/tmp/v1-runtime")
        .join(std::process::id().to_string());
    std::fs::create_dir_all(root.join("etc/systemd/system")).unwrap();
    std::os::unix::fs::symlink(
        "/dev/null",
        root.join("etc/systemd/system/wg-quick@.service"),
    )
    .unwrap();
    assert_eq!(
        v1_detect::wg_quick_units_at(&root).unwrap(),
        Vec::<String>::new()
    );
    for (dir, name) in [
        ("run/systemd/system/multi-user.target.wants", "runtime"),
        ("run/systemd/system/network.target.requires", "required"),
        ("etc/systemd/system/network.target.requires", "persistent"),
    ] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
        std::os::unix::fs::symlink(
            "/lib/systemd/system/wg-quick@.service",
            root.join(dir).join(format!("wg-quick@{name}.service")),
        )
        .unwrap();
    }
    assert_eq!(
        v1_detect::wg_quick_units_at(&root).unwrap(),
        [
            "wg-quick@persistent.service",
            "wg-quick@required.service",
            "wg-quick@runtime.service"
        ]
    );
    std::fs::remove_dir_all(root).unwrap();
}
