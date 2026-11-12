//! Golden release archive from fixed input; no compiler or clock affects bytes.
#![allow(clippy::unwrap_used)]
use scupper_core::release::{self, Members};
#[test]
fn deterministic_archive_golden_and_manifest() {
    let members = Members::from([("scupper".into(), b"fixed CLI\n".to_vec())]);
    let archive = release::encode(members.clone()).unwrap();
    assert_eq!(archive, release::encode(members).unwrap());
    assert_eq!(
        release::hash(&archive),
        include_str!("../../tests/golden/release.sha256").trim()
    );
    let decoded = release::decode(&archive, false).unwrap();
    assert_eq!(
        decoded["MANIFEST"],
        format!("{}  scupper\n", release::hash(b"fixed CLI\n")).as_bytes()
    );
    assert!(release::decode(&archive, true).is_err());
    let mut corrupted = archive;
    corrupted[600] ^= 1;
    assert!(release::decode(&corrupted, false).is_err());
}
#[test]
fn release_namespace_refuses_unknown_files_and_manifest_injection() {
    for name in ["../scupper", "/scupper", "extra", "MANIFEST"] {
        assert!(
            release::encode(Members::from([
                ("scupper".into(), vec![1]),
                (name.into(), vec![2])
            ]))
            .is_err()
        );
    }
}
