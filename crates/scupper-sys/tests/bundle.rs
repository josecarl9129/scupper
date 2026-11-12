//! Deterministic bundle round trips and hostile archive confinement.
#![allow(clippy::unwrap_used)]
use scupper_sys::{
    bundle,
    lock::WriterLock,
    store::{MetaInput, VersionStore},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "bundle-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn fixture(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let writer = WriterLock::acquire(root.join("run")).unwrap();
    let store = VersionStore::open(root.join("source"), Some(&writer)).unwrap();
    let text = include_str!("../../scupper-core/tests/fixtures/site-m2.toml");
    for n in 1..=2 {
        store
            .commit(
                &writer,
                if n == 1 { None } else { Some(1) },
                text,
                MetaInput {
                    actor: "fixture".into(),
                    at: 0,
                    reason: "bundle fixture".into(),
                },
            )
            .unwrap();
    }
    let state = serde_json::to_vec(&scupper_sys::state::State::default()).unwrap();
    fs::write(root.join("source/state.json"), &state).unwrap();
    let mut members = BTreeMap::from([
        ("head".into(), b"2\n".to_vec()),
        ("state.json".into(), state),
    ]);
    for n in 1..=2 {
        for ext in ["toml", "meta.json"] {
            let name = format!("versions/{n:06}.{ext}");
            members.insert(
                name.clone(),
                fs::read(root.join("source/config").join(name)).unwrap(),
            );
        }
    }
    members
}
fn add_manifest(members: &mut BTreeMap<String, Vec<u8>>) {
    members.remove("MANIFEST");
    let mut manifest = String::new();
    for (name, bytes) in members.iter() {
        manifest.push_str(&digest(bytes));
        manifest.push_str("  ");
        manifest.push_str(name);
        manifest.push('\n');
    }
    members.insert("MANIFEST".into(), manifest.into_bytes());
}
fn checksum(header: &mut [u8]) {
    header[148..156].fill(b' ');
    let sum: usize = header.iter().map(|b| usize::from(*b)).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}
fn tar(members: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (name, content) in members {
        let mut header = [0_u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000640\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", content.len()).as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[156] = b'0';
        header[257..265].copy_from_slice(b"ustar\x0000");
        checksum(&mut header);
        bytes.extend(header);
        bytes.extend(content);
        bytes.resize(bytes.len().next_multiple_of(512), 0);
    }
    bytes.resize(bytes.len() + 1024, 0);
    bytes
}
fn snapshot(path: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(base: &Path, path: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                out.push((
                    path.strip_prefix(base).unwrap().into(),
                    fs::read(path).unwrap(),
                ));
            }
        }
    }
    let mut out = vec![];
    walk(path, path, &mut out);
    out.sort();
    out
}
fn refused(root: &Path, bytes: &[u8], reason: &str) {
    let target = root.join("target");
    if !target.exists() {
        fs::create_dir(&target).unwrap();
    }
    let before = snapshot(root);
    assert_eq!(bundle::verify(bytes).unwrap_err().to_string(), reason);
    assert_eq!(
        bundle::restore(bytes, &target).unwrap_err().to_string(),
        reason
    );
    assert_eq!(snapshot(root), before);
    assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    assert!(!root.join("escaped").exists());
}
#[test]
fn round_trip_deterministic_golden_and_allow_list() {
    let t = Temp::new();
    let mut members = fixture(&t.0);
    add_manifest(&mut members);
    fs::create_dir(t.0.join("source/secrets")).unwrap();
    fs::write(
        t.0.join("source/secrets/never-bundle"),
        "fake secret marker",
    )
    .unwrap();
    fs::write(t.0.join("source/events.log"), "never-bundle").unwrap();
    let bytes = bundle::export(&t.0.join("source"), None).unwrap();
    assert_eq!(bytes, tar(&members));
    assert_eq!(bytes, bundle::export(&t.0.join("source"), None).unwrap());
    assert_eq!(
        digest(&bytes),
        include_str!("../../../tests/golden/config-bundle.sha256").trim()
    );
    bundle::verify(&bytes).unwrap();
    fs::create_dir(t.0.join("target")).unwrap();
    bundle::restore(&bytes, &t.0.join("target")).unwrap();
    bundle::restore(&bytes, &t.0.join("absent-target")).unwrap();
    assert_eq!(
        bytes,
        bundle::export(&t.0.join("absent-target"), None).unwrap()
    );
    assert_eq!(bytes, bundle::export(&t.0.join("target"), None).unwrap());
    for (name, content) in members {
        if name != "MANIFEST" {
            let path = if name == "state.json" {
                t.0.join("target").join(name)
            } else {
                t.0.join("target/config").join(name)
            };
            assert_eq!(fs::read(path).unwrap(), content);
        }
    }
    for name in [
        "secrets/key",
        "events.log",
        "/head",
        "../head",
        "versions/000001.toml/../head",
        "versions/000000.toml",
        "versions/1.toml",
    ] {
        assert!(!bundle::allowed_member(name));
        assert_eq!(
            bundle::export(&t.0.join("source"), Some(&[name.into()]))
                .unwrap_err()
                .to_string(),
            "member outside bundle allow-list"
        );
    }
    let before = snapshot(&t.0);
    assert_eq!(
        bundle::restore(&bytes, &t.0.join("target"))
            .unwrap_err()
            .to_string(),
        "restore target is not empty"
    );
    assert_eq!(snapshot(&t.0), before);
}
#[test]
fn hostile_members_write_nothing() {
    let t = Temp::new();
    let mut members = fixture(&t.0);
    add_manifest(&mut members);
    let good = tar(&members);
    for name in [
        "../escaped",
        "/escaped",
        "versions/../escaped",
        "secrets/key",
        "events.log",
        "versions/000000.toml",
        "versions/000001.extra",
    ] {
        let mut bad = members.clone();
        bad.insert(name.into(), b"no".to_vec());
        add_manifest(&mut bad);
        refused(&t.0, &tar(&bad), "unknown or duplicate member");
    }
    for kind in *b"123456xg" {
        let mut bad = good.clone();
        bad[156] = kind;
        checksum(&mut bad[..512]);
        refused(&t.0, &bad, "only regular unprefixed files allowed");
    }
    let mut bad = good.clone();
    bad[345..350].copy_from_slice(b"../..");
    checksum(&mut bad[..512]);
    refused(&t.0, &bad, "only regular unprefixed files allowed");
    let mut bad = good.clone();
    bad[157..161].copy_from_slice(b"head");
    checksum(&mut bad[..512]);
    refused(&t.0, &bad, "only regular unprefixed files allowed");
    let mut bad = good.clone();
    bad[0] ^= 1;
    refused(&t.0, &bad, "invalid ustar header");
    refused(&t.0, &good[..good.len() - 1024], "missing tar trailer");
    let mut bad = good.clone();
    bad[512] ^= 1;
    refused(&t.0, &bad, "manifest hash mismatch");
    let mut bad = members.clone();
    bad.insert(
        "versions/000001.toml".into(),
        vec![b'a'; bundle::MAX_MEMBER + 1],
    );
    add_manifest(&mut bad);
    refused(&t.0, &tar(&bad), "bundle size limit");
    let mut bad = members.clone();
    for n in 3..=18 {
        bad.insert(
            format!("versions/{n:06}.toml"),
            vec![b'a'; bundle::MAX_MEMBER],
        );
    }
    add_manifest(&mut bad);
    refused(&t.0, &tar(&bad), "bundle size limit");
}
#[test]
fn hashes_schema_parents_head_and_manifest_are_checked() {
    let t = Temp::new();
    let original = fixture(&t.0);
    for (name, content, reason) in [
        (
            "head",
            b"1\n".to_vec(),
            "head must name last version, complete history required",
        ),
        (
            "head",
            b"3\n".to_vec(),
            "head must name last version, complete history required",
        ),
        (
            "versions/000001.toml",
            b"schema = 999\n".to_vec(),
            "invalid version schema",
        ),
        ("state.json", b"{}".to_vec(), "invalid state"),
        (
            "state.json",
            br#"{"schema":2,"applied_version":null,"selection":"Auto","quarantine":null}"#.to_vec(),
            "invalid state schema or applied version",
        ),
    ] {
        let mut bad = original.clone();
        bad.insert(name.into(), content);
        add_manifest(&mut bad);
        refused(&t.0, &tar(&bad), reason);
    }
    for (name, field, value) in [
        (
            "versions/000002.meta.json",
            "parent",
            serde_json::json!(null),
        ),
        ("versions/000001.meta.json", "parent", serde_json::json!(1)),
        (
            "versions/000002.meta.json",
            "sha256",
            serde_json::json!("0".repeat(64)),
        ),
    ] {
        let mut bad = original.clone();
        let mut meta: serde_json::Value = serde_json::from_slice(&bad[name]).unwrap();
        meta[field] = value;
        bad.insert(name.into(), serde_json::to_vec(&meta).unwrap());
        add_manifest(&mut bad);
        refused(
            &t.0,
            &tar(&bad),
            "nonlinear history or invalid version hash",
        );
    }
    let mut bad = original.clone();
    add_manifest(&mut bad);
    bad.get_mut("versions/000001.toml").unwrap()[0] ^= 1;
    refused(&t.0, &tar(&bad), "manifest hash mismatch");
    let mut bad = original.clone();
    add_manifest(&mut bad);
    bad.insert("MANIFEST".into(), b"".to_vec());
    refused(&t.0, &tar(&bad), "manifest member mismatch");
    let mut bad = original;
    add_manifest(&mut bad);
    bad.remove("versions/000001.toml");
    add_manifest(&mut bad);
    refused(
        &t.0,
        &tar(&bad),
        "head must name last version, complete history required",
    );
}
#[test]
fn source_and_target_symlinks_are_refused() {
    use std::os::unix::fs::symlink;
    assert!(bundle::read_bundle(Path::new("Cargo.toml")).is_ok());
    let t = Temp::new();
    fixture(&t.0);
    let bytes = bundle::export(&t.0.join("source"), None).unwrap();
    fs::create_dir(t.0.join("empty")).unwrap();
    symlink(t.0.join("empty"), t.0.join("link")).unwrap();
    assert_eq!(
        bundle::restore(&bytes, &t.0.join("link"))
            .unwrap_err()
            .to_string(),
        "restore target must be an absent or empty directory"
    );
    assert_eq!(fs::read_dir(t.0.join("empty")).unwrap().count(), 0);
    fs::rename(t.0.join("source/config/versions"), t.0.join("versions")).unwrap();
    symlink(t.0.join("versions"), t.0.join("source/config/versions")).unwrap();
    assert_eq!(
        bundle::export(&t.0.join("source"), None)
            .unwrap_err()
            .to_string(),
        "symlink or non-directory in path"
    );
}
