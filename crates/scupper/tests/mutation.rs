#![cfg(target_os = "linux")]
//! Run the shipped rules command in isolated subprocesses for feature fencing.
#![allow(clippy::unwrap_used)]
use std::{fs, path::PathBuf, process::Command};

#[test]
fn rules_runtime_selector_is_fenced() {
    for mutation in ["M-ct", "M-out", "M-probe"] {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("rules-mutation-{}-{mutation}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "rules_child", "--nocapture"])
            .env("SCUPPER_LAB_MUTATION", mutation)
            .env("SCUPPER_RULES_TEST_ROOT", &root)
            .status()
            .unwrap();
        assert!(status.success());
        let output = fs::read_to_string(root.join("output.nft")).unwrap();
        let mut expected =
            include_str!("../../scupper-core/tests/golden/netns-m2-one-exit.nft").to_owned();
        if cfg!(feature = "lab-mutation") {
            let diff = match mutation {
                "M-ct" => include_str!("../../../tests/golden/M-ct.diff"),
                "M-out" => include_str!("../../../tests/golden/M-out.diff"),
                _ => "",
            };
            if !diff.is_empty() {
                let removed: String = diff.lines().filter_map(|s| s.strip_prefix('-')).fold(
                    String::new(),
                    |mut text, line| {
                        text.push_str(line);
                        text.push('\n');
                        text
                    },
                );
                let added: String = diff.lines().filter_map(|s| s.strip_prefix('+')).fold(
                    String::new(),
                    |mut text, line| {
                        text.push_str(line);
                        text.push('\n');
                        text
                    },
                );
                assert_eq!(expected.matches(&removed).count(), 1);
                expected = expected.replacen(&removed, &added, 1);
            }
        }
        // Version/digest are supplied by the immutable store, not this fixture.
        assert_eq!(
            output.lines().skip(2).collect::<Vec<_>>(),
            expected.lines().skip(2).collect::<Vec<_>>()
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn rules_child() {
    use scupper::cli::{self, Dependencies, EffectiveUid, ProcNamespaces, TerminalPrompt};
    use scupper_sys::{
        lock::WriterLock,
        store::{MetaInput, VersionStore},
        system::RealSystem,
    };
    let Some(root) = std::env::var_os("SCUPPER_RULES_TEST_ROOT").map(PathBuf::from) else {
        return;
    };
    let state = root.join("state");
    let config = root.join("config");
    let run = root.join("run");
    fs::create_dir_all(&config).unwrap();
    fs::write(config.join("gateway-id"), "gw1\n").unwrap();
    {
        let writer = WriterLock::acquire(&run).unwrap();
        let store = VersionStore::open_with_mirror_root(&state, &config, Some(&writer)).unwrap();
        store
            .commit(
                &writer,
                None,
                include_str!("../../scupper-core/tests/fixtures/site-m2.toml"),
                MetaInput {
                    actor: "test".into(),
                    at: 1000,
                    reason: "feature fence".into(),
                },
            )
            .unwrap();
    }
    let system = RealSystem::default();
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let code = cli::run_with(
        ["scupper", "rules"],
        &Dependencies {
            state_root: &state,
            config_root: &config,
            writer_root: &run,
            system: &system,
            probe_exec: &system,
            namespaces: &ProcNamespaces,
            privilege: &EffectiveUid,
            prompt: &TerminalPrompt,
        },
        &mut output,
        &mut errors,
    );
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&errors));
    fs::write(root.join("output.nft"), output).unwrap();
}
