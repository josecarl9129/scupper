//! Install flag parsing, confirmation, --plan and --check contracts.
#![allow(clippy::unwrap_used)]
#[path = "../../scupper-sys/tests/support/install.rs"]
mod support;
use scupper::cli::{self, Dependencies, NamespaceReader, Privilege, Prompt};
use scupper_core::{config, install as model};
use std::{
    cell::Cell,
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use support::{Fake, Host};
struct Interaction {
    tty: bool,
    answer: bool,
    prompts: Cell<usize>,
}
impl Privilege for Interaction {
    fn is_root(&self) -> bool {
        true
    }
}
impl Prompt for Interaction {
    fn is_terminal(&self) -> bool {
        self.tty
    }
    fn confirm(&self, _: &str, _: Option<&str>) -> io::Result<bool> {
        self.prompts.set(self.prompts.get() + 1);
        Ok(self.answer)
    }
}
impl NamespaceReader for Interaction {
    fn read_namespace(&self, _: &Path) -> io::Result<PathBuf> {
        Err(io::ErrorKind::NotFound.into())
    }
    fn gateway_marker(&self) -> io::Result<bool> {
        Ok(false)
    }
    fn open_gateway(&self) -> Result<Option<scupper_sys::netns::NetnsHandle>, String> {
        Ok(None)
    }
}
fn run(
    host: &Host,
    fake: &Fake,
    interaction: &Interaction,
    flags: &[&str],
) -> (u8, String, String) {
    *fake.run_root.borrow_mut() = Some(host.paths.at(model::RUN_ROOT));
    let mut args = vec![
        "scupper",
        "install",
        "--binaries",
        host.options.binaries.to_str().unwrap(),
    ];
    if !flags.contains(&"--bundle") {
        args.extend_from_slice(&[
            "--gateway-id",
            "gw1",
            "--uplink",
            "eth0",
            "--exit-file",
            host.options.exit_file.as_ref().unwrap().to_str().unwrap(),
            "--exit-id",
            "ch1",
        ]);
    }
    args.extend_from_slice(flags);
    invoke(host, fake, interaction, args)
}
fn invoke(
    host: &Host,
    fake: &Fake,
    interaction: &Interaction,
    args: Vec<&str>,
) -> (u8, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = cli::run_with(
        args,
        &Dependencies {
            state_root: &host.paths.at(model::STATE_ROOT),
            config_root: &host.paths.at(model::CONFIG_ROOT),
            writer_root: &host.paths.at(model::RUN_ROOT),
            system: fake,
            probe_exec: &scupper_sys::system::RealSystem::default(),
            privilege: interaction,
            prompt: interaction,
            namespaces: interaction,
        },
        &mut out,
        &mut err,
    );
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}
#[test]
fn plan_and_check_are_read_only_and_check_detects_each_drift() {
    let host = Host::new();
    let fake = Fake::default();
    let interaction = Interaction {
        tty: false,
        answer: false,
        prompts: Cell::new(0),
    };
    let before = host.snapshot();
    let (code, out, err) = run(&host, &fake, &interaction, &["--plan"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("generate wg0"));
    assert_eq!(host.snapshot(), before);
    assert_eq!(run(&host, &fake, &interaction, &["--check"]).0, 1);
    assert_eq!(host.snapshot(), before);
    assert_eq!(interaction.prompts.get(), 0);
    host.apply(&fake);
    assert_eq!(run(&host, &fake, &interaction, &["--check"]).0, 0);
    fs::remove_dir_all(host.paths.at(model::RUN_ROOT)).unwrap();
    let before = host.snapshot();
    assert_eq!(run(&host, &fake, &interaction, &["--check"]).0, 0);
    assert_eq!(host.snapshot(), before);
    fs::set_permissions(
        host.paths.at(model::CONFIG_ROOT),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert_eq!(run(&host, &fake, &interaction, &["--check"]).0, 1);
    host.apply(&fake);
    fake.users.borrow_mut().remove(model::USERS[0]);
    assert_eq!(run(&host, &fake, &interaction, &["--check"]).0, 1);
    host.apply(&fake);
    fs::write(
        host.paths.at("/etc/systemd/system/scupperd.service"),
        "changed",
    )
    .unwrap();
    let before = host.snapshot();
    assert_eq!(run(&host, &fake, &interaction, &["--check"]).0, 1);
    assert_eq!(host.snapshot(), before);
}
#[test]
fn confirmation_is_after_preflight_and_default_is_no() {
    let host = Host::new();
    let fake = Fake::default();
    let mut interaction = Interaction {
        tty: false,
        answer: false,
        prompts: Cell::new(0),
    };
    let before = host.snapshot();
    let (code, out, err) = run(&host, &fake, &interaction, &[]);
    assert_eq!(code, 1);
    assert!(out.contains("groupadd"));
    assert!(err.contains("--yes"));
    assert_eq!(host.snapshot(), before);
    interaction.tty = true;
    let (code, _, err) = run(&host, &fake, &interaction, &[]);
    assert_eq!(code, 1);
    assert!(err.contains("cancelled"));
    assert_eq!(interaction.prompts.get(), 1);
    assert_eq!(host.snapshot(), before);
    let missing = Fake {
        missing_packages: true,
        ..Fake::default()
    };
    let (code, out, err) = run(&host, &missing, &interaction, &["--yes"]);
    assert_eq!(code, 1);
    assert_eq!(
        out,
        "apt-get install -y wireguard-tools nftables iproute2 conntrack\n"
    );
    assert!(err.contains("apt-get install -y wireguard-tools nftables iproute2 conntrack"));
    assert_eq!(interaction.prompts.get(), 1);
    assert_eq!(host.snapshot(), before);
}
#[test]
fn apply_prints_check_peer_and_deletion_reminder_even_when_check_fails() {
    let host = Host::new();
    let fake = Fake::default();
    let interaction = Interaction {
        tty: false,
        answer: false,
        prompts: Cell::new(0),
    };
    let (code, out, err) = run(&host, &fake, &interaction, &["--yes"]);
    // This fake does not boot a live namespace, so the real check cannot succeed.
    assert_ne!(code, 0, "{out} {err}");
    let key = String::from_utf8(host.key()).unwrap();
    assert!(!format!("{out}{err}").contains(&key));
    assert!(!format!("{out}{err}").contains(support::PRIVATE));
    assert!(out.contains("scupper check:"));
    assert!(out.contains("[Peer]"));
    assert!(out.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
    assert!(out.contains("Delete the downloaded provider file"));
    assert!(out.contains("The Mac device must still be added before a client can join."));
    assert!(!out.contains("scupper device add"));
    let snippet = out
        .split("```toml\n")
        .nth(1)
        .unwrap()
        .split("```\n")
        .next()
        .unwrap();
    assert!(snippet.contains("address4 = \"10.99.0.2/32\""));
    assert!(snippet.contains("gateways = [\"gw1\"]"));
    assert!(!snippet.contains("address6"));
    let store = scupper_sys::store::VersionStore::read_only(
        &host.paths.at(model::STATE_ROOT),
        &host.paths.at(model::CONFIG_ROOT),
    );
    let text = format!(
        "{}\n{}",
        store.read(1).unwrap().0,
        snippet.replace("<MAC_PUBLIC_KEY>", support::PUBLIC)
    );
    config::validate(config::parse_site(&text).unwrap()).unwrap();
    let file = host.root.join("client.toml");
    fs::write(&file, text).unwrap();
    let commands: Vec<_> = out
        .lines()
        .filter(|line| line.starts_with("scupper config "))
        .collect();
    assert_eq!(commands, ["scupper config load FILE"]);
    // Run the printed command through the real clap definition and config loader.
    let mut args: Vec<_> = commands[0]
        .split_whitespace()
        .map(|arg| {
            if arg == "FILE" {
                file.to_str().unwrap()
            } else {
                arg
            }
        })
        .collect();
    args.push("--yes");
    let (code, result, err) = invoke(&host, &fake, &interaction, args);
    assert_eq!(code, 0, "{result} {err}");
    let (_, rerun, _) = run(&host, &fake, &interaction, &["--yes"]);
    assert!(!rerun.contains("device"), "{rerun}");
    assert!(!rerun.contains("scupper config load"));

    assert_restored_device_setup_is_suppressed(&host, &interaction);
}
fn assert_restored_device_setup_is_suppressed(host: &Host, interaction: &Interaction) {
    // The same head with a device must suppress setup after a bundle restore.
    let archive = scupper_sys::bundle::export(&host.paths.at(model::STATE_ROOT), None).unwrap();
    let restored = Host::new();
    let bundle_file = restored.root.join("bundle.tar");
    fs::write(&bundle_file, archive).unwrap();
    fs::create_dir_all(restored.paths.at(model::CONFIG_ROOT)).unwrap();
    for reference in ["wg0", "exit-ch1-v1"] {
        scupper_sys::secrets::SecretFile::write_new(
            &restored.paths.at(model::CONFIG_ROOT),
            &config::SecretName::new(config::SecretKind::Wg, reference).unwrap(),
            &fs::read(host.paths.at(&format!("{}/{reference}", model::WG_ROOT))).unwrap(),
        )
        .unwrap();
    }
    let (_, output, err) = run(
        &restored,
        &Fake::default(),
        interaction,
        &["--bundle", bundle_file.to_str().unwrap(), "--yes"],
    );
    assert!(output.contains("[Peer]"), "{output} {err}");
    assert!(!output.contains("device"), "{output}");
    assert!(!output.contains("scupper config load"));
}
