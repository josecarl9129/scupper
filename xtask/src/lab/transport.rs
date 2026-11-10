//! Stable lab-only `WireGuard` client ports, including the provider-facing client.
use super::{Lab, Result, command::Invocation, fail};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

pub(super) const EXIT_PORT: u16 = 51821;

// Production intentionally leaves exit ports ephemeral. Install this fixture
// only in each lab gateway process's mount namespace, before any peer can send.
const WG: &str = r#"#!/bin/sh
set -eu
# The bind-mounted pathname is /usr/bin/wg; the real executable is passed through
# a root-owned fixture pathname embedded when this script is created.
real=__REAL_WG__
if [ "${1-}" = set ] && [ "${2-}" = ex-ch1 ]; then
    shift 2
    exec "$real" set ex-ch1 listen-port 51821 "$@"
fi
exec "$real" "$@"
"#;

const OVERLAY: &str = r#"
set -eu
# Preserve /run/netns shared peers while isolating the executable overlay.
mount --make-private /
for path in /usr /usr/bin; do
    if mountpoint -q "$path"; then mount --make-private "$path"; fi
done
mount --bind "$1" /usr/bin/wg
shift
exec "$@"
"#;

pub(super) fn overlay(invocation: &Invocation, fixture: &Path) -> Invocation {
    let mut args = vec![
        "--mount".into(),
        "--propagation".into(),
        "unchanged".into(),
        "--".into(),
        "/bin/sh".into(),
        "-c".into(),
        OVERLAY.into(),
        "lab-wireguard".into(),
        fixture.to_string_lossy().into_owned(),
        invocation.program.clone(),
    ];
    args.extend(invocation.args.iter().cloned());
    Invocation {
        program: "unshare".into(),
        args,
    }
}

impl Lab {
    pub(super) fn prepare_transport(&mut self) -> Result<()> {
        let real = self.private.join("wg-real");
        fs::copy("/usr/bin/wg", &real)?;
        let fixture = self.private.join("wg-fixed-port");
        // Quote the literal private pathname for the generated shell script.
        let quoted = format!(
            "'{}'",
            real.to_str().ok_or("wg pathname")?.replace('\'', "'\\''")
        );
        fs::write(&fixture, WG.replace("__REAL_WG__", &quoted))?;
        fs::set_permissions(&fixture, fs::Permissions::from_mode(0o700))?;
        self.runner.wg_fixture = Some(fixture);
        Ok(())
    }

    pub(super) fn assert_transport_ports(&mut self) -> Result<()> {
        // Initial gateway boot runs before the end clients are built.
        let mut clients = vec![("scupper", "ex-ch1", EXIT_PORT)];
        if self.client_ports_ready {
            for ns in ["client", "client2"] {
                clients.push((ns, "wg0", 51820));
            }
        }
        for (ns, iface, expected) in clients {
            let actual = self.cmd(ns, "wg", &["show", iface, "listen-port"])?;
            if actual.trim().parse::<u16>()? != expected {
                return fail(format!(
                    "{ns}/{iface} WireGuard port changed: expected {expected}, got {actual}"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn fixed_port_fixture_preserves_arguments_and_only_pins_exit() {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("wg-fixture-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let real = dir.join("wg-real");
        fs::write(&real, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n").unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let script = WG.replace("__REAL_WG__", &format!("'{}'", real.display()));
        for (args, expected) in [
            (
                vec!["set", "ex-ch1", "peer", "example"],
                "set\nex-ch1\nlisten-port\n51821\npeer\nexample\n",
            ),
            (
                vec!["show", "ex-ch1", "listen-port"],
                "show\nex-ch1\nlisten-port\n",
            ),
            (
                vec!["set", "wg0", "listen-port", "51820"],
                "set\nwg0\nlisten-port\n51820\n",
            ),
        ] {
            let result = std::process::Command::new("/bin/sh")
                .args(["-c", &script, "wg"])
                .args(args)
                .output()
                .unwrap();
            assert!(result.status.success());
            assert_eq!(String::from_utf8(result.stdout).unwrap(), expected);
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
