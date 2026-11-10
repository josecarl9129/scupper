//! Local TLS target with real exit DNS and HTTP parsing, including a healthy
//! response control before substituting the host's uplink address.
use super::{A, DaemonGuard, Duration, Invocation, Path, Result, Signal, fail, fs};
use scupper_core::{
    config::{GatewayId, parse_site, validate},
    render::{VersionStamp, render_netns},
};
use scupper_sys::{
    lock::WriterLock,
    state::{StateFile, StateRead},
    store::{MetaInput, VersionStore},
};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

impl DaemonGuard<'_> {
    #[allow(clippy::too_many_lines)] // TLS controls and exact verdict recovery form one trial.
    pub(super) fn exit_ip_target(&mut self, root: &Path) -> Result<()> {
        self.control_stop(Signal::TERM)?;
        let tls = self.lab.private.join("L15-tls");
        fs::create_dir(&tls)?;
        let ca = tls.join("ca.pem");
        let ca_key = tls.join("ca.key");
        let cert = tls.join("server.pem");
        let key = tls.join("server.key");
        let csr = tls.join("server.csr");
        let der = tls.join("ca.der");
        let ext = tls.join("extensions");
        fs::write(
            &ext,
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:sink.lab.test\n",
        )?;
        let path = |p: &std::path::PathBuf| p.to_str().ok_or("TLS path").map(str::to_owned);
        self.lab.cmd(
            "",
            "openssl",
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=Leak lab CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-keyout",
                &path(&ca_key)?,
                "-out",
                &path(&ca)?,
            ],
        )?;
        self.lab.cmd(
            "",
            "openssl",
            &[
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=sink.lab.test",
                "-keyout",
                &path(&key)?,
                "-out",
                &path(&csr)?,
            ],
        )?;
        self.lab.cmd(
            "",
            "openssl",
            &[
                "x509",
                "-req",
                "-in",
                &path(&csr)?,
                "-CA",
                &path(&ca)?,
                "-CAkey",
                &path(&ca_key)?,
                "-CAcreateserial",
                "-days",
                "1",
                "-extfile",
                &path(&ext)?,
                "-out",
                &path(&cert)?,
            ],
        )?;
        self.lab.cmd(
            "",
            "openssl",
            &[
                "x509",
                "-in",
                &path(&ca)?,
                "-outform",
                "DER",
                "-out",
                &path(&der)?,
            ],
        )?;
        let mut hex = String::new();
        for byte in fs::read(der)? {
            write!(hex, "{byte:02x}")?;
        }
        self.lab.runner.probe_ca = Some(hex);
        fs::write(tls.join("ip.txt"), format!("{}\n", A.provider.peer))?;
        let mut server=self.lab.runner.background(&Invocation::new("internet","/bin/sh",&["-c","cd \"$1\"; exec openssl s_server -quiet -WWW -accept 443 -cert server.pem -key server.key","L15-server",tls.to_str().ok_or("TLS directory")?]),&self.lab.artifacts.join("L15-https.stdout"))?;
        self.lab
            .daemon_wait("L15 HTTPS listener", Duration::from_secs(5), |lab| {
                Ok(lab.cmd("internet", "ss", &["-ltnH"])?.contains(":443"))
            })?;
        self.local_target_config(root)?;
        self.lab.boot_gateway(&[], "L15-target-boot")?;
        self.control_restart(root, "fake-target")?;
        self.lab.daemon_complete_tick(root)?;
        self.expect_check(root, 0, None, "fake-target-healthy")?;
        fs::write(tls.join("ip.txt"), format!("{}\n", A.gwhost.peer))?;
        self.expect_check(
            root,
            2,
            Some(("Unprotected", "ExitIpIsUplinkAddress")),
            "fake-target-uplink",
        )?;
        let report = fs::read_to_string(self.lab.artifacts.join("L15-fake-target-uplink.json"))?;
        if !report.contains("ExitIpIsUplinkAddress") || !report.contains(A.gwhost.peer) {
            return fail("L15 failed at a stage other than exit-IP uplink detection");
        }
        fs::write(tls.join("ip.txt"), format!("{}\n", A.provider.peer))?;
        self.expect_check(root, 0, None, "fake-target-restored")?;
        self.control_stop(Signal::TERM)?;
        self.reset_control_fixture()?;
        self.supervised_fixture(root)?;
        self.lab.boot_gateway(&[], "L15-original-config")?;
        self.lab.runner.probe_ca = None;
        self.control_restart(root, "original-target")?;
        server.alive()?;
        server.stop(Signal::TERM)?;
        Ok(())
    }
    fn local_target_config(&mut self, root: &Path) -> Result<()> {
        let state_root = root.join("var-lib/scupper");
        let config_root = root.join("etc/scupper");
        let writer = WriterLock::acquire(root.join("run/scupper"))?;
        let store = VersionStore::open_with_mirror_root(&state_root, &config_root, Some(&writer))?;
        let head = store.head()?.ok_or("head")?;
        let file = StateFile::open(&state_root, Some(&writer))?;
        let StateRead::Present(mut state) = file.read()? else {
            return fail("state");
        };
        let (text, _) = store.read(state.applied_version.ok_or("applied version")?)?;
        let mut site = parse_site(&text)?;
        site.health.probe_targets = vec!["https://sink.lab.test/ip.txt".into()];
        let text = toml::to_string(&site)?;
        self.lab.site = validate(site).map_err(|e| format!("L15 target config: {e:?}"))?;
        let version = store.commit(
            &writer,
            Some(head),
            &text,
            MetaInput {
                actor: "lab".into(),
                at: 3,
                reason: "local exit-IP target".into(),
            },
        )?;
        state.applied_version = Some(version);
        file.write(&writer, &state)?;
        let rules = render_netns(
            &self.lab.site,
            &GatewayId("gw1".into()),
            &VersionStamp {
                version,
                sha256: Sha256::digest(text.as_bytes()).into(),
            },
        )?;
        store.write_rendered(&writer, version, &rules)?;
        fs::write(&self.lab.rules, rules)?;
        Ok(())
    }
}
