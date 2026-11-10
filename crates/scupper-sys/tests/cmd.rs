//! Exact argument contracts for every typed command and optional operand branch.

use scupper_core::{
    parse::PeerKey,
    render::{Family, RouteTarget, Scope, SysctlFamily, SysctlKey},
    rules::IfName,
};
use scupper_sys::{
    cmd::*,
    system::{ExecTarget, Program},
};
use std::{error::Error, time::Duration};

fn key() -> Result<PeerKey, scupper_core::parse::ParseError> {
    PeerKey::new(&format!("{}=", "A".repeat(43)))
}
fn name() -> Result<IfName, scupper_core::rules::ConfigError> {
    IfName::new("wg0")
}

#[test]
fn every_command_argv() -> Result<(), Box<dyn Error>> {
    let cases = vec![
        (
            KernelCmd::Ip(IpCmd::LinkShowJson),
            Program::Ip,
            vec!["-d", "-j", "link", "show"],
        ),
        (
            KernelCmd::Ip(IpCmd::AddrShowJson),
            Program::Ip,
            vec!["-j", "addr", "show"],
        ),
        (
            KernelCmd::Ip(IpCmd::LinkSetDown(name()?)),
            Program::Ip,
            vec!["link", "set", "dev", "wg0", "down"],
        ),
        (
            KernelCmd::Ip(IpCmd::LinkDelete(name()?)),
            Program::Ip,
            vec!["link", "delete", "dev", "wg0"],
        ),
        (
            KernelCmd::Ip(IpCmd::RouteGet {
                dst: "1.1.1.1".parse()?,
                from: Some("10.99.0.2".parse()?),
                iif: Some(name()?),
            }),
            Program::Ip,
            vec!["route", "get", "1.1.1.1", "from", "10.99.0.2", "iif", "wg0"],
        ),
        (
            KernelCmd::Ip(IpCmd::RouteGet {
                dst: "2001:db8::1".parse()?,
                from: None,
                iif: None,
            }),
            Program::Ip,
            vec!["-6", "route", "get", "2001:db8::1"],
        ),
        (
            KernelCmd::Ip(IpCmd::RouteReplace(Family::V4, RouteTarget::Unreachable)),
            Program::Ip,
            vec!["route", "replace", "unreachable", "default"],
        ),
        (
            KernelCmd::Ip(IpCmd::RouteReplace(Family::V6, RouteTarget::Unreachable)),
            Program::Ip,
            vec!["-6", "route", "replace", "unreachable", "default"],
        ),
        (
            KernelCmd::Nft(NftCmd::ListRulesetJson),
            Program::Nft,
            vec!["-j", "list", "ruleset"],
        ),
        (
            KernelCmd::Nft(NftCmd::LoadStdin),
            Program::Nft,
            vec!["-f", "-"],
        ),
        (
            KernelCmd::Nft(NftCmd::CheckStdin),
            Program::Nft,
            vec!["-c", "-f", "-"],
        ),
        (
            KernelCmd::Tc(TcCmd::QdiscShowJson { dev: name()? }),
            Program::Tc,
            vec!["-j", "qdisc", "show", "dev", "wg0"],
        ),
        (
            KernelCmd::Conntrack(ConntrackCmd::Flush),
            Program::Conntrack,
            vec!["-F"],
        ),
    ];
    for (cmd, program, argv) in cases {
        assert_eq!(
            cmd.render(),
            (program, argv.into_iter().map(str::to_owned).collect()),
            "{cmd:?}"
        );
    }
    Ok(())
}

#[test]
fn family_and_tc_inventory_argv() -> Result<(), Box<dyn Error>> {
    let mut cases = Vec::new();
    for (family, flag) in [(Family::V4, "-4"), (Family::V6, "-6")] {
        cases.push((
            KernelCmd::Ip(IpCmd::RuleShowJson { family }),
            Program::Ip,
            vec!["-j", flag, "rule", "show"],
        ));
        for (table, text) in [(RouteTable::Main, "main"), (RouteTable::All, "all")] {
            cases.push((
                KernelCmd::Ip(IpCmd::RouteShowJson { family, table }),
                Program::Ip,
                vec!["-j", flag, "route", "show", "table", text],
            ));
        }
    }
    for (parent, text) in [
        (TcParent::Ingress, "ingress"),
        (TcParent::Egress, "egress"),
        (TcParent::Root, "root"),
    ] {
        cases.push((
            KernelCmd::Tc(TcCmd::FilterShowJson {
                dev: name()?,
                parent,
            }),
            Program::Tc,
            vec!["-j", "filter", "show", "dev", "wg0", text],
        ));
    }
    for (cmd, program, argv) in cases {
        assert_eq!(
            cmd.render(),
            (program, argv.into_iter().map(str::to_owned).collect()),
            "{cmd:?}"
        );
    }
    Ok(())
}

#[test]
fn sysctl_and_exit_route_argv() -> Result<(), Box<dyn Error>> {
    let sysctl = SysctlKey {
        family: SysctlFamily::Ipv4,
        scope: Scope::Link(IfName::new("wg.0")?),
        name: "rp_filter",
    };
    assert_eq!(
        KernelCmd::Sysctl(SysctlCmd::Read(sysctl.clone())).render(),
        (
            Program::Sysctl,
            vec!["-n".into(), "net.ipv4.conf.wg/0.rp_filter".into()]
        )
    );
    assert_eq!(
        KernelCmd::Sysctl(SysctlCmd::Write(sysctl, 0)).render(),
        (
            Program::Sysctl,
            vec!["-w".into(), "net.ipv4.conf.wg/0.rp_filter=0".into()]
        )
    );
    let config = scupper_core::config::parse_site(include_str!(
        "../../scupper-core/tests/fixtures/site-m2.toml"
    ))?;
    let site = scupper_core::config::validate(config).map_err(|_| "invalid site fixture")?;
    let gateway = site.gateways().values().next().ok_or("missing gateway")?;
    let exit = gateway.exits().first().ok_or("missing exit")?;
    for (family, prefix) in [(Family::V4, vec![]), (Family::V6, vec!["-6"])] {
        let mut expected = prefix;
        expected.extend(["route", "replace", "default", "dev", exit.ifname().as_str()]);
        assert_eq!(
            KernelCmd::Ip(IpCmd::RouteReplace(
                family,
                RouteTarget::Exit(exit.ifname().clone())
            ))
            .render(),
            (
                Program::Ip,
                expected.into_iter().map(str::to_owned).collect()
            )
        );
    }
    Ok(())
}

type WgCase = (WgCmd, Vec<String>);

fn wg_cases() -> Result<Vec<WgCase>, Box<dyn Error>> {
    let mut cases = Vec::new();
    for field in [
        WgField::PublicKey,
        WgField::ListenPort,
        WgField::Peers,
        WgField::AllowedIps,
        WgField::Endpoints,
        WgField::PersistentKeepalive,
        WgField::LatestHandshakes,
        WgField::Transfer,
    ] {
        cases.push((
            WgCmd::Show {
                ifname: name()?,
                field,
            },
            vec!["show".into(), "wg0".into(), field.as_str().into()],
        ));
    }
    for (cmd, argv) in [
        (
            WgCmd::SetPrivateKeyFromStdin { ifname: name()? },
            vec!["set", "wg0", "private-key", "/dev/stdin"],
        ),
        (
            WgCmd::SetListenPort {
                ifname: name()?,
                port: 51820,
            },
            vec!["set", "wg0", "listen-port", "51820"],
        ),
        (WgCmd::Pubkey, vec!["pubkey"]),
    ] {
        cases.push((cmd, argv.into_iter().map(str::to_owned).collect()));
    }
    cases.push((
        WgCmd::RemovePeer {
            ifname: name()?,
            public_key: key()?,
        },
        vec![
            "set".into(),
            "wg0".into(),
            "peer".into(),
            key()?.to_string(),
            "remove".into(),
        ],
    ));
    cases.push((
        WgCmd::SetPeer {
            ifname: name()?,
            public_key: key()?,
            allowed_ips: vec!["10.99.0.2/32".parse()?, "fd00:99::2/128".parse()?],
            endpoint: Some("[2001:db8::1]:51820".parse()?),
            keepalive: Some(25),
        },
        vec![
            "set".into(),
            "wg0".into(),
            "peer".into(),
            key()?.to_string(),
            "preshared-key".into(),
            "/dev/null".into(),
            "allowed-ips".into(),
            "10.99.0.2/32,fd00:99::2/128".into(),
            "endpoint".into(),
            "[2001:db8::1]:51820".into(),
            "persistent-keepalive".into(),
            "25".into(),
        ],
    ));
    cases.push((
        WgCmd::SetPeer {
            ifname: name()?,
            public_key: key()?,
            allowed_ips: vec![],
            endpoint: None,
            keepalive: None,
        },
        vec![
            "set".into(),
            "wg0".into(),
            "peer".into(),
            key()?.to_string(),
            "preshared-key".into(),
            "/dev/null".into(),
            "allowed-ips".into(),
            String::new(),
        ],
    ));
    Ok(cases)
}

#[test]
fn every_wg_variant_argv_and_forbidden_tokens() -> Result<(), Box<dyn Error>> {
    for (cmd, expected) in wg_cases()? {
        let (program, args) = KernelCmd::Wg(cmd.clone()).render();
        assert_eq!(program, Program::Wg);
        assert_eq!(args, expected, "{cmd:?}");
        for token in ["showconf", "dump", "preshared-keys"] {
            assert!(!args.iter().any(|arg| arg == token), "{cmd:?}");
        }
        if matches!(cmd, WgCmd::SetPeer { .. }) {
            assert!(
                args.windows(2)
                    .any(|pair| pair == ["preshared-key", "/dev/null"])
            );
        } else {
            assert!(!args.iter().any(|arg| arg == "preshared-key"));
        }
        if matches!(cmd, WgCmd::SetPrivateKeyFromStdin { .. }) {
            assert_eq!(args, ["set", "wg0", "private-key", "/dev/stdin"]);
        } else {
            assert!(!args.iter().any(|arg| arg == "private-key"));
        }
        if matches!(cmd, WgCmd::Show { .. }) {
            assert!(!args.iter().any(|arg| arg.starts_with('/')));
        }
    }
    Ok(())
}

#[cfg(feature = "testing")]
#[test]
fn dispatch_preserves_namespace_stdin_and_deadline() -> Result<(), Box<dyn Error>> {
    use scupper_sys::system::{ExecOutput, testing::FakeSystem};
    let handle = scupper_sys::netns::testing::handle()?;
    let target = ExecTarget::Netns(&handle);
    let sys = FakeSystem::new(0);
    let timeout = Duration::from_millis(27);
    for cmd in [
        KernelCmd::Sysctl(SysctlCmd::Read(SysctlKey {
            family: SysctlFamily::Ipv4,
            scope: Scope::Global,
            name: "ip_forward",
        })),
        KernelCmd::Nft(NftCmd::LoadStdin),
        KernelCmd::Wg(WgCmd::SetPrivateKeyFromStdin { ifname: name()? }),
    ] {
        let (program, args) = cmd.render();
        let output = ExecOutput {
            status: Some(7),
            stdout: String::new(),
            stderr: String::new(),
        };
        sys.push_in(target, program, &args, Ok(output.clone()));
        let result = if cmd.needs_stdin() {
            assert!(run_cmd(&sys, target, &cmd, timeout).is_err());
            run_netns_cmd_with_stdin(&sys, &handle, &cmd, b"input", timeout)
        } else {
            assert!(run_netns_cmd_with_stdin(&sys, &handle, &cmd, b"input", timeout).is_err());
            run_netns_cmd(&sys, &handle, &cmd, timeout)
        };
        assert_eq!(result?, output);
        let calls = sys.calls();
        let call = calls.last().ok_or("missing call")?;
        assert_eq!(call.target_identity, Some(handle.identity()));
        assert_eq!(call.timeout, timeout);
        assert_eq!(call.stdin_len, cmd.needs_stdin().then_some(5));
    }
    Ok(())
}

#[cfg(feature = "testing")]
#[test]
fn every_mutation_requires_namespace_only_dispatch() -> Result<(), Box<dyn Error>> {
    use scupper_sys::system::{ExecOutput, testing::FakeSystem};
    let handle = scupper_sys::netns::testing::handle()?;
    let sys = FakeSystem::new(0);
    let timeout = Duration::from_millis(20);
    let mut mutations = vec![
        KernelCmd::Ip(IpCmd::LinkDelete(name()?)),
        KernelCmd::Ip(IpCmd::LinkSetDown(name()?)),
        KernelCmd::Ip(IpCmd::RouteReplace(Family::V4, RouteTarget::Unreachable)),
        KernelCmd::Nft(NftCmd::LoadStdin),
        KernelCmd::Sysctl(SysctlCmd::Write(
            SysctlKey {
                family: SysctlFamily::Ipv4,
                scope: Scope::Global,
                name: "ip_forward",
            },
            1,
        )),
        KernelCmd::Conntrack(ConntrackCmd::Flush),
    ];
    mutations.extend(wg_cases()?.into_iter().filter_map(|(cmd, _)| {
        let cmd = KernelCmd::Wg(cmd);
        cmd.mutates().then_some(cmd)
    }));
    for cmd in mutations {
        assert!(cmd.mutates());
        let count = sys.calls().len();
        for target in [ExecTarget::Host, ExecTarget::Netns(&handle)] {
            assert!(run_cmd(&sys, target, &cmd, timeout).is_err());
            assert!(run_cmd_with_stdin(&sys, target, &cmd, b"secret", timeout).is_err());
        }
        assert_eq!(sys.calls().len(), count);
        let (program, args) = cmd.render();
        let output = ExecOutput {
            status: Some(0),
            stdout: String::new(),
            stderr: String::new(),
        };
        sys.push_in(
            ExecTarget::Netns(&handle),
            program,
            &args,
            Ok(output.clone()),
        );
        let actual = if cmd.needs_stdin() {
            run_netns_cmd_with_stdin(&sys, &handle, &cmd, b"secret", timeout)
        } else {
            run_netns_cmd(&sys, &handle, &cmd, timeout)
        };
        assert_eq!(actual?, output);
        assert_eq!(sys.calls().len(), count + 1);
    }
    Ok(())
}

#[cfg(feature = "testing")]
#[test]
fn shared_userspace_sockets_block_every_namespace_wg_device_command() -> Result<(), Box<dyn Error>>
{
    use scupper_sys::system::{ExecError, ExecOutput, testing::FakeSystem};
    use std::os::{fd::AsRawFd, unix::net::UnixListener};
    let root = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map_or_else(
            || std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/tmp")),
            std::path::PathBuf::from,
        )
        .join(format!("wg-sockets-{}", std::process::id()));
    std::fs::create_dir(&root)?;
    let handle = scupper_sys::netns::testing::handle()?;
    let dirs = [root.join("var-run-wireguard"), root.join("run-wireguard")];
    for dir in &dirs {
        std::fs::create_dir(dir)?;
    }
    let sys = FakeSystem::new(0).with_wireguard_socket_dirs(dirs.to_vec());
    for dir in &dirs {
        let path = dir.join("wg0.sock");
        // Keep the actual socket under TMPDIR even in long worktree paths;
        // sockaddr_un cannot hold the complete absolute path on those systems.
        let directory = std::fs::File::open(dir)?;
        let socket =
            UnixListener::bind(format!("/proc/self/fd/{}/wg0.sock", directory.as_raw_fd()))?;
        for (wg, _) in wg_cases()? {
            if wg == WgCmd::Pubkey {
                continue;
            }
            let cmd = KernelCmd::Wg(wg);
            let result = if cmd.needs_stdin() {
                run_netns_cmd_with_stdin(&sys, &handle, &cmd, b"secret", Duration::from_secs(1))
            } else {
                run_netns_cmd(&sys, &handle, &cmd, Duration::from_secs(1))
            };
            assert_eq!(
                result,
                Err(ExecError::UserspaceWireguardSocket(path.clone()))
            );
        }
        assert_eq!(sys.calls(), []);
        drop(socket);
        std::fs::remove_file(path)?;
    }
    // An absent socket permits dispatch, and host observations remain available.
    let cmd = KernelCmd::Wg(WgCmd::Show {
        ifname: name()?,
        field: WgField::PublicKey,
    });
    let (program, args) = cmd.render();
    let output = ExecOutput {
        status: Some(0),
        stdout: "(none)\n".into(),
        stderr: String::new(),
    };
    for target in [ExecTarget::Host, ExecTarget::Netns(&handle)] {
        sys.push_in(target, program, &args, Ok(output.clone()));
        assert_eq!(run_cmd(&sys, target, &cmd, Duration::from_secs(1))?, output);
    }
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(feature = "testing")]
#[test]
fn sysctl_readback_decides_success_across_procps_statuses() -> Result<(), Box<dyn Error>> {
    use scupper_sys::system::{ExecOutput, testing::FakeSystem};
    let handle = scupper_sys::netns::testing::handle()?;
    let key = SysctlKey {
        family: SysctlFamily::Ipv4,
        scope: Scope::Global,
        name: "ip_forward",
    };
    for (write_status, read_status, read_value, success) in [
        (0, 0, "1\n", true),
        (1, 0, "1\n", true),
        (22, 0, "1\n", true),
        (0, 0, "0\n", false),
        (0, 1, "1\n", false),
        (0, 0, "bad", false),
    ] {
        let sys = FakeSystem::new(0);
        for (cmd, status, stdout) in [
            (SysctlCmd::Write(key.clone(), 1), write_status, ""),
            (SysctlCmd::Read(key.clone()), read_status, read_value),
        ] {
            let (program, args) = KernelCmd::Sysctl(cmd).render();
            sys.push_in(
                ExecTarget::Netns(&handle),
                program,
                &args,
                Ok(ExecOutput {
                    status: Some(status),
                    stdout: stdout.into(),
                    stderr: String::new(),
                }),
            );
        }
        assert_eq!(
            write_sysctl_verified(&sys, &handle, &key, 1, Duration::from_secs(1)).is_ok(),
            success
        );
        assert_eq!(sys.calls().len(), 2);
        assert!(
            sys.calls()
                .iter()
                .all(|call| call.target_identity == Some(handle.identity()))
        );
    }
    Ok(())
}

#[cfg(feature = "testing")]
#[test]
fn route_delete_requires_observed_absence() -> Result<(), Box<dyn Error>> {
    use scupper_sys::system::{ExecError, ExecOutput, System};
    struct Routes {
        inventory: String,
        fail_inventory: bool,
    }
    impl System for Routes {
        fn now_unix_secs(&self) -> u64 {
            1000
        }
        fn run(&self, _: Program, _: &[String], _: Duration) -> Result<ExecOutput, ExecError> {
            unreachable!()
        }
        fn run_in(
            &self,
            target: ExecTarget<'_>,
            program: Program,
            args: &[String],
            _: Duration,
        ) -> Result<ExecOutput, ExecError> {
            assert!(matches!(target, ExecTarget::Netns(_)));
            assert_eq!(program, Program::Ip);
            let deleting = args.iter().any(|arg| arg == "del");
            Ok(ExecOutput {
                status: Some(i32::from(deleting || self.fail_inventory)),
                stdout: if deleting {
                    String::new()
                } else {
                    self.inventory.clone()
                },
                stderr: "route disappeared".into(),
            })
        }
    }
    let entry = scupper_core::parse::parse_ip_route(r#"[{"dst":"198.18.0.0/24","dev":"foreign0","protocol":"kernel","scope":"link","prefsrc":"198.18.0.1"}]"#)?.remove(0);
    let route = scupper_core::planner::RouteKey {
        family: Family::V4,
        entry: entry.clone(),
    };
    let held = scupper_sys::netns::testing::handle()?;
    assert!(
        delete_observed_route(
            &Routes {
                inventory: "[]".into(),
                fail_inventory: false
            },
            &held,
            &route
        )
        .is_ok()
    );
    let present = r#"[{"dst":"198.18.0.0/24","dev":"foreign0","protocol":"kernel","scope":"link","prefsrc":"198.18.0.1"}]"#;
    assert!(
        delete_observed_route(
            &Routes {
                inventory: present.into(),
                fail_inventory: false
            },
            &held,
            &route
        )
        .is_err()
    );
    let changed_flags = r#"[{"dst":"198.18.0.0/24","dev":"foreign0","protocol":"boot","scope":"global","prefsrc":"198.18.0.2","flags":["linkdown"]}]"#;
    for (inventory, fail_inventory) in [("bad json", false), ("[]", true), (changed_flags, false)] {
        assert!(
            delete_observed_route(
                &Routes {
                    inventory: inventory.into(),
                    fail_inventory
                },
                &held,
                &route
            )
            .is_err()
        );
    }
    Ok(())
}
