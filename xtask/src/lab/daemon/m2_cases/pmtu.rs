//! Exact DF/IPv6 datagrams exercise both sides of each tunnel's MTU boundary.
use super::{A, DaemonGuard, Duration, Flow, Invocation, IpAddr, Path, Result, Signal, fail, fs};
use crate::pcap::path::{Pmtu, pmtu_receiver, pmtu_sender};
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

fn mtu_config(text: &str, client_mtu: u32, exit_mtu: u32) -> Result<String> {
    let mut site = parse_site(text)?;
    let gateway = site
        .gateways
        .get_mut(&GatewayId("gw1".into()))
        .ok_or("PMTU gateway")?;
    gateway.client_tunnel.mtu = client_mtu;
    gateway
        .exits
        .iter_mut()
        .find(|exit| exit.ifname == "ex-ch1")
        .ok_or("PMTU exit")?
        .mtu = exit_mtu;
    validate(site.clone()).map_err(|errors| format!("PMTU config: {errors:?}"))?;
    Ok(toml::to_string(&site)?)
}

impl DaemonGuard<'_> {
    fn configure_pmtu(&mut self, root: &Path, client_mtu: u32, exit_mtu: u32) -> Result<()> {
        {
            let guard = WriterLock::acquire(root.join("run/scupper"))?;
            let store = VersionStore::open_with_mirror_root(
                root.join("var-lib/scupper"),
                root.join("etc/scupper"),
                Some(&guard),
            )?;
            let StateRead::Present(state) =
                StateFile::open(root.join("var-lib/scupper"), None)?.read()?
            else {
                return fail("PMTU missing applied state");
            };
            let (text, _) = store.read(state.applied_version.ok_or("PMTU applied version")?)?;
            let text = mtu_config(&text, client_mtu, exit_mtu)?;
            let version = store.commit(
                &guard,
                store.head()?,
                &text,
                MetaInput {
                    actor: "lab".into(),
                    at: 3,
                    reason: "supervised PMTU fixture".into(),
                },
            )?;
            self.lab.site = validate(parse_site(&text)?)
                .map_err(|errors| format!("PMTU config: {errors:?}"))?;
            let rules = render_netns(
                &self.lab.site,
                &GatewayId("gw1".into()),
                &VersionStamp {
                    version,
                    sha256: Sha256::digest(text.as_bytes()).into(),
                },
            )?;
            store.write_rendered(&guard, version, &rules)?;
            fs::write(&self.lab.rules, rules)?;
        }
        let (code, output) =
            self.control_command(root, &["apply"], &format!("pmtu-{client_mtu}-{exit_mtu}"))?;
        if code != 0 {
            return fail(format!("PMTU apply: {code}: {output}"));
        }
        self.lab.daemon_complete_tick(root)?;
        self.lab.daemon_route_healthy(Duration::from_secs(30))?;
        self.lab.wait_provider()?;
        self.lab.assert_transport_ports()?;
        self.expect_check(root, 0, None, "pmtu-configured")
    }
    pub(super) fn raw_udp(
        &mut self,
        ns: &str,
        interface: &str,
        endpoints: (IpAddr, IpAddr),
        ports: (u16, u16),
        size: usize,
    ) -> Result<usize> {
        let (source, destination) = endpoints;
        let (sport, dport) = ports;
        let marker = super::Lab::marker()?;
        self.lab.fault_markers.push(marker.clone());
        let bytes = datagram(source, destination, sport, dport, size, marker.as_bytes())?;
        let file = self.lab.private.join("m2-datagram.bin");
        let length = bytes.len();
        fs::write(&file, bytes)?;
        let exe = self.lab.executable.clone();
        self.lab.cmd(
            ns,
            &exe,
            &[
                "send-packet",
                "--interface",
                interface,
                "--file",
                file.to_str().ok_or("packet file")?,
            ],
        )?;
        Ok(length)
    }
    pub(super) fn pmtu_trial(&mut self, root: &Path, stem: &str) -> Result<()> {
        // Configure the smaller MTU through apply. An out-of-band MTU change is
        // real drift: reconciliation lowers the link while restoring it.
        for reverse in [false, true] {
            self.configure_pmtu(
                root,
                if reverse { 1280 } else { 1420 },
                if reverse { 1420 } else { 1280 },
            )?;
            self.pmtu_direction(stem, false, reverse)?;
            self.lab.daemon_complete_tick(root)?;
            let iface = if reverse { "wg0" } else { "ex-ch1" };
            let links: serde_json::Value = serde_json::from_str(&self.lab.cmd(
                "scupper",
                "ip",
                &["-j", "link", "show", iface],
            )?)?;
            fs::write(
                self.lab
                    .artifacts
                    .join(format!("L20-v4-{iface}-after-tick.json")),
                serde_json::to_vec_pretty(&links)?,
            )?;
            if links[0]["mtu"] != 1280 {
                return fail("L20 configured IPv4 MTU did not survive the supervised tick");
            }
            self.expect_check(
                root,
                0,
                None,
                if reverse {
                    "v4-return-supervised"
                } else {
                    "v4-outbound-supervised"
                },
            )?;
        }
        self.configure_pmtu(root, 1420, 1420)?;
        self.pmtu_v6_trial(root, stem)
    }
    fn pmtu_v6_trial(&mut self, root: &Path, stem: &str) -> Result<()> {
        // M2 refuses IPv6 configuration. This separate fixture checks renderer
        // chains only. Park between iterations: SIGSTOP can interrupt a kernel
        // read across its deadline and manufacture Unknown observations on resume.
        self.notify
            .as_ref()
            .ok_or("notify")?
            .incomplete_tick(root, true)?;
        let trial = (|| {
            self.lab.daemon_wait(
                "PMTU reconciliation parked",
                Duration::from_secs(40),
                |_| {
                    use scupper_proto::{Op, OpResult, Response};
                    use scupper_sys::daemon::control;
                    Ok(matches!(
                        control::call(
                            &root.join("run/scupper"),
                            &control::request(Op::Ping {}),
                            Duration::from_secs(2),
                        ),
                        Ok(Response {
                            result: Ok(OpResult::Ping {
                                current_iteration_age: None,
                                operation: None,
                                ..
                            }),
                            ..
                        })
                    ))
                },
            )?;
            self.reset_m2_network()?;
            self.pmtu_v6_path()?;
            for reverse in [false, true] {
                self.pmtu_direction(stem, true, reverse)?;
            }
            self.reset_m2_network()
        })();
        let resumed = self
            .notify
            .as_ref()
            .ok_or("notify")?
            .incomplete_tick(root, false);
        trial.and(resumed)?;
        self.lab.daemon_complete_tick(root)
    }
    fn pmtu_v6_path(&mut self) -> Result<()> {
        for (ns, iface, addr) in [
            ("client", "wg0", "fd00:99::2/64"),
            ("scupper", "wg0", "fd00:99::1/64"),
            ("scupper", "ex-ch1", "2001:db8:2::2/64"),
            ("provA", "wgp", "2001:db8:2::1/64"),
        ] {
            self.lab.cmd(
                ns,
                "ip",
                &["-6", "addr", "add", addr, "dev", iface, "nodad"],
            )?;
        }
        self.lab.cmd(
            "scupper",
            "ip",
            &["-6", "route", "replace", "default", "dev", "ex-ch1"],
        )?;
        self.lab.cmd(
            "scupper",
            "wg",
            &[
                "set",
                "wg0",
                "peer",
                &self.lab.public_keys[3].clone(),
                "allowed-ips",
                "10.99.0.2/32,fd00:99::2/128",
            ],
        )?;
        self.lab.cmd(
            "scupper",
            "wg",
            &[
                "set",
                "ex-ch1",
                "peer",
                &self.lab.public_keys[2].clone(),
                "allowed-ips",
                "0.0.0.0/0,::/0",
            ],
        )?;
        self.lab.cmd(
            "provA",
            "wg",
            &[
                "set",
                "wgp",
                "peer",
                &self.lab.public_keys[1].clone(),
                "allowed-ips",
                "10.2.0.2/32,2001:db8:2::2/128",
            ],
        )?;
        // Use the renderer's existing directional chains, widening only the two
        // empty M2 sets. No permissive replacement forward chain is installed.
        self.lab.runner.input(&Invocation::new("scupper","nft",&["-f","-"]),Some(b"add element inet scupper client_nets6 { fd00:99::/64 }\nadd element inet scupper exit_ifaces_v6 { \"ex-ch1\" }\n"))?;
        Ok(())
    }
    #[allow(clippy::too_many_lines)] // Keep the NAT control, MTU change and directional evidence adjacent.
    fn pmtu_direction(&mut self, stem: &str, v6: bool, reverse: bool) -> Result<()> {
        let tag = format!(
            "{stem}-{}-{}",
            if v6 { "v6" } else { "v4" },
            if reverse { "return" } else { "outbound" }
        );
        let (client, gateway, provider, exit): (IpAddr, IpAddr, IpAddr, IpAddr) = if v6 {
            (
                "fd00:99::2".parse()?,
                "fd00:99::1".parse()?,
                "2001:db8:2::1".parse()?,
                "2001:db8:2::2".parse()?,
            )
        } else {
            (
                A.client_inner.parse()?,
                A.gateway_inner.parse()?,
                A.provider_inner.parse()?,
                A.exit_inner.parse()?,
            )
        };
        for (iface, mtu) in [
            ("wg0", if reverse { "1280" } else { "1420" }),
            ("ex-ch1", if reverse { "1420" } else { "1280" }),
        ] {
            if v6 {
                self.lab
                    .cmd("scupper", "ip", &["link", "set", iface, "mtu", mtu])?;
            }
        }
        // A small request creates the NAT tuple required for a genuine related
        // return. Keep its client port bound so no unrelated ICMP is generated.
        let exe = self.lab.executable.clone();
        let log = self.lab.artifacts.join(format!("{tag}-sink.jsonl"));
        let bind = if v6 {
            "[2001:db8:2::1]:8080"
        } else {
            "10.2.0.1:8080"
        };
        let mut server = self.lab.runner.background(
            &Invocation::new(
                "provA",
                &exe,
                &[
                    "sink",
                    "--protocol",
                    "udp-drain",
                    "--bind",
                    bind,
                    "--log",
                    log.to_str().ok_or("log")?,
                ],
            ),
            &self.lab.artifacts.join(format!("{tag}-sink.stdout")),
        )?;
        self.lab
            .daemon_wait("PMTU provider listener", Duration::from_secs(3), |lab| {
                Ok(lab.cmd("provA", "ss", &["-lunH"])?.contains(":8080"))
            })?;
        // A silent client socket consumes normal UDP responses. It is a local
        // sink as well as the sender interface for the crafted exact datagram.
        let client_bind = if v6 {
            "[fd00:99::2]:40020"
        } else {
            "10.99.0.2:40020"
        };
        let mut client_sink = self.lab.runner.background(
            &Invocation::new(
                "client",
                &exe,
                &[
                    "sink",
                    "--protocol",
                    "udp-drain",
                    "--bind",
                    client_bind,
                    "--log",
                    log.to_str().ok_or("log")?,
                ],
            ),
            &self.lab.artifacts.join(format!("{tag}-client.stdout")),
        )?;
        self.lab
            .daemon_wait("PMTU client listener", Duration::from_secs(3), |lab| {
                Ok(lab.cmd("client", "ss", &["-lunH"])?.contains(":40020"))
            })?;
        // Sink helpers echo, so stop the normal provider echo immediately after
        // proving a request arrived; then inject just one measured large reply.
        self.raw_udp("client", "wg0", (client, provider), (40020, 8080), 64)?;
        self.lab
            .daemon_wait("PMTU established NAT tuple", Duration::from_secs(3), |_| {
                Ok(fs::read_to_string(&log).is_ok_and(|s| !s.is_empty()))
            })?;
        let (ns, iface, source, destination, router, sport, dport) = if reverse {
            ("provA", "wgp", provider, exit, exit, 8080, 40020)
        } else {
            ("client", "wg0", client, provider, gateway, 40020, 8080)
        };
        self.lab.capture(ns, iface, &format!("{tag}-sender"))?;
        // Capture the opposite side too: ICMP errors must never be forwarded to
        // the receiver of the oversized datagram.
        let (other_ns, other_if) = if reverse {
            ("client", "wg0")
        } else {
            ("provA", "wgp")
        };
        self.lab
            .capture(other_ns, other_if, &format!("{tag}-other"))?;
        fs::write(
            self.lab.artifacts.join(format!("{tag}.json")),
            serde_json::to_vec_pretty(
                &serde_json::json!({"sender":source,"destination":destination,"router":router,"source_port":sport,"destination_port":dport,"mtu":1280,"packet_bytes":1400,"reverse":reverse,"ipv6":v6,"supervision":if v6 {"renderer chain property, unsupervised"} else {"running"},"links":self.lab.cmd("scupper","ip",&["-j","link","show"])?}),
            )?,
        )?;
        self.raw_udp(ns, iface, (source, destination), (sport, dport), 1400)?;
        self.lab.runner.dwell(Duration::from_millis(500))?;
        self.lab.stop_capture()?;
        self.lab.stop_capture()?;
        pmtu_sender(
            &fs::read(self.lab.artifacts.join(format!("{tag}-sender.pcap")))?,
            &Pmtu {
                router,
                flow: Flow {
                    source,
                    destination,
                    protocol: 17,
                    ports: Some((sport, dport)),
                },
                mtu: 1280,
            },
        )?;
        // At the receiver NAT changes outbound source / return destination.
        let received_flow = Flow {
            source: if reverse { source } else { exit },
            destination: if reverse { client } else { destination },
            protocol: 17,
            ports: Some((sport, dport)),
        };
        pmtu_receiver(
            &fs::read(self.lab.artifacts.join(format!("{tag}-other.pcap")))?,
            &received_flow,
        )?;
        server.alive()?;
        client_sink.alive()?;
        server.stop(Signal::TERM)?;
        client_sink.stop(Signal::TERM)?;
        self.lab.cmd("scupper", "conntrack", &["-F"])?;
        Ok(())
    }
    pub(in crate::lab::daemon) fn reset_m2_network(&mut self) -> Result<()> {
        self.lab.runner.probe_ca = None;
        for (ns, iface, addr) in [
            ("client", "wg0", "fd00:99::2/64"),
            ("scupper", "wg0", "fd00:99::1/64"),
            ("scupper", "ex-ch1", "2001:db8:2::2/64"),
            ("provA", "wgp", "2001:db8:2::1/64"),
        ] {
            let _ = self.lab.runner.output(
                &Invocation::new(ns, "ip", &["-6", "addr", "del", addr, "dev", iface]),
                None,
            );
        }
        for iface in ["wg0", "ex-ch1"] {
            self.lab
                .cmd("scupper", "ip", &["link", "set", iface, "mtu", "1420"])?;
        }
        self.lab.cmd(
            "scupper",
            "ip",
            &["-6", "route", "replace", "unreachable", "default"],
        )?;
        for (ns, iface, peer, allowed) in [
            ("scupper", "wg0", 3, "10.99.0.2/32"),
            ("scupper", "ex-ch1", 2, "0.0.0.0/0"),
            ("provA", "wgp", 1, "10.2.0.2/32"),
        ] {
            self.lab.cmd(
                ns,
                "wg",
                &[
                    "set",
                    iface,
                    "peer",
                    &self.lab.public_keys[peer].clone(),
                    "allowed-ips",
                    allowed,
                ],
            )?;
        }
        for (ns, family, table) in [
            ("scupper", "inet", "m2_trace"),
            ("gwhost", "ip", "m2_host"),
            ("gwhost", "inet", "m2_host"),
            ("gwhost", "ip", "m2_nat"),
            ("gwhost", "ip", "m2_flush_control"),
        ] {
            let _ = self.lab.runner.output(
                &Invocation::new(ns, "nft", &["delete", "table", family, table]),
                None,
            );
        }
        let _ = self.lab.runner.output(
            &Invocation::new("gwhost", "ip", &["route", "del", "198.18.5.0/24"]),
            None,
        );
        let _ = self.lab.runner.output(
            &Invocation::new("gwhost", "ip", &["rule", "del", "pref", "100"]),
            None,
        );
        let _ = self.lab.runner.output(
            &Invocation::new("provA", "ip", &["route", "del", "10.99.0.0/24"]),
            None,
        );
        if self.case == "L11" {
            // Clear this trial's learned endpoint/session timers before later
            // cases require zero ciphertext on the idle client's transport.
            self.lab
                .cmd("client2", "ip", &["link", "set", "wg0", "down"])?;
            self.lab
                .cmd("client2", "ip", &["link", "set", "wg0", "up"])?;
            self.lab.assert_transport_ports()?;
            let peer = self.lab.public_keys[4].clone();
            self.lab
                .cmd("scupper", "wg", &["set", "wg0", "peer", &peer, "remove"])?;
            self.lab.cmd(
                "scupper",
                "wg",
                &["set", "wg0", "peer", &peer, "allowed-ips", "10.99.0.3/32"],
            )?;
        }
        self.lab.load_real_rules()?;
        Ok(())
    }
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(0)
}
fn datagram(
    source: IpAddr,
    destination: IpAddr,
    sport: u16,
    dport: u16,
    size: usize,
    marker: &[u8],
) -> Result<Vec<u8>> {
    let header = if source.is_ipv4() { 20 } else { 40 };
    let size = size.max(header + 8 + marker.len());
    if size < header + 8 || size > 65535 {
        return fail("invalid PMTU datagram size");
    }
    let mut udp = vec![b'P'; size - header];
    udp[..2].copy_from_slice(&sport.to_be_bytes());
    udp[2..4].copy_from_slice(&dport.to_be_bytes());
    let udp_len = u16::try_from(udp.len())?;
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[6..8].fill(0);
    udp[8..8 + marker.len()].copy_from_slice(marker);
    let mut packet = vec![0; header];
    match (source, destination) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&u16::try_from(size)?.to_be_bytes());
            packet[6] = 0x40;
            packet[8] = 64;
            packet[9] = 17;
            packet[12..16].copy_from_slice(&a.octets());
            packet[16..20].copy_from_slice(&b.octets());
            let sum = checksum(&packet);
            packet[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&u16::try_from(udp.len())?.to_be_bytes());
            packet[6] = 17;
            packet[7] = 64;
            packet[8..24].copy_from_slice(&a.octets());
            packet[24..40].copy_from_slice(&b.octets());
            let mut pseudo = Vec::new();
            pseudo.extend(a.octets());
            pseudo.extend(b.octets());
            pseudo.extend(u32::try_from(udp.len())?.to_be_bytes());
            pseudo.extend([0, 0, 0, 17]);
            pseudo.extend(&udp);
            let sum = checksum(&pseudo);
            udp[6..8].copy_from_slice(&if sum == 0 { u16::MAX } else { sum }.to_be_bytes());
        }
        _ => return fail("datagram family mismatch"),
    }
    packet.extend(udp);
    Ok(packet)
}

#[cfg(test)]
mod tests {
    #[test]
    fn supervised_pmtu_fixture_configures_each_direction_without_disabling_supervision() {
        let mut site = scupper_core::config::parse_site(super::super::super::super::SITE).unwrap();
        site.health.require_daemon = true;
        let text = toml::to_string(&site).unwrap();
        for (client_mtu, exit_mtu) in [(1420, 1280), (1280, 1420), (1420, 1420)] {
            let text = super::mtu_config(&text, client_mtu, exit_mtu).unwrap();
            let site = scupper_core::config::parse_site(&text).unwrap();
            let gateway = &site.gateways[&scupper_core::config::GatewayId("gw1".into())];
            assert_eq!(gateway.client_tunnel.mtu, client_mtu);
            assert_eq!(gateway.exits[0].mtu, exit_mtu);
            assert!(site.health.require_daemon);
        }
    }
    #[test]
    fn small_raw_v4_v6_controls_keep_the_complete_canary_marker() {
        let marker = b"scupper-canary-00112233445566778899aabbccddeeff";
        for (source, destination) in [
            ("198.18.12.2", "192.0.2.6"),
            ("fd00:99::2", "2001:db8:2::1"),
        ] {
            let packet = super::datagram(
                source.parse().unwrap(),
                destination.parse().unwrap(),
                40012,
                8080,
                64,
                marker,
            )
            .unwrap();
            assert!(packet.windows(marker.len()).any(|bytes| bytes == marker));
            assert!(packet.len() < 1280);
        }
    }
}
