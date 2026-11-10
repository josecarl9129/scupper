//! The complete address allocation. The root namespace receives no addresses.
#[derive(Clone, Copy)]
pub(super) struct Segment {
    pub ns: &'static str,
    pub wan_if: &'static str,
    pub staging: &'static str,
    pub network: &'static str,
    pub wan: &'static str,
    pub peer: &'static str,
}
pub(super) struct Addresses {
    pub gwhost: Segment,
    pub client: Segment,
    pub provider: Segment,
    pub client2: Segment,
    pub internet: Segment,
    pub bridge: Segment,
    pub client_net: &'static str,
    pub gateway_inner: &'static str,
    pub client_inner: &'static str,
    pub exit_net: &'static str,
    pub exit_inner: &'static str,
    pub provider_inner: &'static str,
    pub client_v6_net: &'static str,
    pub client_v6: &'static str,
    pub internet_v6_net: &'static str,
    pub internet_v6: &'static str,
    pub wan_v6: &'static str,
    pub bridge_v6: &'static str,
    pub bridge_wan_v6: &'static str,
    pub client_link_local_v6: &'static str,
}
pub(super) const PORT: u16 = 8080;
pub(super) const A: Addresses = Addresses {
    gwhost: Segment {
        ns: "gwhost",
        wan_if: "to-gwhost",
        staging: "scl-gw",
        network: "198.51.100.0/30",
        wan: "198.51.100.1",
        peer: "198.51.100.2",
    },
    client: Segment {
        ns: "client",
        wan_if: "to-client",
        staging: "scl-cl",
        network: "192.0.2.0/30",
        wan: "192.0.2.1",
        peer: "192.0.2.2",
    },
    client2: Segment {
        ns: "client2",
        wan_if: "to-client2",
        staging: "scl-cl2",
        network: "192.0.2.8/30",
        wan: "192.0.2.9",
        peer: "192.0.2.10",
    },
    provider: Segment {
        ns: "provA",
        wan_if: "to-provA",
        staging: "scl-pa",
        network: "203.0.113.0/30",
        wan: "203.0.113.1",
        peer: "203.0.113.2",
    },
    internet: Segment {
        ns: "internet",
        wan_if: "to-internet",
        staging: "scl-in",
        network: "192.0.2.4/30",
        wan: "192.0.2.5",
        peer: "192.0.2.6",
    },
    bridge: Segment {
        ns: "scupper",
        wan_if: "to-bridge",
        staging: "scl-br",
        network: "198.51.100.4/30",
        wan: "198.51.100.5",
        peer: "198.51.100.6",
    },
    client_net: "10.99.0.0/24",
    gateway_inner: "10.99.0.1",
    client_inner: "10.99.0.2",
    exit_net: "10.2.0.0/24",
    exit_inner: "10.2.0.2",
    provider_inner: "10.2.0.1",
    client_v6_net: "fd00:99::/64",
    client_v6: "fd00:99::2",
    internet_v6_net: "2001:db8:4::/64",
    internet_v6: "2001:db8:4::6",
    wan_v6: "2001:db8:4::5",
    bridge_v6: "2001:db8:5::6",
    bridge_wan_v6: "2001:db8:5::5",
    client_link_local_v6: "fe80::2",
};
impl Addresses {
    pub fn segments(&self) -> [Segment; 6] {
        [
            self.gwhost,
            self.client,
            self.client2,
            self.provider,
            self.internet,
            self.bridge,
        ]
    }
}

// IPv6-only path additions, installed only for nft isolation/control phases.
pub(super) const V6_PATH: [(&str, &str, &str); 4] = [
    ("scupper", "ex-ch1", "2001:db8:2::2/64"),
    ("provA", "wgp", "2001:db8:2::1/64"),
    ("provA", "eth0", "2001:db8:3::2/64"),
    ("wan", "to-provA", "2001:db8:3::1/64"),
];
