//! Strict site parsing, exhaustive safety checks and topology properties.

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use ipnet::Ipv4Net;

use proptest::prelude::*;
use scupper_core::config::{
    AlertSink, ApiSettings, ConfigError, Device, DnsSettings, DurationStr, Exit, ExitId, Failback,
    Gateway, GatewayId, HeartbeatReport, ParseRule, PublicKey, Role, Rule, SecretKind, Severity,
    SiteConfig, Standby, User, ValidatedSite, ValidatedUrl, ValidationError, WebhookPreset,
    parse_site, validate,
};

const FIXTURE: &str = include_str!("fixtures/site-m2.toml");
const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

#[allow(clippy::unwrap_used)] // Test-fixture invariants; failures must fail the test.
fn config() -> SiteConfig {
    parse_site(FIXTURE).unwrap()
}
#[allow(clippy::unwrap_used)] // Test-fixture invariants; failures must fail the test.
fn gateway(cfg: &mut SiteConfig) -> &mut Gateway {
    cfg.gateways.get_mut(&GatewayId("gw1".into())).unwrap()
}
fn exit(cfg: &mut SiteConfig) -> &mut Exit {
    &mut gateway(cfg).exits[0]
}
#[allow(clippy::unwrap_used)] // Test-fixture invariants; failures must fail the test.
fn device(cfg: &mut SiteConfig) -> &mut Device {
    cfg.devices.get_mut("mac").unwrap()
}
#[allow(clippy::unwrap_used)] // Test-fixture invariants; failures must fail the test.
fn rejects(cfg: SiteConfig, path: &str, rule: Rule) -> Vec<ValidationError> {
    let errors = validate(cfg).unwrap_err();
    assert!(
        errors.contains(&ValidationError {
            path: path.into(),
            rule
        }),
        "expected {path}: {rule}; got {errors:?}"
    );
    errors
}
macro_rules! negative {
    ($name:ident, $path:literal, $rule:ident, $change:expr) => {
        #[test]
        fn $name() {
            let mut cfg = config();
            ($change)(&mut cfg);
            rejects(cfg, $path, Rule::$rule);
        }
    };
}

#[test]
#[allow(clippy::too_many_lines)] // Exercises every public accessor against the reference document.
fn reference_fixture_and_typed_accessors() {
    let cfg = config();
    let site = validate(cfg.clone()).unwrap();
    let serialized = toml::to_string(&cfg).unwrap();
    let actual_cfg = parse_site(&serialized).unwrap();
    let round_trip = validate(actual_cfg).unwrap();
    assert_eq!(format!("{site:?}"), format!("{round_trip:?}"));
    assert_eq!(site.site().name, "home");
    let gw = site.gateway(&GatewayId("gw1".into())).unwrap();
    assert!(site.gateway(&GatewayId("missing".into())).is_none());
    assert_eq!(site.gateways().len(), 1);
    assert_eq!(gw.endpoint().to_string(), "198.51.100.7:51820");
    assert_eq!(gw.uplinks()[0].as_str(), "eth0");
    assert_eq!(gw.client_tunnel().ifname().as_str(), "wg0");
    assert_eq!(gw.client_tunnel().address4().to_string(), "10.99.0.1/24");
    assert_eq!(
        gw.client_tunnel().identity().private_key_ref.kind(),
        SecretKind::Wg
    );
    assert_eq!(gw.client_tunnel().identity().private_key_ref.name(), "wg0");
    assert_eq!(gw.exits()[0].id().as_str(), "ch1");
    assert_eq!(gw.exits()[0].ifname().as_str(), "ex-ch1");
    assert_eq!(gw.exits()[0].ifname().ifname().as_str(), "ex-ch1");
    assert_eq!(gw.exits()[0].address4().to_string(), "10.2.0.2/32");
    assert_eq!(gw.exits()[0].dns()[0].to_string(), "10.2.0.1");
    assert_eq!(gw.exits()[0].peer_public_key(), [1; 32]);
    assert_eq!(gw.exits()[0].keepalive(), Duration::from_secs(25));
    assert_eq!(site.devices()["mac"].address4().prefix_len(), 32);
    assert_eq!(site.devices()["mac"].public_key(), [2; 32]);
    assert_eq!(site.policy().failback, Failback::Manual);
    assert_eq!(site.policy().standby, Standby::Hot);
    assert_eq!(site.health().handshake_stale(), Duration::from_secs(180));
    assert_eq!(site.sinks().len(), 2);
    assert_eq!(site.sinks()["phone"].min_severity(), Severity::Warning);
    assert_eq!(site.sinks()["phone"].url_ref().kind(), SecretKind::Url);
    assert!(matches!(
        site.sinks()["chat"],
        AlertSink::Webhook {
            preset: WebhookPreset::Telegram,
            ..
        }
    ));
    assert_eq!(
        site.heartbeat().unwrap().report,
        HeartbeatReport::StatusCode
    );
    assert_eq!(site.heartbeat().unwrap().url_ref.kind(), SecretKind::Url);
    assert_eq!(PublicKey(KEY.into()).to_string(), KEY);
    assert_eq!(site.site().primary.as_str(), "gw1");
    assert_eq!(gw.netns(), "scupper");
    assert!(gw.api().is_none());
    assert!(gw.dns().is_none());
    assert_eq!(gw.client_tunnel().identity_id(), "edge");
    assert_eq!(
        gw.client_tunnel().identity().public_key.bytes().unwrap(),
        [0; 32]
    );
    assert_eq!(gw.client_tunnel().identity().listen_port, 51820);
    assert_eq!(gw.client_tunnel().mtu(), 1420);
    let exit = &gw.exits()[0];
    assert_eq!(exit.name().as_str(), "Zurich");
    assert_eq!(
        exit.tags()
            .iter()
            .map(scupper_core::config::Tag::as_str)
            .collect::<Vec<_>>(),
        ["fast"]
    );
    assert_eq!(exit.provider(), "proton");
    assert_eq!(exit.private_key_ref().kind(), SecretKind::Wg);
    assert_eq!(exit.private_key_ref().name(), "exit-ch1");
    assert_eq!(exit.endpoint().to_string(), "203.0.113.10:51820");
    assert_eq!(exit.mtu(), 1420);
    assert!(exit.enabled());
    let device = &site.devices()["mac"];
    assert_eq!(device.user(), "admin");
    assert_eq!(device.gateways(), &[GatewayId("gw1".into())]);
    assert_eq!(device.api_token_sha256(), Some("0".repeat(64).as_str()));
    assert_eq!(device.address4().to_string(), "10.99.0.2/32");
    assert_eq!(site.users()["admin"].role, Role::Admin);
    assert_eq!(site.policy().exits, [ExitId("ch1".into())]);
    assert_eq!(
        site.policy().failback_hold.duration().unwrap().as_secs(),
        600
    );
    assert_eq!(site.policy().min_dwell.duration().unwrap().as_secs(), 120);
    let health = site.health();
    assert_eq!(health.failover_grace().as_secs(), 30);
    assert_eq!(
        health
            .probe_targets()
            .iter()
            .map(ValidatedUrl::as_str)
            .collect::<Vec<_>>(),
        [
            "https://probe.example.net/ip",
            "https://probe.example.org/ip"
        ]
    );
    assert_eq!(health.route_probe_dst4(), Ipv4Addr::new(1, 1, 1, 1));
    assert_eq!(
        health.route_probe_dst6(),
        "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!(
        health.speed_test_url().as_str(),
        "https://speed.example.net/25MB.bin"
    );
    assert_eq!(health.speed_test_url().host(), "speed.example.net");
    assert_eq!(health.speed_test_url().ip(), None);
    assert!(health.require_daemon());
    assert_eq!(site.sinks()["phone"].url_ref().name(), "ntfy-url");
    assert_eq!(site.sinks()["chat"].url_ref().name(), "telegram-url");
    assert_eq!(site.sinks()["chat"].min_severity(), Severity::Critical);
    let heartbeat = site.heartbeat().unwrap();
    assert_eq!(
        heartbeat.kind,
        scupper_core::config::HeartbeatKind::Healthchecks
    );
    assert_eq!(heartbeat.url_ref.name(), "heartbeat-url");
    assert_eq!(heartbeat.interval.duration().unwrap().as_secs(), 60);
}

#[test]
fn optional_api_and_dns_are_checked_and_retained() {
    let mut cfg = config();
    gateway(&mut cfg).api = Some(ApiSettings { port: 7380 });
    gateway(&mut cfg).dns = Some(DnsSettings {
        block_dot: true,
        cache: true,
    });
    let site = validate(cfg).unwrap();
    let gw = site.gateway(&GatewayId("gw1".into())).unwrap();
    assert_eq!(gw.api().unwrap().port, 7380);
    assert!(gw.dns().unwrap().block_dot);
    // Also exercise deserialization of the optional sections.
    validate(parse_site(&format!("{FIXTURE}\n[gateways.gw1.api]\nport = 7380\n[gateways.gw1.dns]\nblock_dot = true\ncache = true\n")).unwrap()).unwrap();
}

#[test]
fn omitted_settings_have_documented_defaults() {
    let input = FIXTURE;
    let start = input.find("[health]").unwrap();
    let end = input.find("[users.admin]").unwrap();
    let input = format!("{}{}", &input[..start], &input[end..]);
    let input = input
        .lines()
        .filter(|line| {
            ![
                "mtu =",
                "keepalive =",
                "enabled =",
                "tags =",
                "failback =",
                "failback_hold =",
                "min_dwell =",
                "standby =",
                "interval =",
                "report =",
            ]
            .iter()
            .any(|prefix| line.starts_with(prefix))
        })
        .collect::<Vec<_>>()
        .join("\n");
    let site = validate(parse_site(&input).unwrap()).unwrap();
    assert_eq!(site.health().handshake_stale().as_secs(), 180);
    assert_eq!(site.health().failover_grace().as_secs(), 30);
    assert_eq!(
        site.health()
            .probe_targets()
            .iter()
            .map(ValidatedUrl::as_str)
            .collect::<Vec<_>>(),
        ["https://ifconfig.me/ip", "https://icanhazip.com/"]
    );
    assert!(site.health().require_daemon());
    assert_eq!(site.health().route_probe_dst4(), Ipv4Addr::new(1, 1, 1, 1));
    assert_eq!(
        site.health().route_probe_dst6(),
        "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!(
        site.health().speed_test_url().as_str(),
        "https://speed.example.net/25MB.bin"
    );
    assert_eq!(site.policy().failback, Failback::Manual);
    let gw = site.gateway(&GatewayId("gw1".into())).unwrap();
    assert_eq!(gw.client_tunnel().mtu(), 1420);
    assert_eq!(gw.exits()[0].mtu(), 1420);
    assert_eq!(gw.exits()[0].keepalive().as_secs(), 25);
    assert!(gw.exits()[0].enabled());
    assert_eq!(gw.exits()[0].tags(), []);
    assert!(
        parse_site(&input).unwrap().devices["mac"]
            .address6
            .is_none()
    );
    // A present, empty health table applies the same field defaults.
    let input = input.replace("[users.admin]", "[health]\n\n[users.admin]");
    assert_eq!(
        parse_site(&input).unwrap().health.route_probe_dst4,
        "1.1.1.1"
    );
    assert_eq!(
        site.policy().failback_hold.duration().unwrap().as_secs(),
        600
    );
    assert_eq!(site.policy().min_dwell.duration().unwrap().as_secs(), 120);
    assert_eq!(site.policy().standby, Standby::Hot);
    assert_eq!(
        site.heartbeat()
            .unwrap()
            .interval
            .duration()
            .unwrap()
            .as_secs(),
        60
    );
    assert_eq!(site.heartbeat().unwrap().report, HeartbeatReport::OkOnly);
}

negative!(
    invalid_ifname,
    "gateways.gw1.client_tunnel.ifname",
    InvalidIfname,
    |c: &mut SiteConfig| gateway(c).client_tunnel.ifname = "WG_0".into()
);
negative!(
    long_ifname,
    "gateways.gw1.exits[0].ifname",
    InvalidIfname,
    |c: &mut SiteConfig| exit(c).ifname = "ex-12345678901234".into()
);
negative!(
    missing_exit_prefix,
    "gateways.gw1.exits[0].ifname",
    ExitIfnamePrefix,
    |c: &mut SiteConfig| exit(c).ifname = "exit0".into()
);
negative!(
    exit_uplink_collision,
    "gateways.gw1.exits[0].ifname",
    InterfaceConflict,
    |c: &mut SiteConfig| gateway(c).uplinks = vec!["ex-ch1".into()]
);
negative!(
    exit_client_collision,
    "gateways.gw1.exits[0].ifname",
    InterfaceConflict,
    |c: &mut SiteConfig| gateway(c).client_tunnel.ifname = "ex-ch1".into()
);
negative!(
    client_uplink_collision,
    "gateways.gw1.client_tunnel.ifname",
    InterfaceConflict,
    |c: &mut SiteConfig| gateway(c).uplinks = vec!["wg0".into()]
);
negative!(
    duplicate_uplink,
    "gateways.gw1.uplinks[1]",
    InterfaceConflict,
    |c: &mut SiteConfig| gateway(c).uplinks.push("eth0".into())
);
negative!(
    invalid_exit_id,
    "gateways.gw1.exits[0].id",
    InvalidId,
    |c: &mut SiteConfig| exit(c).id.0 = "UPPER".into()
);
negative!(
    long_exit_id,
    "gateways.gw1.exits[0].id",
    InvalidId,
    |c: &mut SiteConfig| exit(c).id.0 = "a".repeat(33)
);
negative!(
    invalid_exit_name,
    "gateways.gw1.exits[0].name",
    InvalidExitName,
    |c: &mut SiteConfig| exit(c).name.0 = "bad\nname".into()
);
negative!(
    empty_exit_name,
    "gateways.gw1.exits[0].name",
    InvalidExitName,
    |c: &mut SiteConfig| exit(c).name.0.clear()
);
negative!(
    invalid_tag,
    "gateways.gw1.exits[0].tags[0]",
    InvalidTag,
    |c: &mut SiteConfig| exit(c).tags[0].0 = "Fast!".into()
);
negative!(
    empty_policy,
    "policy.exits",
    EmptyPolicy,
    |c: &mut SiteConfig| c.policy.exits.clear()
);
negative!(
    unknown_policy_exit,
    "policy.exits[0]",
    UnknownExit,
    |c: &mut SiteConfig| c.policy.exits[0].0 = "absent".into()
);
negative!(
    disabled_policy_exit,
    "policy.exits[0]",
    DisabledExit,
    |c: &mut SiteConfig| exit(c).enabled = false
);
negative!(
    duplicate_policy_exit,
    "policy.exits[1]",
    DuplicatePolicyExit,
    |c: &mut SiteConfig| c.policy.exits.push(ExitId("ch1".into()))
);
negative!(
    device_subnet,
    "devices.mac.address4",
    DeviceHostPrefix,
    |c: &mut SiteConfig| device(c).address4 = "10.99.0.2/24".into()
);
negative!(
    device_default_route,
    "devices.mac.address4",
    DeviceHostPrefix,
    |c: &mut SiteConfig| device(c).address4 = "0.0.0.0/0".into()
);
negative!(
    device_outside,
    "devices.mac.address4",
    DeviceOutsideClientPrefix,
    |c: &mut SiteConfig| device(c).address4 = "203.0.113.2/32".into()
);
negative!(
    device_exit_overlap,
    "devices.mac.address4",
    DeviceAddressOverlap,
    |c: &mut SiteConfig| device(c).address4 = "10.2.0.2/32".into()
);
negative!(
    device_dns_overlap,
    "devices.mac.address4",
    DeviceAddressOverlap,
    |c: &mut SiteConfig| device(c).address4 = "10.2.0.1/32".into()
);
negative!(
    device_gateway_address_overlap,
    "devices.mac.address4",
    DeviceAddressOverlap,
    |c: &mut SiteConfig| device(c).address4 = "10.99.0.1/32".into()
);
negative!(
    unknown_device_gateway,
    "devices.mac.gateways[0]",
    UnknownGateway,
    |c: &mut SiteConfig| device(c).gateways[0].0 = "absent".into()
);
negative!(
    unknown_device_user,
    "devices.mac.user",
    UnknownUser,
    |c: &mut SiteConfig| device(c).user = "absent".into()
);
negative!(
    endpoint_hostname,
    "gateways.gw1.exits[0].endpoint",
    InvalidEndpoint,
    |c: &mut SiteConfig| exit(c).endpoint = "vpn.example.net:51820".into()
);
negative!(
    endpoint_zero_port,
    "gateways.gw1.endpoint",
    InvalidEndpoint,
    |c: &mut SiteConfig| gateway(c).endpoint = "198.51.100.7:0".into()
);
negative!(
    endpoint_large_port,
    "gateways.gw1.endpoint",
    InvalidEndpoint,
    |c: &mut SiteConfig| gateway(c).endpoint = "198.51.100.7:65536".into()
);
negative!(
    dns_hostname,
    "gateways.gw1.exits[0].dns[0]",
    InvalidDnsServer,
    |c: &mut SiteConfig| exit(c).dns[0] = "dns.example.net".into()
);
negative!(
    zero_duration,
    "gateways.gw1.exits[0].keepalive",
    InvalidDuration,
    |c: &mut SiteConfig| exit(c).keepalive.0 = "0s".into()
);
negative!(
    duration_order,
    "health.failover_grace",
    FailoverGraceNotLessThanHandshakeStale,
    |c: &mut SiteConfig| c.health.failover_grace.0 = "180s".into()
);
negative!(
    unknown_identity,
    "gateways.gw1.client_tunnel.identity",
    UnknownIdentity,
    |c: &mut SiteConfig| gateway(c).client_tunnel.identity = "absent".into()
);
negative!(
    primary_mismatch,
    "site.primary",
    PrimaryGatewayMismatch,
    |c: &mut SiteConfig| c.site.primary.0 = "absent".into()
);
negative!(
    block_dot_false,
    "gateways.gw1.dns.block_dot",
    BlockDotRequired,
    |c: &mut SiteConfig| gateway(c).dns = Some(DnsSettings {
        block_dot: false,
        cache: true
    })
);
negative!(
    client_ipv6,
    "gateways.gw1.client_tunnel.address6",
    NotSupportedInThisRelease,
    |c: &mut SiteConfig| gateway(c).client_tunnel.address6 = Some("2001:db8::1/64".into())
);
negative!(
    exit_ipv6,
    "gateways.gw1.exits[0].address6",
    NotSupportedInThisRelease,
    |c: &mut SiteConfig| exit(c).address6 = Some("2001:db8:2::2/128".into())
);
negative!(
    device_ipv6,
    "devices.mac.address6",
    NotSupportedInThisRelease,
    |c: &mut SiteConfig| device(c).address6 = Some("2001:db8::2/128".into())
);
negative!(
    unsupported_provider,
    "gateways.gw1.exits[0].provider",
    NotSupportedInThisRelease,
    |c: &mut SiteConfig| exit(c).provider = "other".into()
);
negative!(
    unsupported_disabled_exit,
    "gateways.gw1.exits[0].enabled",
    NotSupportedInThisRelease,
    |c: &mut SiteConfig| exit(c).enabled = false
);
negative!(
    no_gateway,
    "gateways",
    NotSupportedInThisRelease,
    |c: &mut SiteConfig| c.gateways.clear()
);
negative!(
    no_exit,
    "gateways.gw1.exits",
    NotSupportedInThisRelease,
    |c: &mut SiteConfig| gateway(c).exits.clear()
);
negative!(
    invalid_public_key,
    "devices.mac.public_key",
    InvalidPublicKey,
    |c: &mut SiteConfig| device(c).public_key.0 = "not-a-key".into()
);
negative!(
    invalid_address,
    "devices.mac.address4",
    InvalidAddress,
    |c: &mut SiteConfig| device(c).address4 = "client.example.net/32".into()
);
negative!(
    invalid_port,
    "identities.edge.listen_port",
    InvalidPort,
    |c: &mut SiteConfig| c.identities.get_mut("edge").unwrap().listen_port = 0
);
negative!(
    invalid_api_port,
    "gateways.gw1.api.port",
    InvalidPort,
    |c: &mut SiteConfig| gateway(c).api = Some(ApiSettings { port: 65536 })
);
negative!(
    invalid_namespace,
    "gateways.gw1.netns",
    InvalidNamespace,
    |c: &mut SiteConfig| gateway(c).netns = "other".into()
);
negative!(
    invalid_mtu,
    "gateways.gw1.client_tunnel.mtu",
    InvalidMtu,
    |c: &mut SiteConfig| gateway(c).client_tunnel.mtu = 0
);
negative!(
    invalid_token_hash,
    "devices.mac.api_token_sha256",
    InvalidTokenHash,
    |c: &mut SiteConfig| device(c).api_token_sha256 = Some("raw-token".into())
);
negative!(
    invalid_probe_url,
    "health.probe_targets[0]",
    InvalidProbeUrl,
    |c: &mut SiteConfig| c.health.probe_targets[0] = "http://probe.example.net".into()
);
negative!(
    empty_device_gateways,
    "devices.mac.gateways",
    EmptyDeviceGateways,
    |c: &mut SiteConfig| device(c).gateways.clear()
);
negative!(
    duplicate_device_gateway,
    "devices.mac.gateways[1]",
    DuplicateDeviceGateway,
    |c: &mut SiteConfig| device(c).gateways.push(GatewayId("gw1".into()))
);
negative!(
    invalid_gateway_id,
    "gateways.UPPER",
    InvalidId,
    |c: &mut SiteConfig| {
        let gw = c.gateways.remove(&GatewayId("gw1".into())).unwrap();
        c.gateways.insert(GatewayId("UPPER".into()), gw);
    }
);
negative!(
    manually_changed_schema,
    "schema",
    UnsupportedSchema,
    |c: &mut SiteConfig| c.schema = 2
);

#[test]
fn second_gateway_and_shared_identity_are_rejected() {
    let mut cfg = config();
    let gw = gateway(&mut cfg).clone();
    cfg.gateways.insert(GatewayId("gw2".into()), gw);
    let errors = rejects(cfg, "gateways", Rule::NotSupportedInThisRelease);
    assert!(errors.contains(&ValidationError {
        path: "gateways.gw2.client_tunnel.identity".into(),
        rule: Rule::IdentityShared
    }));
}

#[test]
fn second_exit_checks_duplicates_even_when_release_rejects_it() {
    let mut cfg = config();
    let mut second = exit(&mut cfg).clone();
    second.name.0 = "zURICH".into();
    gateway(&mut cfg).exits.push(second);
    let errors = rejects(cfg, "gateways.gw1.exits", Rule::NotSupportedInThisRelease);
    for (field, rule) in [
        ("id", Rule::DuplicateExitId),
        ("name", Rule::DuplicateExitName),
        ("ifname", Rule::InterfaceConflict),
    ] {
        assert!(errors.contains(&ValidationError {
            path: format!("gateways.gw1.exits[1].{field}"),
            rule
        }));
    }
}

#[test]
fn exit_name_may_not_equal_another_exits_id() {
    let mut cfg = config();
    let mut second = exit(&mut cfg).clone();
    second.id.0 = "other".into();
    second.name.0 = "CH1".into();
    second.ifname = "ex-other".into();
    gateway(&mut cfg).exits.push(second);
    rejects(cfg, "gateways.gw1.exits[1].name", Rule::ExitNameMatchesId);
}

#[test]
fn duplicate_device_addresses() {
    let mut cfg = config();
    let peer = device(&mut cfg).clone();
    cfg.devices.insert("phone".into(), peer);
    rejects(cfg, "devices.phone.address4", Rule::DuplicateDeviceAddress);
}

#[test]
fn reserved_r2_sections_parse_then_fail_specifically() {
    for section in ["groups", "policies", "allow", "providers"] {
        let value = if section == "policies" || section == "allow" {
            "[{}]"
        } else {
            "{}"
        };
        let text = format!("{section} = {value}\n{FIXTURE}");
        rejects(
            parse_site(&text).unwrap(),
            section,
            Rule::NotSupportedInThisRelease,
        );
    }
}

#[test]
fn unknown_fields_name_full_paths() {
    for (text, path) in [
        (format!("unexpected = 1\n{FIXTURE}"), "unexpected"),
        (format!("{FIXTURE}\nunexpected = 1"), "heartbeat.unexpected"),
        (
            FIXTURE.replace("netns =", "unexpected = 1\nnetns ="),
            "gateways.gw1.unexpected",
        ),
        (
            FIXTURE.replace("mtu = 1420", "unexpected = 1\nmtu = 1420"),
            "gateways.gw1.client_tunnel.unexpected",
        ),
        (
            FIXTURE.replace("keepalive =", "unexpected = 1\nkeepalive ="),
            "gateways.gw1.exits[0].unexpected",
        ),
        (
            FIXTURE.replace("kind = \"ntfy\"", "kind = \"ntfy\"\nunexpected = 1"),
            "alerts.sinks.phone.unexpected",
        ),
        (
            FIXTURE.replace("kind = \"ntfy\"", "kind = \"ntfy\"\npreset = \"generic\""),
            "alerts.sinks.phone.preset",
        ),
    ] {
        assert_eq!(
            parse_site(&text).unwrap_err(),
            ConfigError {
                path: path.into(),
                rule: ParseRule::UnknownField
            }
        );
    }
    assert_eq!(
        parse_site(&FIXTURE.replace("schema = 1", "schema = 2")).unwrap_err(),
        ConfigError {
            path: "schema".into(),
            rule: ParseRule::UnsupportedSchema
        }
    );
}

#[test]
fn malformed_enum_and_shape_errors_never_echo_input() {
    for text in [
        format!("{KEY} = ["),
        FIXTURE.replace("\"manual\"", &format!("\"{KEY}\"")),
        FIXTURE.replace("listen_port = 51820", &format!("listen_port = \"{KEY}\"")),
    ] {
        let error = parse_site(&text).unwrap_err();
        assert!(!error.to_string().contains(KEY));
        assert!(!format!("{error:?}").contains(KEY));
    }
    for bad in ["ntfy", "webhook", "other"] {
        assert!(
            parse_site(&FIXTURE.replace("kind = \"healthchecks\"", &format!("kind = \"{bad}\"")))
                .is_err()
        );
    }
}

#[test]
fn secret_grammar_and_schema_derived_kind() {
    for name in ["../x", "A", "x.y", &"x".repeat(64), ""] {
        for (old, path) in [
            ("wg0", "identities.edge.private_key_ref"),
            ("exit-ch1", "gateways.gw1.exits[0].private_key_ref"),
            ("ntfy-url", "alerts.sinks.phone.url_ref"),
            ("heartbeat-url", "heartbeat.url_ref"),
        ] {
            let field = if old.ends_with("url") {
                "url_ref"
            } else {
                "private_key_ref"
            };
            let input = FIXTURE.replace(
                &format!("{field} = \"{old}\""),
                &format!("{field} = \"{name}\""),
            );
            rejects(parse_site(&input).unwrap(), path, Rule::InvalidSecretRef);
        }
    }
    let input = FIXTURE.replace(
        "private_key_ref = \"wg0\"",
        "private_key_ref = \"ntfy-url\"",
    );
    let cfg = parse_site(&input).unwrap();
    // A URL-like name cannot select the URL directory from a key field.
    assert_eq!(
        cfg.identities["edge"].private_key_ref.kind(),
        SecretKind::Wg
    );
    assert_eq!(cfg.alerts.sinks["phone"].url_ref().kind(), SecretKind::Url);
    validate(cfg).unwrap();
    for name in ["0", "a-b", &"x".repeat(63)] {
        validate(
            parse_site(&FIXTURE.replace(
                "private_key_ref = \"wg0\"",
                &format!("private_key_ref = \"{name}\""),
            ))
            .unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn key_lint_covers_strings_tags_map_keys_and_never_echoes_values() {
    for path in [
        "site.name",
        "gateways.gw1.exits[0].name",
        "gateways.gw1.exits[0].tags[0]",
        "heartbeat.url_ref",
    ] {
        let mut cfg = config();
        match path {
            "site.name" => cfg.site.name = KEY.into(),
            "gateways.gw1.exits[0].name" => exit(&mut cfg).name.0 = KEY.into(),
            "gateways.gw1.exits[0].tags[0]" => exit(&mut cfg).tags[0].0 = KEY.into(),
            _ => {
                cfg = parse_site(&FIXTURE.replace("heartbeat-url", KEY)).unwrap();
            }
        }
        let errors = rejects(cfg, path, Rule::LooksLikeKeyMaterial);
        for error in errors {
            assert!(!error.to_string().contains(KEY));
            assert!(!format!("{error:?}").contains(KEY));
        }
    }
    let mut cfg = config();
    cfg.users.insert(KEY.into(), User { role: Role::User });
    rejects(cfg, "users.<redacted>", Rule::LooksLikeKeyMaterial);
    let error = parse_site(&format!("\"{KEY}\" = 1\n{FIXTURE}")).unwrap_err();
    assert_eq!(error.path, "<redacted>");
    assert!(!error.to_string().contains(KEY));
    // Public key and peer_public_key fields in the reference fixture are exempt.
    validate(config()).unwrap();
}

#[test]
fn all_independent_errors_are_returned() {
    let mut cfg = config();
    exit(&mut cfg).ifname = "eth0".into();
    device(&mut cfg).address4 = "0.0.0.0/0".into();
    device(&mut cfg).user = "absent".into();
    cfg.health.failover_grace.0 = "999s".into();
    let errors = validate(cfg).unwrap_err();
    for (path, rule) in [
        ("gateways.gw1.exits[0].ifname", Rule::InterfaceConflict),
        ("gateways.gw1.exits[0].ifname", Rule::ExitIfnamePrefix),
        ("devices.mac.address4", Rule::DeviceHostPrefix),
        ("devices.mac.user", Rule::UnknownUser),
        (
            "health.failover_grace",
            Rule::FailoverGraceNotLessThanHandshakeStale,
        ),
    ] {
        assert!(errors.contains(&ValidationError {
            path: path.into(),
            rule
        }));
    }
}

#[test]
fn duration_and_public_key_edges() {
    for (text, secs) in [("25s", 25), ("10m", 600), ("2h", 7200), ("120s", 120)] {
        assert_eq!(DurationStr(text.into()).duration().unwrap().as_secs(), secs);
    }
    for text in [
        "",
        "s",
        "0s",
        "-1s",
        "+1s",
        "1.5s",
        "2d",
        "1 s",
        "1S",
        "18446744073709551615h",
        "é",
        "\u{1f600}",
    ] {
        assert_eq!(
            DurationStr(text.into()).duration(),
            Err(Rule::InvalidDuration)
        );
    }
    assert_eq!(PublicKey(KEY.into()).bytes().unwrap(), [0; 32]);
    assert_eq!(
        PublicKey(KEY.trim_end_matches('=').into()).bytes().unwrap(),
        [0; 32]
    );
    for text in [
        "",
        "abc",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-=",
    ] {
        assert_eq!(PublicKey(text.into()).bytes(), Err(Rule::InvalidPublicKey));
    }
}

proptest! {
    #[test]
    fn valid_generated_sites_obey_topology(
        hosts in prop::collection::btree_set(2_u8..=254, 0..20),
        suffix in "[a-z0-9]{1,10}",
        family in 0_u8..3, base in any::<u16>(), prefix in 16_u8..=30,
    ) {
        let mut cfg = config();
        let first = match family { 0 => Ipv4Addr::new(10, 99, 0, 0), 1 => Ipv4Addr::new(172, 16, 0, 0), _ => Ipv4Addr::new(192, 168, 0, 0) };
        let net = Ipv4Net::new(Ipv4Addr::from(u32::from(first) + u32::from(base)), prefix).unwrap();
        let network = u32::from(net.network());
        gateway(&mut cfg).client_tunnel.address4 = format!("{}/{prefix}", Ipv4Addr::from(network + 1));
        let offsets: BTreeSet<_> = hosts.into_iter().map(|host| 2 + u32::from(host) % ((1_u32 << (32 - prefix)) - 3)).collect();
        let prototype = device(&mut cfg).clone();
        cfg.devices.clear();
        for (i, offset) in offsets.into_iter().enumerate() {
            let mut peer = prototype.clone();
            peer.address4 = format!("{}/32", Ipv4Addr::from(network + offset));
            peer.public_key = generated_key(u8::try_from(i + 1).unwrap());
            cfg.devices.insert(format!("peer-{offset}"), peer);
        }
        exit(&mut cfg).ifname = format!("ex-{suffix}");
        let site = validate(cfg).unwrap();
        assert_topology(&site);
    }

    #[test]
    fn generated_invalid_or_valid_configs_preserve_invariants_when_accepted(
        peers in prop::collection::vec((any::<u8>(), 0_u8..=32, 0_u8..=4), 0..12),
        exit_name in prop_oneof![Just("eth0".to_owned()), Just("wg0".to_owned()), "ex-[a-z0-9]{1,12}"],
        client_base in prop_oneof![any::<u32>(), (any::<u16>()).prop_map(|n| 0x0a63_0000 + u32::from(n))],
        client_len in 0_u8..=32,
        route4 in prop_oneof![Just("1.1.1.1".to_owned()), any::<u32>().prop_map(|n| Ipv4Addr::from(n).to_string())],
        route6 in prop_oneof![Just("2606:4700:4700::1111".to_owned()), any::<u128>().prop_map(|n| Ipv6Addr::from(n).to_string())],
        empty_uplinks in any::<bool>(), empty_probes in any::<bool>(), exit_len in 0_u8..=32,
    ) {
        let mut cfg = config();
        gateway(&mut cfg).client_tunnel.address4 = format!("{}/{client_len}", Ipv4Addr::from(client_base));
        cfg.health.route_probe_dst4 = route4;
        cfg.health.route_probe_dst6 = route6;
        if empty_uplinks { gateway(&mut cfg).uplinks.clear(); }
        if empty_probes { cfg.health.probe_targets.clear(); }
        exit(&mut cfg).address4 = format!("198.51.100.2/{exit_len}");
        let prototype = device(&mut cfg).clone();
        cfg.devices.clear();
        for (i, (host, prefix, key)) in peers.into_iter().enumerate() {
            let mut peer = prototype.clone();
            peer.address4 = format!("10.99.0.{host}/{prefix}");
            peer.public_key = generated_key(key);
            cfg.devices.insert(format!("peer-{i}"), peer);
        }
        exit(&mut cfg).ifname = exit_name;
        if let Ok(site) = validate(cfg) { assert_topology(&site); }
    }

    #[test]
    fn arbitrary_bounded_toml_never_panics(text in prop::collection::vec(any::<char>(), 0..4096)) {
        let text: String = text.into_iter().collect();
        if let Ok(cfg) = parse_site(&text) { let _ = validate(cfg); }
    }
}

#[allow(clippy::unwrap_used)] // Test-fixture invariants; failures must fail the test.
fn assert_topology(site: &ValidatedSite) {
    let mut seen = BTreeSet::new();
    for device in site.devices().values() {
        assert_eq!(device.address4().prefix_len(), 32);
        assert_ne!(device.address4().to_string(), "0.0.0.0/0");
        assert!(seen.insert(device.address4().addr()));
        for id in device.gateways() {
            let gw = site.gateway(id).unwrap();
            assert!(
                gw.client_tunnel()
                    .address4()
                    .contains(&device.address4().addr())
            );
        }
    }
    let route4: Ipv4Addr = site.health().route_probe_dst4();
    let route6: Ipv6Addr = site.health().route_probe_dst6();
    for cidr in [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    ] {
        assert!(!cidr.parse::<Ipv4Net>().unwrap().contains(&route4));
    }
    assert!(
        "2000::/3"
            .parse::<ipnet::Ipv6Net>()
            .unwrap()
            .contains(&route6)
    );
    assert!(
        !"2001:db8::/32"
            .parse::<ipnet::Ipv6Net>()
            .unwrap()
            .contains(&route6)
    );
    assert_ne!(site.health().probe_targets(), []);
    for (id, gw) in site.gateways() {
        let client = gw.client_tunnel().address4();
        assert!((16..=30).contains(&client.prefix_len()));
        assert!(client.network().is_private() && client.broadcast().is_private());
        assert_ne!(client.addr(), client.network());
        assert_ne!(client.addr(), client.broadcast());
        assert!(!client.contains(&route4));
        assert_ne!(gw.uplinks(), []);
        let mut keys = BTreeSet::from([gw.client_tunnel().identity().public_key.bytes().unwrap()]);
        let outside = |ip| {
            if let IpAddr::V4(ip) = ip {
                assert!(!client.contains(&ip));
            }
        };
        outside(gw.endpoint().ip());
        for url in site.health().probe_targets() {
            if let Some(ip) = url.ip() {
                outside(ip);
            }
        }
        for device in site
            .devices()
            .values()
            .filter(|device| device.gateways().contains(id))
        {
            assert_ne!(device.address4().addr(), client.addr());
            assert!(keys.insert(device.public_key()));
        }
        for exit in gw.exits() {
            assert_eq!(exit.address4().prefix_len(), 32);
            assert_ne!(route4, exit.address4().addr());
            assert!(
                !client.contains(&exit.address4().network())
                    && !exit.address4().contains(&client.network())
            );
            outside(exit.endpoint().ip());
            for ip in exit.dns() {
                outside(*ip);
            }
            assert!(keys.insert(exit.peer_public_key()));
            assert_ne!(exit.ifname().as_str(), gw.client_tunnel().ifname().as_str());
            assert!(
                !gw.uplinks()
                    .iter()
                    .any(|uplink| uplink.as_str() == exit.ifname().as_str())
            );
        }
    }
}

#[test]
fn programmatic_reference_swaps_cannot_bypass_field_kinds() {
    let mut cfg = config();
    cfg.identities.get_mut("edge").unwrap().private_key_ref =
        cfg.alerts.sinks["phone"].url_ref().clone();
    rejects(
        cfg,
        "identities.edge.private_key_ref",
        Rule::SecretKindMismatch,
    );
}

#[test]
fn public_key_named_map_entries_do_not_bypass_key_lint() {
    let mut cfg = config();
    let mut peer = device(&mut cfg).clone();
    peer.user = KEY.into();
    cfg.devices.insert("public_key".into(), peer);
    rejects(cfg, "devices.public_key.user", Rule::LooksLikeKeyMaterial);
}

#[test]
fn every_duration_field_reports_its_path() {
    for (old, path) in [
        ("handshake_stale = \"180s\"", "health.handshake_stale"),
        ("failover_grace = \"30s\"", "health.failover_grace"),
        ("failback_hold = \"10m\"", "policy.failback_hold"),
        ("min_dwell = \"120s\"", "policy.min_dwell"),
        ("keepalive = \"25s\"", "gateways.gw1.exits[0].keepalive"),
        ("interval = \"60s\"", "heartbeat.interval"),
    ] {
        let field = old.split(" = ").next().unwrap();
        let cfg = parse_site(&FIXTURE.replace(old, &format!("{field} = \"0s\""))).unwrap();
        rejects(cfg, path, Rule::InvalidDuration);
    }
}

#[test]
fn every_public_key_field_checks_length_and_padding() {
    for (old, path) in [
        ("[identities.edge]", "identities.edge.public_key"),
        (
            "[[gateways.gw1.exits]]",
            "gateways.gw1.exits[0].peer_public_key",
        ),
        ("[devices.mac]", "devices.mac.public_key"),
    ] {
        let mut cfg = config();
        match old {
            "[identities.edge]" => {
                cfg.identities.get_mut("edge").unwrap().public_key.0 = "invalid".into();
            }
            "[devices.mac]" => device(&mut cfg).public_key.0 = "invalid".into(),
            _ => exit(&mut cfg).peer_public_key.0 = "invalid".into(),
        }
        rejects(cfg, path, Rule::InvalidPublicKey);
    }
    assert_eq!(
        PublicKey("//////////////////////////////////////////8=".into())
            .bytes()
            .unwrap(),
        [255; 32]
    );
}

#[test]
fn literal_ipv6_endpoints_and_port_boundaries() {
    let mut cfg = config();
    gateway(&mut cfg).endpoint = "[2001:db8::7]:1".into();
    exit(&mut cfg).endpoint = "[2001:db8::10]:65535".into();
    let site = validate(cfg).unwrap();
    let gw = site.gateway(&GatewayId("gw1".into())).unwrap();
    assert_eq!(gw.endpoint().port(), 1);
    assert_eq!(gw.exits()[0].endpoint().port(), 65535);
}

#[test]
fn ifname_grammar_boundaries_and_cold_standby() {
    for name in [
        "",
        "Upper",
        "under_score",
        "dot.name",
        "é",
        "a".repeat(16).as_str(),
    ] {
        let mut cfg = config();
        gateway(&mut cfg).client_tunnel.ifname = name.into();
        rejects(
            cfg,
            "gateways.gw1.client_tunnel.ifname",
            Rule::InvalidIfname,
        );
    }
    let mut cfg = config();
    gateway(&mut cfg).client_tunnel.ifname = "a".into();
    exit(&mut cfg).ifname = "ex-123456789012".into();
    cfg.policy.standby = Standby::Cold;
    validate(cfg).unwrap();
}

#[test]
fn all_nested_models_reject_unknown_fields() {
    for (header, path) in [
        ("[site]", "site.bad"),
        ("[identities.edge]", "identities.edge.bad"),
        ("[policy]", "policy.bad"),
        ("[health]", "health.bad"),
        ("[users.admin]", "users.admin.bad"),
        ("[devices.mac]", "devices.mac.bad"),
        ("[alerts.sinks.chat]", "alerts.sinks.chat.bad"),
    ] {
        let input = FIXTURE.replace(header, &format!("{header}\nbad = true"));
        assert_eq!(
            parse_site(&input).unwrap_err(),
            ConfigError {
                path: path.into(),
                rule: ParseRule::UnknownField
            }
        );
    }
    for (header, body, path) in [
        ("[alerts]", "bad = true", "alerts.bad"),
        (
            "[gateways.gw1.api]",
            "port = 7380\nbad = true",
            "gateways.gw1.api.bad",
        ),
        (
            "[gateways.gw1.dns]",
            "block_dot = true\ncache = true\nbad = true",
            "gateways.gw1.dns.bad",
        ),
    ] {
        let input = format!("{FIXTURE}\n{header}\n{body}");
        assert_eq!(
            parse_site(&input).unwrap_err(),
            ConfigError {
                path: path.into(),
                rule: ParseRule::UnknownField
            }
        );
    }
}

// Distinct synthetic public keys: 31 zero bytes followed by the seed byte.
fn generated_key(seed: u8) -> PublicKey {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    PublicKey(format!(
        "{}{}{}=",
        "A".repeat(41),
        char::from(ALPHABET[usize::from(seed >> 2)]),
        char::from(ALPHABET[usize::from((seed & 3) << 4)])
    ))
}

#[test]
fn client_prefix_requires_private_host_subnets() {
    for address in [
        "10.99.0.1/0",
        "10.99.0.1/8",
        "10.99.0.1/15",
        "10.99.0.1/31",
        "10.99.0.1/32",
        "198.51.100.1/24",
        "100.64.0.1/24",
        "10.99.0.0/24",
        "10.99.0.255/24",
        "172.15.0.1/16",
        "172.32.0.1/16",
        "192.169.0.1/16",
    ] {
        let mut cfg = config();
        gateway(&mut cfg).client_tunnel.address4 = address.into();
        rejects(
            cfg,
            "gateways.gw1.client_tunnel.address4",
            Rule::InvalidClientPrefix,
        );
    }
    for address in [
        "10.99.0.1/16",
        "10.99.0.1/30",
        "172.16.0.1/16",
        "172.31.0.1/16",
        "192.168.0.1/16",
    ] {
        let mut cfg = config();
        gateway(&mut cfg).client_tunnel.address4 = address.into();
        let ip: Ipv4Addr = address.split('/').next().unwrap().parse().unwrap();
        device(&mut cfg).address4 = format!("{}/32", Ipv4Addr::from(u32::from(ip) + 1));
        validate(cfg).unwrap();
    }
}

#[test]
fn client_prefix_cannot_overlap_any_infrastructure_address() {
    for field in [
        "exit-address",
        "exit-dns",
        "exit-endpoint",
        "gateway-endpoint",
        "route-probe",
        "probe-target",
        "speed-test",
        "exit-subnet",
    ] {
        let mut cfg = config();
        match field {
            "exit-address" => exit(&mut cfg).address4 = "10.99.0.200/32".into(),
            "exit-subnet" => exit(&mut cfg).address4 = "10.0.0.2/8".into(),
            "exit-dns" => exit(&mut cfg).dns = vec!["10.99.0.200".into()],
            "exit-endpoint" => exit(&mut cfg).endpoint = "10.99.0.200:51820".into(),
            "gateway-endpoint" => gateway(&mut cfg).endpoint = "10.99.0.200:51820".into(),
            "route-probe" => cfg.health.route_probe_dst4 = "10.99.0.200".into(),
            "speed-test" => cfg.health.speed_test_url = "https://10.99.0.200:443/ip".into(),
            _ => cfg.health.probe_targets = vec!["https://10.99.0.200:443/ip".into()],
        }
        rejects(
            cfg,
            "gateways.gw1.client_tunnel.address4",
            Rule::ClientPrefixOverlap,
        );
    }
}

negative!(
    empty_uplinks,
    "gateways.gw1.uplinks",
    EmptyUplinks,
    |c: &mut SiteConfig| gateway(c).uplinks.clear()
);
negative!(
    empty_probes,
    "health.probe_targets",
    EmptyProbeTargets,
    |c: &mut SiteConfig| c.health.probe_targets.clear()
);
negative!(
    exit_requires_host_prefix,
    "gateways.gw1.exits[0].address4",
    ExitHostPrefix,
    |c: &mut SiteConfig| exit(c).address4 = "198.51.100.2/24".into()
);
negative!(
    empty_exit_dns,
    "gateways.gw1.exits[0].dns",
    EmptyDnsServers,
    |c: &mut SiteConfig| exit(c).dns.clear()
);
negative!(
    ipv6_exit_dns,
    "gateways.gw1.exits[0].dns[0]",
    NotSupportedInThisRelease,
    |c: &mut SiteConfig| exit(c).dns[0] = "2001:db8::53".into()
);

#[test]
fn route_probe_ipv4_requires_public_unicast() {
    for ip in [
        "0.0.0.0",
        "0.1.2.3",
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.0.1",
        "100.64.0.1",
        "100.127.255.254",
        "224.0.0.1",
        "239.1.2.3",
        "255.255.255.255",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "198.18.0.1",
        "240.0.0.1",
        "2001:db8::1",
        "invalid",
    ] {
        let mut cfg = config();
        cfg.health.route_probe_dst4 = ip.into();
        rejects(cfg, "health.route_probe_dst4", Rule::InvalidRouteProbe);
    }
    let mut cfg = config();
    cfg.health.route_probe_dst4 = "10.99.0.200".into();
    rejects(cfg, "health.route_probe_dst4", Rule::InvalidRouteProbe);
    let mut cfg = config();
    exit(&mut cfg).address4 = "1.1.1.1/32".into();
    rejects(cfg, "health.route_probe_dst4", Rule::InvalidRouteProbe);
    for ip in ["1.1.1.1", "8.8.8.8", "100.63.255.255", "100.128.0.1"] {
        let mut cfg = config();
        cfg.health.route_probe_dst4 = ip.into();
        validate(cfg).unwrap();
    }
}

#[test]
fn route_probe_ipv6_requires_global_unicast() {
    for ip in [
        "::",
        "::1",
        "fc00::1",
        "fdff::1",
        "fe80::1",
        "ff02::1",
        "2001:db8::1",
        "::ffff:1.1.1.1",
        "100::1",
        "3fff::1",
        "1.1.1.1",
        "invalid",
    ] {
        let mut cfg = config();
        cfg.health.route_probe_dst6 = ip.into();
        rejects(cfg, "health.route_probe_dst6", Rule::InvalidRouteProbe);
    }
    for ip in ["2606:4700:4700::1111", "2001:4860:4860::8888"] {
        let mut cfg = config();
        cfg.health.route_probe_dst6 = ip.into();
        validate(cfg).unwrap();
    }
}

#[test]
fn peer_keys_are_distinct_after_decoding() {
    let mut cfg = config();
    let mut second = device(&mut cfg).clone();
    second.address4 = "10.99.0.3/32".into();
    second.public_key.0 = second.public_key.0.trim_end_matches('=').into();
    cfg.devices.insert("phone".into(), second);
    rejects(cfg, "devices.phone.public_key", Rule::DuplicatePublicKey);
    let mut cfg = config();
    device(&mut cfg).public_key = cfg.identities["edge"].public_key.clone();
    rejects(cfg, "devices.mac.public_key", Rule::DuplicatePublicKey);
    let mut cfg = config();
    exit(&mut cfg).peer_public_key = cfg.identities["edge"].public_key.clone();
    rejects(
        cfg,
        "gateways.gw1.exits[0].peer_public_key",
        Rule::DuplicatePublicKey,
    );
    let mut cfg = config();
    device(&mut cfg).public_key = exit(&mut cfg).peer_public_key.clone();
    rejects(cfg, "devices.mac.public_key", Rule::DuplicatePublicKey);
}

#[test]
fn probe_and_speed_urls_require_strict_https_authorities() {
    let long_label = format!("https://{}.example", "x".repeat(64));
    let long_host = format!(
        "https://{}.{}.{}.{}",
        "x".repeat(63),
        "x".repeat(63),
        "x".repeat(63),
        "x".repeat(63)
    );
    for url in [
        "https://:",
        "https://@x",
        "https://x:0",
        "http://x",
        "https://exa mple",
        "https://user:pass@x/",
        "https://x:65536/",
        "https://x:/",
        "https://x:+1",
        "https://x:1:2",
        "https://-x",
        "https://x-",
        "https://x..example",
        "https://",
        "https:///ip",
        "https://x\n/ip",
        "https://x/\t",
        "https://x/\u{7f}",
        "https://x\\evil",
        "https://[invalid]/",
        "https://[::1]",
        "https://::1/",
        "https://[::1]tail",
        "https://é.example",
        &long_label,
        &long_host,
    ] {
        let mut cfg = config();
        cfg.health.probe_targets[0] = url.into();
        rejects(cfg, "health.probe_targets[0]", Rule::InvalidProbeUrl);
        let mut cfg = config();
        cfg.health.speed_test_url = url.into();
        rejects(cfg, "health.speed_test_url", Rule::InvalidProbeUrl);
    }
    let max_host = format!(
        "https://{}.{}.{}.{}",
        "x".repeat(63),
        "x".repeat(63),
        "x".repeat(63),
        "x".repeat(61)
    );
    for url in [
        "https://x",
        "https://Example-1.COM:1/ip?x=y#z",
        "https://x:65535",
        "https://8.8.8.8/ip",
        "https://[2001:4860:4860::8888]:443/ip",
        &max_host,
    ] {
        let mut cfg = config();
        cfg.health.probe_targets[0] = url.into();
        cfg.health.speed_test_url = url.into();
        let site = validate(cfg).unwrap();
        assert_eq!(site.health().probe_targets()[0].as_str(), url);
        assert_eq!(
            &site.health().probe_targets()[0],
            site.health().speed_test_url()
        );
        match site.health().speed_test_url().host() {
            "8.8.8.8" => assert_eq!(
                site.health().speed_test_url().ip(),
                Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
            ),
            "2001:4860:4860::8888" => assert_eq!(
                site.health().speed_test_url().ip(),
                Some("2001:4860:4860::8888".parse().unwrap())
            ),
            _ => assert_eq!(site.health().speed_test_url().ip(), None),
        }
    }
}

#[test]
fn keepalive_respects_wireguard_and_handshake_bounds() {
    for keepalive in ["179s", "180s", "181s", "65536s"] {
        let mut cfg = config();
        exit(&mut cfg).keepalive.0 = keepalive.into();
        rejects(
            cfg,
            "gateways.gw1.exits[0].keepalive",
            Rule::InvalidKeepalive,
        );
    }
    for (keepalive, stale) in [("1s", "180s"), ("25s", "175s"), ("65535s", "65685s")] {
        let mut cfg = config();
        exit(&mut cfg).keepalive.0 = keepalive.into();
        cfg.health.handshake_stale.0 = stale.into();
        validate(cfg).unwrap();
    }
}

#[test]
fn key_lint_finds_embedded_keys_at_any_offset_and_redacts_paths() {
    for value in [
        format!("prefix{KEY}suffix"),
        format!("é{KEY}"),
        format!("AAA{KEY}AAA"),
        format!("/{KEY}/"),
    ] {
        for field in ["name", "url", "sink", "tag", "exit-name"] {
            let mut cfg = config();
            let path = match field {
                "name" => {
                    cfg.site.name = value.clone();
                    "site.name"
                }
                "url" => {
                    cfg.health.probe_targets[0] = format!("https://probe.example/{value}");
                    "health.probe_targets[0]"
                }
                "sink" => {
                    let sink = cfg.alerts.sinks.remove("phone").unwrap();
                    cfg.alerts.sinks.insert(value.clone(), sink);
                    "alerts.sinks.<redacted>"
                }
                "tag" => {
                    exit(&mut cfg).tags[0].0 = value.clone();
                    "gateways.gw1.exits[0].tags[0]"
                }
                _ => {
                    exit(&mut cfg).name.0 = value.clone();
                    "gateways.gw1.exits[0].name"
                }
            };
            let errors = rejects(cfg, path, Rule::LooksLikeKeyMaterial);
            assert!(errors.iter().all(
                |error| !error.to_string().contains(KEY) && !format!("{error:?}").contains(KEY)
            ));
        }
    }
    let error = parse_site(&format!("\"prefix{KEY}suffix\" = 1\n{FIXTURE}")).unwrap_err();
    assert_eq!(error.path, "<redacted>");
}

#[test]
fn map_ids_have_the_same_strict_grammar() {
    for id in ["bad\nname", "[", "-x", "Upper", "", &"x".repeat(33)] {
        for map in ["devices", "identities", "users", "alerts.sinks", "gateways"] {
            let mut cfg = config();
            match map {
                "devices" => {
                    let entry = cfg.devices.remove("mac").unwrap();
                    cfg.devices.insert(id.into(), entry);
                }
                "identities" => {
                    let entry = cfg.identities.remove("edge").unwrap();
                    cfg.identities.insert(id.into(), entry);
                }
                "users" => {
                    let entry = cfg.users.remove("admin").unwrap();
                    cfg.users.insert(id.into(), entry);
                }
                "alerts.sinks" => {
                    let entry = cfg.alerts.sinks.remove("phone").unwrap();
                    cfg.alerts.sinks.insert(id.into(), entry);
                }
                _ => {
                    let entry = cfg.gateways.remove(&GatewayId("gw1".into())).unwrap();
                    cfg.gateways.insert(GatewayId(id.into()), entry);
                }
            }
            rejects(cfg, &format!("{map}.{id}"), Rule::InvalidId);
        }
    }
}

#[test]
fn clients_and_uplinks_cannot_use_reserved_interface_names() {
    for name in ["-x", "lo", "ex-wg"] {
        let mut cfg = config();
        gateway(&mut cfg).client_tunnel.ifname = name.into();
        rejects(
            cfg,
            "gateways.gw1.client_tunnel.ifname",
            Rule::InvalidIfname,
        );
        let mut cfg = config();
        gateway(&mut cfg).uplinks[0] = name.into();
        rejects(cfg, "gateways.gw1.uplinks[0]", Rule::InvalidIfname);
    }
}

#[test]
fn exit_dns_cannot_be_unspecified_local_multicast_or_broadcast() {
    for ip in [
        "0.0.0.0",
        "127.0.0.1",
        "127.100.1.1",
        "224.0.0.1",
        "239.255.255.255",
        "255.255.255.255",
    ] {
        let mut cfg = config();
        exit(&mut cfg).dns[0] = ip.into();
        rejects(cfg, "gateways.gw1.exits[0].dns[0]", Rule::InvalidDnsServer);
    }
    let mut cfg = config();
    exit(&mut cfg).dns[0] = "10.2.0.1".into();
    validate(cfg).unwrap();
}

#[test]
fn numeric_url_hosts_cannot_masquerade_as_dns_names() {
    for host in [
        "10.99.5",
        "174260229",
        "0x0a.0x63.0.5",
        "012.0143.0.5",
        "127.1",
        "0177.1",
        "2130706433",
        "0x7f000001",
        "0X7F.0.0.1",
        "example.123",
        "0x0a.example",
        "example.0xff",
        "999.1.1.1",
    ] {
        reject_health_url(&format!("https://{host}/ip"));
    }
    for host in ["123.example", "a1.example", "dead.beef", "123abc"] {
        let mut cfg = config();
        cfg.health.probe_targets[0] = format!("https://{host}/ip");
        cfg.health.speed_test_url = format!("https://{host}/speed");
        validate(cfg).unwrap();
    }
}

fn reject_health_url(url: &str) {
    let mut cfg = config();
    cfg.health.probe_targets[0] = url.into();
    rejects(cfg, "health.probe_targets[0]", Rule::InvalidProbeUrl);
    let mut cfg = config();
    cfg.health.speed_test_url = url.into();
    rejects(cfg, "health.speed_test_url", Rule::InvalidProbeUrl);
}

#[test]
fn literal_url_hosts_require_public_unicast() {
    for host in [
        "0.0.0.0",
        "0.1.2.3",
        "127.0.0.1",
        "10.2.0.2",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.0.1",
        "100.64.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "198.18.0.1",
        "240.0.0.1",
        "[::]",
        "[::1]",
        "[fc00::1]",
        "[fe80::1]",
        "[ff02::1]",
        "[2001:db8::1]",
        "[::ffff:8.8.8.8]",
        "[3fff::1]",
        "[2606:4700::1%eth0]",
    ] {
        reject_health_url(&format!("https://{host}/ip"));
    }
}

#[test]
fn public_url_hosts_cannot_equal_exit_addresses() {
    for speed in [false, true] {
        let mut cfg = config();
        exit(&mut cfg).address4 = "8.8.8.8/32".into();
        let path = if speed {
            cfg.health.speed_test_url = "https://8.8.8.8/speed".into();
            "health.speed_test_url"
        } else {
            cfg.health.probe_targets[0] = "https://8.8.8.8/ip".into();
            "health.probe_targets[0]"
        };
        rejects(cfg, path, Rule::InvalidProbeUrl);
    }
}

#[test]
fn handshake_staleness_includes_rekey_time_and_slack() {
    let mut cfg = config();
    cfg.health.handshake_stale.0 = "150s".into();
    rejects(
        cfg,
        "gateways.gw1.exits[0].keepalive",
        Rule::InvalidKeepalive,
    );
    for stale in ["31s", "149s"] {
        let mut cfg = config();
        // Even the shortest valid keepalive cannot bypass the absolute bound.
        exit(&mut cfg).keepalive.0 = "1s".into();
        cfg.health.handshake_stale.0 = stale.into();
        rejects(cfg, "health.handshake_stale", Rule::InvalidHandshakeStale);
    }
    let mut cfg = config();
    cfg.health.handshake_stale.0 = "174s".into();
    rejects(
        cfg,
        "gateways.gw1.exits[0].keepalive",
        Rule::InvalidKeepalive,
    );
}

#[test]
fn device_addresses_exclude_subnet_network_and_broadcast() {
    for (client, device_ip) in [
        ("10.99.0.1/24", "10.99.0.0/32"),
        ("10.99.0.1/24", "10.99.0.255/32"),
        ("10.99.0.1/16", "10.99.0.0/32"),
        ("10.99.0.1/16", "10.99.255.255/32"),
        ("10.99.0.1/30", "10.99.0.0/32"),
        ("10.99.0.1/30", "10.99.0.3/32"),
    ] {
        let mut cfg = config();
        gateway(&mut cfg).client_tunnel.address4 = client.into();
        device(&mut cfg).address4 = device_ip.into();
        rejects(cfg, "devices.mac.address4", Rule::DeviceOutsideClientPrefix);
    }
}

#[test]
fn display_names_have_printable_length_bounds() {
    for name in [
        "",
        "line\nbreak",
        "tab\tname",
        "control\u{7f}",
        &"x".repeat(65),
    ] {
        let mut cfg = config();
        cfg.site.name = name.into();
        rejects(cfg, "site.name", Rule::InvalidSiteName);
    }
    for name in ["x", &"x".repeat(64), &"é".repeat(64)] {
        let mut cfg = config();
        cfg.site.name = name.into();
        validate(cfg).unwrap();
    }
    for name in ["", " ", "   ", "\u{2003}"] {
        let mut cfg = config();
        exit(&mut cfg).name.0 = name.into();
        rejects(cfg, "gateways.gw1.exits[0].name", Rule::InvalidExitName);
    }
    let mut cfg = config();
    exit(&mut cfg).name.0 = " Zurich ".into();
    validate(cfg).unwrap();
}

#[test]
fn exit_interface_requires_a_suffix() {
    for name in ["ex-", "ex--", "ex-a-b"] {
        let mut cfg = config();
        exit(&mut cfg).ifname = name.into();
        rejects(cfg, "gateways.gw1.exits[0].ifname", Rule::ExitIfnamePrefix);
    }
    let mut cfg = config();
    exit(&mut cfg).ifname = "ex-0".into();
    validate(cfg).unwrap();
}

#[test]
fn endpoints_exclude_unspecified_ips_and_ipv6_scopes() {
    for endpoint in [
        "0.0.0.0:51820",
        "[::]:51820",
        "[fe80::1%eth0]:51820",
        "[fe80::1%2]:51820",
    ] {
        let mut cfg = config();
        gateway(&mut cfg).endpoint = endpoint.into();
        rejects(cfg, "gateways.gw1.endpoint", Rule::InvalidEndpoint);
        let mut cfg = config();
        exit(&mut cfg).endpoint = endpoint.into();
        rejects(cfg, "gateways.gw1.exits[0].endpoint", Rule::InvalidEndpoint);
    }
}

#[test]
fn key_lint_catches_embedded_unpadded_and_url_safe_base64() {
    for key in [
        KEY.trim_end_matches('=').to_owned(),
        format!("{}8=", "/".repeat(42)),
        format!("{}8", "_".repeat(42)),
        format!("{}8=", "_".repeat(42)),
        format!("{}8", "-".repeat(42)),
        format!("{}8=", "-".repeat(42)),
    ] {
        for value in [
            key.clone(),
            format!("prefix{key}suffix"),
            format!("é/{key}/tail"),
        ] {
            let mut cfg = config();
            cfg.health.probe_targets[0] = format!("https://probe.example/{value}");
            rejects(cfg, "health.probe_targets[0]", Rule::LooksLikeKeyMaterial);
            let mut cfg = config();
            let sink = cfg.alerts.sinks.remove("phone").unwrap();
            cfg.alerts.sinks.insert(value.clone(), sink);
            let errors = rejects(cfg, "alerts.sinks.<redacted>", Rule::LooksLikeKeyMaterial);
            assert!(errors.iter().all(|e| !format!("{e:?}").contains(&key)));
            let error = parse_site(&format!("\"{value}\" = 1\n{FIXTURE}")).unwrap_err();
            assert_eq!(error.path, "<redacted>");
        }
    }
}

#[test]
#[allow(clippy::unwrap_used)]
fn heartbeat_interval_bounds() {
    for (value, valid) in [("9s", false), ("10s", true), ("1h", true), ("3601s", false)] {
        let cfg =
            parse_site(&FIXTURE.replace("interval = \"60s\"", &format!("interval = \"{value}\"")))
                .unwrap();
        let result = validate(cfg);
        assert_eq!(result.is_ok(), valid, "{value}: {result:?}");
    }
}

#[test]
#[allow(clippy::unwrap_used)]
fn alert_qualification_grace_defaults_and_bounds() {
    let text = include_str!("fixtures/site-m2.toml");
    let cfg = parse_site(text).unwrap();
    assert_eq!(cfg.alerts.fail_closed_grace_seconds, 30);
    for seconds in [0, 1, 30, 300, 301] {
        let mut cfg = cfg.clone();
        cfg.alerts.fail_closed_grace_seconds = seconds;
        assert_eq!(validate(cfg).is_ok(), (1..=300).contains(&seconds));
    }
}
