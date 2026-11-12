//! Safety checks. Release restrictions are grouped separately for later lifting.

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use ipnet::Ipv4Net;

use super::{
    Rule, ValidationError, child,
    model::{Gateway, HealthSettings, Policy, SiteConfig},
    network::{client_prefix, global_v6, https_host, https_ip, public_v4},
    types::{
        DurationStr, PublicKey, SecretKind, SecretName, contains_key, id_chars, valid_exit_ifname,
        valid_id, valid_ifname,
    },
    validated::{self, ValidatedSite},
};

// WireGuard REKEY_AFTER_TIME permits a healthy handshake to age by a full
// rekey interval after keepalive, plus scheduling/network slack.
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const HANDSHAKE_SLACK: Duration = Duration::from_secs(30);
const MIN_HANDSHAKE_STALE: Duration = REKEY_AFTER_TIME.saturating_add(HANDSHAKE_SLACK);

#[derive(Default)]
struct Errors(Vec<ValidationError>);
impl Errors {
    fn check(&mut self, valid: bool, path: &str, rule: Rule) {
        if !valid {
            self.0.push(ValidationError {
                path: path.into(),
                rule,
            });
        }
    }
    fn duration(&mut self, value: &DurationStr, path: &str) {
        self.check(value.duration().is_ok(), path, Rule::InvalidDuration);
    }
    fn secret(&mut self, value: &SecretName, path: &str, kind: SecretKind) {
        self.check(value.kind() == kind, path, Rule::SecretKindMismatch);
        self.check(value.valid(), path, Rule::InvalidSecretRef);
    }
    fn public_key(&mut self, value: &PublicKey, path: &str) {
        self.check(value.bytes().is_ok(), path, Rule::InvalidPublicKey);
    }
    fn port(&mut self, port: u32, path: &str) {
        self.check((1..=65535).contains(&port), path, Rule::InvalidPort);
    }
    fn mtu(&mut self, mtu: u32, path: &str) {
        self.check((576..=65535).contains(&mtu), path, Rule::InvalidMtu);
    }
    fn endpoint(&mut self, text: &str, path: &str) {
        self.check(
            !text.contains('%')
                && text
                    .parse::<SocketAddr>()
                    .is_ok_and(|a| a.port() > 0 && super::valid_endpoint_ip(a.ip())),
            path,
            Rule::InvalidEndpoint,
        );
    }
    fn address(&mut self, text: &str, path: &str) -> Option<Ipv4Net> {
        let value = text.parse().ok();
        self.check(value.is_some(), path, Rule::InvalidAddress);
        value
    }
}

/// Checks every invariant and returns all failures without echoing input values.
///
/// The returned site owns immutable, typed renderer inputs. R2 sections and M2
/// topology restrictions are rejected even when their contents would be unused.
/// The suspect and active probe intervals in §8 have no R1 config fields:
/// both intervals are constants, so there is no interval comparison here.
///
/// # Errors
/// Returns every independent semantic failure with its exact field path and rule.
#[allow(clippy::too_many_lines)]
pub fn validate(cfg: SiteConfig) -> Result<ValidatedSite, Vec<ValidationError>> {
    let mut errors = Errors::default();
    errors.check(cfg.schema == 1, "schema", Rule::UnsupportedSchema);
    errors.check(
        (1..=64).contains(&cfg.site.name.chars().count())
            && cfg.site.name.chars().all(|c| !c.is_control()),
        "site.name",
        Rule::InvalidSiteName,
    );
    release_restrictions(&cfg, &mut errors);
    match serde_json::to_value(&cfg) {
        Ok(value) => lint_keys(&value, "", &mut errors),
        Err(_) => errors.check(false, "", Rule::KeyLintFailed),
    }
    map_ids(&cfg, &mut errors);

    for (id, identity) in &cfg.identities {
        let path = child("identities", id);
        errors.public_key(&identity.public_key, &child(&path, "public_key"));
        errors.secret(
            &identity.private_key_ref,
            &child(&path, "private_key_ref"),
            SecretKind::Wg,
        );
        errors.port(identity.listen_port, &child(&path, "listen_port"));
    }
    let mut identities = BTreeSet::new();
    for (id, gw) in &cfg.gateways {
        let path = child("gateways", id.as_str());
        errors.check(valid_id(id.as_str()), &path, Rule::InvalidId);
        errors.check(
            gw.netns == "scupper",
            &child(&path, "netns"),
            Rule::InvalidNamespace,
        );
        errors.endpoint(&gw.endpoint, &child(&path, "endpoint"));
        let client_path = child(&path, "client_tunnel");
        let client = &gw.client_tunnel;
        let identity_path = child(&client_path, "identity");
        errors.check(
            cfg.identities.contains_key(&client.identity),
            &identity_path,
            Rule::UnknownIdentity,
        );
        errors.check(
            identities.insert(&client.identity),
            &identity_path,
            Rule::IdentityShared,
        );
        if let Some(net) = errors.address(&client.address4, &child(&client_path, "address4")) {
            errors.check(
                client_prefix(net),
                &child(&client_path, "address4"),
                Rule::InvalidClientPrefix,
            );
            client_overlaps(&cfg, net, &child(&client_path, "address4"), &mut errors);
        }
        errors.check(
            !gw.uplinks.is_empty(),
            &child(&path, "uplinks"),
            Rule::EmptyUplinks,
        );
        peer_keys(&cfg, id, gw, &path, &mut errors);
        errors.mtu(client.mtu, &child(&client_path, "mtu"));
        interfaces(gw, &path, &mut errors);
        exits(gw, &cfg.health, &path, &mut errors);
        if let Some(api) = &gw.api {
            errors.port(api.port, &child(&path, "api.port"));
        }
        if let Some(dns) = &gw.dns {
            errors.check(
                dns.block_dot,
                &child(&path, "dns.block_dot"),
                Rule::BlockDotRequired,
            );
        }
        policy(&cfg.policy, gw, &mut errors);
    }
    errors.check(
        cfg.gateways.len() == 1 && cfg.gateways.contains_key(&cfg.site.primary),
        "site.primary",
        Rule::PrimaryGatewayMismatch,
    );
    // Check policy cardinality independently, including configurations with no gateways.
    errors.check(
        !cfg.policy.exits.is_empty(),
        "policy.exits",
        Rule::EmptyPolicy,
    );
    let mut policy_ids = BTreeSet::new();
    for (i, id) in cfg.policy.exits.iter().enumerate() {
        errors.check(
            policy_ids.insert(id),
            &format!("policy.exits[{i}]"),
            Rule::DuplicatePolicyExit,
        );
    }
    errors.duration(&cfg.policy.failback_hold, "policy.failback_hold");
    errors.duration(&cfg.policy.min_dwell, "policy.min_dwell");
    errors.check(
        (30..=300).contains(&cfg.policy.initial_qualification_seconds),
        "policy.initial_qualification_seconds",
        Rule::InvalidInitialQualification,
    );
    health(&cfg, &mut errors);
    devices(&cfg, &mut errors);
    for (id, sink) in &cfg.alerts.sinks {
        errors.secret(
            sink.url_ref(),
            &child(&child("alerts.sinks", id), "url_ref"),
            SecretKind::Url,
        );
    }
    if let Some(heartbeat) = &cfg.heartbeat {
        errors.secret(&heartbeat.url_ref, "heartbeat.url_ref", SecretKind::Url);
        errors.duration(&heartbeat.interval, "heartbeat.interval");
        if let Ok(interval) = heartbeat.interval.duration() {
            errors.check(
                (std::time::Duration::from_secs(10)..=std::time::Duration::from_secs(3600))
                    .contains(&interval),
                "heartbeat.interval",
                Rule::InvalidHeartbeatInterval,
            );
        }
    }
    if !errors.0.is_empty() {
        return Err(errors.0);
    }
    // Construction repeats only infallible conversions on checked data; using
    // Option here keeps the safety boundary panic-free if a future check drifts.
    validated::build(cfg).ok_or_else(|| {
        vec![ValidationError {
            path: String::new(),
            rule: Rule::InvalidAddress,
        }]
    })
}

// M2-only restrictions: lift each here when the corresponding milestone lands.
fn release_restrictions(cfg: &SiteConfig, errors: &mut Errors) {
    for (path, value) in [
        ("groups", &cfg.groups),
        ("policies", &cfg.policies),
        ("allow", &cfg.allow),
        ("providers", &cfg.providers),
    ] {
        errors.check(value.is_none(), path, Rule::NotSupportedInThisRelease);
    }
    errors.check(
        cfg.gateways.len() == 1,
        "gateways",
        Rule::NotSupportedInThisRelease,
    );
    errors.check(
        cfg.policy.exits.len() == 1,
        "policy.exits",
        Rule::NotSupportedInThisRelease,
    );
    for (id, gw) in &cfg.gateways {
        let path = child("gateways", id.as_str());
        errors.check(
            gw.exits.len() == 1,
            &child(&path, "exits"),
            Rule::NotSupportedInThisRelease,
        );
        errors.check(
            gw.client_tunnel.address6.is_none(),
            &child(&path, "client_tunnel.address6"),
            Rule::NotSupportedInThisRelease,
        );
        for (i, exit) in gw.exits.iter().enumerate() {
            let path = format!("{path}.exits[{i}]");
            errors.check(
                exit.provider == "proton",
                &child(&path, "provider"),
                Rule::NotSupportedInThisRelease,
            );
            errors.check(
                exit.enabled,
                &child(&path, "enabled"),
                Rule::NotSupportedInThisRelease,
            );
            errors.check(
                exit.address6.is_none(),
                &child(&path, "address6"),
                Rule::NotSupportedInThisRelease,
            );
        }
    }
    for (id, device) in &cfg.devices {
        errors.check(
            device.address6.is_none(),
            &child(&child("devices", id), "address6"),
            Rule::NotSupportedInThisRelease,
        );
    }
}

fn interfaces(gw: &Gateway, path: &str, errors: &mut Errors) {
    let mut names = BTreeSet::new();
    let mut check = |name: &str, path: String, exit: bool| {
        errors.check(
            valid_ifname(name) && (exit || (name != "lo" && !name.starts_with("ex-"))),
            &path,
            Rule::InvalidIfname,
        );
        errors.check(
            names.insert(name.to_owned()),
            &path,
            Rule::InterfaceConflict,
        );
    };
    for (i, uplink) in gw.uplinks.iter().enumerate() {
        check(uplink, format!("{path}.uplinks[{i}]"), false);
    }
    check(
        &gw.client_tunnel.ifname,
        child(path, "client_tunnel.ifname"),
        false,
    );
    for (i, exit) in gw.exits.iter().enumerate() {
        check(&exit.ifname, format!("{path}.exits[{i}].ifname"), true);
    }
}

#[allow(clippy::too_many_lines)]
fn exits(gw: &Gateway, health: &HealthSettings, path: &str, errors: &mut Errors) {
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for (i, exit) in gw.exits.iter().enumerate() {
        let path = format!("{path}.exits[{i}]");
        errors.check(
            valid_id(exit.id.as_str()),
            &child(&path, "id"),
            Rule::InvalidId,
        );
        errors.check(
            ids.insert(&exit.id),
            &child(&path, "id"),
            Rule::DuplicateExitId,
        );
        let name = exit.name.as_str();
        errors.check(
            exit.name.is_valid(),
            &child(&path, "name"),
            Rule::InvalidExitName,
        );
        errors.check(
            names.insert(name.to_lowercase()),
            &child(&path, "name"),
            Rule::DuplicateExitName,
        );
        errors.check(
            !gw.exits
                .iter()
                .enumerate()
                .any(|(j, other)| i != j && name.to_lowercase() == other.id.as_str()),
            &child(&path, "name"),
            Rule::ExitNameMatchesId,
        );
        for (i, tag) in exit.tags.iter().enumerate() {
            errors.check(
                id_chars(tag.as_str()),
                &format!("{path}.tags[{i}]"),
                Rule::InvalidTag,
            );
        }
        errors.check(
            valid_exit_ifname(&exit.ifname),
            &child(&path, "ifname"),
            Rule::ExitIfnamePrefix,
        );
        errors.secret(
            &exit.private_key_ref,
            &child(&path, "private_key_ref"),
            SecretKind::Wg,
        );
        if let Some(reference) = &exit.preshared_key_ref {
            errors.secret(
                reference,
                &child(&path, "preshared_key_ref"),
                SecretKind::Wg,
            );
        }
        errors.public_key(&exit.peer_public_key, &child(&path, "peer_public_key"));
        errors.endpoint(&exit.endpoint, &child(&path, "endpoint"));
        if let Some(net) = errors.address(&exit.address4, &child(&path, "address4")) {
            errors.check(
                net.prefix_len() == 32,
                &child(&path, "address4"),
                Rule::ExitHostPrefix,
            );
        }
        errors.check(
            !exit.dns.is_empty(),
            &child(&path, "dns"),
            Rule::EmptyDnsServers,
        );
        for (i, dns) in exit.dns.iter().enumerate() {
            let path = format!("{path}.dns[{i}]");
            match dns.parse::<IpAddr>() {
                Ok(IpAddr::V6(_)) => errors.check(false, &path, Rule::NotSupportedInThisRelease),
                Ok(IpAddr::V4(ip)) => errors.check(
                    !ip.is_unspecified()
                        && !ip.is_loopback()
                        && !ip.is_multicast()
                        && !ip.is_broadcast(),
                    &path,
                    Rule::InvalidDnsServer,
                ),
                Err(_) => errors.check(false, &path, Rule::InvalidDnsServer),
            }
        }
        errors.duration(&exit.keepalive, &child(&path, "keepalive"));
        if let Ok(keepalive) = exit.keepalive.duration() {
            errors.check(
                (1..=65535).contains(&keepalive.as_secs())
                    && health
                        .handshake_stale
                        .duration()
                        .is_ok_and(|stale| keepalive + REKEY_AFTER_TIME + HANDSHAKE_SLACK <= stale),
                &child(&path, "keepalive"),
                Rule::InvalidKeepalive,
            );
        }
        errors.mtu(exit.mtu, &child(&path, "mtu"));
    }
}
fn policy(policy: &Policy, gw: &Gateway, errors: &mut Errors) {
    for (i, id) in policy.exits.iter().enumerate() {
        let path = format!("policy.exits[{i}]");
        match gw.exits.iter().find(|exit| &exit.id == id) {
            None => errors.check(false, &path, Rule::UnknownExit),
            Some(exit) => errors.check(exit.enabled, &path, Rule::DisabledExit),
        }
    }
}

fn devices(cfg: &SiteConfig, errors: &mut Errors) {
    let mut addresses = BTreeSet::new();
    for (id, device) in &cfg.devices {
        let path = child("devices", id);
        errors.public_key(&device.public_key, &child(&path, "public_key"));
        errors.check(
            cfg.users.contains_key(&device.user),
            &child(&path, "user"),
            Rule::UnknownUser,
        );
        if let Some(hash) = &device.api_token_sha256 {
            errors.check(
                hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
                &child(&path, "api_token_sha256"),
                Rule::InvalidTokenHash,
            );
        }
        let address_path = child(&path, "address4");
        let address = errors.address(&device.address4, &address_path);
        if let Some(address) = address {
            errors.check(
                address.prefix_len() == 32,
                &address_path,
                Rule::DeviceHostPrefix,
            );
            errors.check(
                addresses.insert(address.addr()),
                &address_path,
                Rule::DuplicateDeviceAddress,
            );
            // Provider-side overlaps are forbidden even for gateways on which the
            // device is not installed; the site remains safe when it moves.
            let overlap = cfg.gateways.values().flat_map(|g| &g.exits).any(|e| {
                e.address4
                    .parse::<Ipv4Net>()
                    .is_ok_and(|net| overlaps(address, net))
                    || e.dns.iter().any(|dns| {
                        dns.parse::<Ipv4Addr>()
                            .is_ok_and(|ip| address.contains(&ip))
                    })
            });
            errors.check(!overlap, &address_path, Rule::DeviceAddressOverlap);
        }
        errors.check(
            !device.gateways.is_empty(),
            &child(&path, "gateways"),
            Rule::EmptyDeviceGateways,
        );
        let mut gateways = BTreeSet::new();
        for (i, id) in device.gateways.iter().enumerate() {
            let gateway_path = format!("{path}.gateways[{i}]");
            errors.check(
                gateways.insert(id),
                &gateway_path,
                Rule::DuplicateDeviceGateway,
            );
            match cfg.gateways.get(id) {
                None => errors.check(false, &gateway_path, Rule::UnknownGateway),
                Some(gw) => {
                    if let (Some(address), Ok(client)) =
                        (address, gw.client_tunnel.address4.parse::<Ipv4Net>())
                    {
                        errors.check(
                            client.contains(&address.network())
                                && client.contains(&address.broadcast())
                                && address.addr() != client.network()
                                && address.addr() != client.broadcast(),
                            &address_path,
                            Rule::DeviceOutsideClientPrefix,
                        );
                        errors.check(
                            address.addr() != client.addr(),
                            &address_path,
                            Rule::DeviceAddressOverlap,
                        );
                    }
                }
            }
        }
    }
}
fn overlaps(a: Ipv4Net, b: Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

fn health(cfg: &SiteConfig, errors: &mut Errors) {
    let health = &cfg.health;
    errors.duration(&health.handshake_stale, "health.handshake_stale");
    errors.duration(&health.failover_grace, "health.failover_grace");
    if let Ok(stale) = health.handshake_stale.duration() {
        errors.check(
            stale >= MIN_HANDSHAKE_STALE,
            "health.handshake_stale",
            Rule::InvalidHandshakeStale,
        );
    }
    if let (Ok(grace), Ok(stale)) = (
        health.failover_grace.duration(),
        health.handshake_stale.duration(),
    ) {
        errors.check(
            grace < stale,
            "health.failover_grace",
            Rule::FailoverGraceNotLessThanHandshakeStale,
        );
    }
    errors.check(
        health.route_probe_dst4.parse::<Ipv4Addr>().is_ok(),
        "health.route_probe_dst4",
        Rule::InvalidAddress,
    );
    errors.check(
        health.route_probe_dst6.parse::<Ipv6Addr>().is_ok(),
        "health.route_probe_dst6",
        Rule::InvalidAddress,
    );
    errors.check(
        health
            .route_probe_dst4
            .parse::<Ipv4Addr>()
            .is_ok_and(public_v4),
        "health.route_probe_dst4",
        Rule::InvalidRouteProbe,
    );
    errors.check(
        health
            .route_probe_dst6
            .parse::<Ipv6Addr>()
            .is_ok_and(global_v6),
        "health.route_probe_dst6",
        Rule::InvalidRouteProbe,
    );
    errors.check(
        !health.probe_targets.is_empty(),
        "health.probe_targets",
        Rule::EmptyProbeTargets,
    );
    for (i, url) in health.probe_targets.iter().enumerate() {
        errors.check(
            valid_probe_url(cfg, url),
            &format!("health.probe_targets[{i}]"),
            Rule::InvalidProbeUrl,
        );
    }
    errors.check(
        valid_probe_url(cfg, &health.speed_test_url),
        "health.speed_test_url",
        Rule::InvalidProbeUrl,
    );
}
fn valid_probe_url(cfg: &SiteConfig, url: &str) -> bool {
    let Some(host) = https_host(url) else {
        return false;
    };
    let Ok(ip) = host.parse::<IpAddr>() else {
        return true;
    };
    let public = match ip {
        IpAddr::V4(ip) => public_v4(ip),
        IpAddr::V6(ip) => global_v6(ip),
    };
    public
        && !cfg.gateways.values().any(|gw| {
            let in_client_prefix = match ip {
                IpAddr::V4(ip) => gw
                    .client_tunnel
                    .address4
                    .parse::<Ipv4Net>()
                    .is_ok_and(|net| net.contains(&ip)),
                IpAddr::V6(_) => false,
            };
            in_client_prefix
                || gw.exits.iter().any(|exit| {
                    exit.address4
                        .parse::<Ipv4Net>()
                        .is_ok_and(|net| IpAddr::V4(net.addr()) == ip)
                        || exit.address6.as_ref().is_some_and(|address| {
                            address
                                .parse::<ipnet::Ipv6Net>()
                                .is_ok_and(|net| IpAddr::V6(net.addr()) == ip)
                        })
                })
        })
}

fn lint_keys(value: &serde_json::Value, path: &str, errors: &mut Errors) {
    match value {
        serde_json::Value::String(text) => {
            errors.check(!contains_key(text), path, Rule::LooksLikeKeyMaterial);
        }
        serde_json::Value::Array(values) => {
            for (i, value) in values.iter().enumerate() {
                lint_keys(value, &format!("{path}[{i}]"), errors);
            }
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                let next = child(path, key);
                errors.check(!contains_key(key), &next, Rule::LooksLikeKeyMaterial);
                // A checked SHA-256 digest is hex, though its alphabet also fits base64.
                let token_hash = matches!(
                    path.split('.').collect::<Vec<_>>().as_slice(),
                    ["devices", _]
                ) && key == "api_token_sha256"
                    && value
                        .as_str()
                        .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()));
                if !token_hash && (!value.is_string() || !public_key_field(path, key)) {
                    lint_keys(value, &next, errors);
                }
            }
        }
        _ => {}
    }
}

fn public_key_field(path: &str, key: &str) -> bool {
    let parts: Vec<_> = path.split('.').collect();
    match parts.as_slice() {
        ["identities" | "devices", _] => key == "public_key",
        ["gateways", _, exits] if exits.starts_with("exits[") && exits.ends_with(']') => {
            key == "peer_public_key"
        }
        _ => false,
    }
}

fn map_ids(cfg: &SiteConfig, errors: &mut Errors) {
    for (parent, ids) in [
        ("identities", cfg.identities.keys().collect::<Vec<_>>()),
        ("devices", cfg.devices.keys().collect()),
        ("users", cfg.users.keys().collect()),
        ("alerts.sinks", cfg.alerts.sinks.keys().collect()),
    ] {
        for id in ids {
            errors.check(valid_id(id), &child(parent, id), Rule::InvalidId);
        }
    }
}

fn client_overlaps(cfg: &SiteConfig, net: Ipv4Net, path: &str, errors: &mut Errors) {
    let contains = |ip: IpAddr| matches!(ip, IpAddr::V4(ip) if net.contains(&ip));
    let overlap = cfg.gateways.values().any(|gw| {
        gw.endpoint
            .parse::<SocketAddr>()
            .is_ok_and(|a| contains(a.ip()))
            || gw.exits.iter().any(|exit| {
                exit.address4
                    .parse::<Ipv4Net>()
                    .is_ok_and(|a| overlaps(net, a))
                    || exit
                        .endpoint
                        .parse::<SocketAddr>()
                        .is_ok_and(|a| contains(a.ip()))
                    || exit
                        .dns
                        .iter()
                        .any(|dns| dns.parse::<IpAddr>().is_ok_and(contains))
            })
    }) || cfg
        .health
        .route_probe_dst4
        .parse::<Ipv4Addr>()
        .is_ok_and(|ip| net.contains(&ip))
        || cfg
            .health
            .probe_targets
            .iter()
            .chain(std::iter::once(&cfg.health.speed_test_url))
            .any(|url| https_ip(url).is_some_and(contains));
    errors.check(!overlap, path, Rule::ClientPrefixOverlap);
    if let Ok(ip) = cfg.health.route_probe_dst4.parse::<Ipv4Addr>() {
        errors.check(
            !net.contains(&ip)
                && !cfg
                    .gateways
                    .values()
                    .flat_map(|g| &g.exits)
                    .any(|e| e.address4.parse::<Ipv4Net>().is_ok_and(|a| a.addr() == ip)),
            "health.route_probe_dst4",
            Rule::InvalidRouteProbe,
        );
    }
}

fn peer_keys(
    cfg: &SiteConfig,
    id: &super::GatewayId,
    gw: &Gateway,
    path: &str,
    errors: &mut Errors,
) {
    let mut keys = BTreeSet::new();
    if let Some(identity) = cfg.identities.get(&gw.client_tunnel.identity)
        && let Ok(key) = identity.public_key.bytes()
    {
        keys.insert(key);
    }
    for (i, exit) in gw.exits.iter().enumerate() {
        if let Ok(key) = exit.peer_public_key.bytes() {
            errors.check(
                keys.insert(key),
                &format!("{path}.exits[{i}].peer_public_key"),
                Rule::DuplicatePublicKey,
            );
        }
    }
    for (device_id, device) in &cfg.devices {
        if device.gateways.contains(id)
            && let Ok(key) = device.public_key.bytes()
        {
            errors.check(
                keys.insert(key),
                &child(&child("devices", device_id), "public_key"),
                Rule::DuplicatePublicKey,
            );
        }
    }
}
