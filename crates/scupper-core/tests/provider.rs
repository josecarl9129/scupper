//! Provider parser acceptance, rejection and redaction properties.
#![allow(clippy::unwrap_used)]
use proptest::prelude::*;
use scupper_core::config::{
    PublicKey,
    provider::{MAX_PROVIDER_BYTES, parse_provider},
};
const PRIVATE: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
const PSK: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
const PUBLIC: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";
fn input() -> String {
    format!(
        "# Name = CH#1234\n# NetShield = 1\n[Interface]\nPrivateKey = {PRIVATE}\nAddress = 192.0.2.2/32\nDNS = 192.0.2.53\n[Peer]\nPublicKey = {PUBLIC}\nEndpoint = 203.0.113.1:51820\nAllowedIPs = 0.0.0.0/0\n"
    )
}
#[test]
fn accepted_forms() {
    for text in [
        input(),
        input().replace("192.0.2.2/32", "192.0.2.2"),
        input().replace("192.0.2.2/32", "192.0.2.2, 2001:db8::2"),
        input()
            .replace("192.0.2.2/32", "192.0.2.2/32, 2001:db8::2/128")
            .replace("192.0.2.53", "192.0.2.53, 2001:db8::53")
            .replace("0.0.0.0/0", "::/0, 0.0.0.0/0")
            .replace("203.0.113.1:51820", "[2001:db8::1]:51820"),
        input().replace("[Peer]", "MTU = 1280\n[Peer]")
            + &format!("PresharedKey = {PSK}\nPersistentKeepalive = 0\n"),
        input().replace("[Peer]", "MTU = 1500\n[Peer]") + "PersistentKeepalive = 65535\n",
        input()
            .replace(PRIVATE, PRIVATE.trim_end_matches('='))
            .replace(PUBLIC, PUBLIC.trim_end_matches('=')),
    ] {
        let parsed = parse_provider(&text).unwrap();
        assert_eq!(parsed.private_key(), PRIVATE.as_bytes());
        assert_eq!(parsed.suggested_id.as_str(), "ch-1234");
        assert_eq!(parsed.suggested_name.as_str(), "Switzerland");
        assert_eq!(parsed.netshield, Some(1));
        let display = format!(
            "{:?} {} {:?}",
            parsed,
            parsed.summary(&PublicKey(PUBLIC.into())),
            parsed.summary(&PublicKey(PUBLIC.into()))
        );
        for key in [PRIVATE, PSK] {
            assert!(!display.contains(key));
        }
    }
    let mut full = input();
    full.extend(std::iter::repeat_n(' ', MAX_PROVIDER_BYTES - full.len()));
    assert!(parse_provider(&full).is_ok());
    full.push(' ');
    assert!(parse_provider(&full).is_err());
}
#[test]
fn every_refused_key_and_duplicate() {
    for key in [
        "PostUp",
        "PreUp",
        "PostDown",
        "PreDown",
        "Table",
        "SaveConfig",
        "FwMark",
        "ListenPort",
        "Unknown",
        PRIVATE,
    ] {
        for section in ["[Interface]", "[Peer]"] {
            let text = input().replace(section, &format!("{section}\n{key} = {PRIVATE}"));
            let error = parse_provider(&text).unwrap_err();
            assert!(!format!("{error:?} {error}").contains(PRIVATE));
            assert!(error.to_string().contains("<redacted>"));
        }
    }
    for (section, key, value) in [
        ("[Interface]", "PrivateKey", PRIVATE),
        ("[Interface]", "Address", "192.0.2.2/32"),
        ("[Interface]", "DNS", "192.0.2.53"),
        ("[Interface]", "MTU", "1420"),
        ("[Peer]", "PublicKey", PUBLIC),
        ("[Peer]", "Endpoint", "203.0.113.1:1"),
        ("[Peer]", "AllowedIPs", "0.0.0.0/0"),
        ("[Peer]", "PresharedKey", PSK),
        ("[Peer]", "PersistentKeepalive", "25"),
    ] {
        let mut text = input();
        if matches!(key, "MTU" | "PresharedKey" | "PersistentKeepalive") {
            text = text.replace(section, &format!("{section}\n{key} = {value}"));
        }
        text = text.replace(section, &format!("{section}\n{key} = {value}"));
        assert!(parse_provider(&text).unwrap_err().to_string().contains(key));
    }
}
#[test]
fn refused_values_and_structure() {
    assert!(parse_provider(&input().replace(PUBLIC, PRIVATE)).is_err());
    assert!(
        parse_provider(&(input().replace(PUBLIC, PSK) + &format!("PresharedKey = {PSK}\n")))
            .is_err()
    );
    for (old, values) in [
        (
            PRIVATE,
            vec![
                "bad",
                "",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=",
                "AAAA",
            ],
        ),
        (PUBLIC, vec!["bad", "", "AAAA"]),
        (
            "192.0.2.2/32",
            vec![
                "192.0.2.2/24",
                "2001:db8::2/128",
                "192.0.2.1/32,192.0.2.2/32",
                "192.0.2.2/32,2001:db8::1/64",
                "192.0.2.2/32,2001:db8::1/128,2001:db8::2/128",
                "host/32",
            ],
        ),
        ("192.0.2.53", vec!["dns.example", "", "192.0.2.53,"]),
        (
            "203.0.113.1:51820",
            vec![
                "vpn.example:51820",
                "203.0.113.1:0",
                "203.0.113.1:65536",
                "203.0.113.1",
                "2001:db8::1:51820",
            ],
        ),
        (
            "0.0.0.0/0",
            vec![
                "::/0",
                "0.0.0.0/1",
                "0.0.0.0/0,0.0.0.0/0",
                "0.0.0.0/0,::/0,::/0",
                "0.0.0.0/0,192.0.2.0/24",
                "",
            ],
        ),
    ] {
        for value in values {
            assert!(
                parse_provider(&input().replace(old, value)).is_err(),
                "{old} -> {value}"
            );
        }
    }
    for extra in [
        "[Peer]\n",
        "[Interface]\n",
        "[Other]\n",
        "garbage\n",
        "PersistentKeepalive = -1\n",
        "PersistentKeepalive = 65536\n",
        "PresharedKey = bad\n",
    ] {
        assert!(parse_provider(&(input() + extra)).is_err());
    }
    for mtu in ["1279", "1501", "-1", "bad"] {
        assert!(
            parse_provider(&input().replace("[Peer]", &format!("MTU = {mtu}\n[Peer]"))).is_err()
        );
    }
    for required in [
        "PrivateKey",
        "Address",
        "DNS",
        "PublicKey",
        "Endpoint",
        "AllowedIPs",
    ] {
        let text = input()
            .lines()
            .filter(|s| !s.starts_with(required))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            parse_provider(&text)
                .unwrap_err()
                .to_string()
                .contains(required)
        );
    }
    for section in ["[Interface]", "[Peer]"] {
        assert!(parse_provider(&input().replace(section, "")).is_err());
    }
}
fn base64(bytes: &[u8; 32]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut bits = 0_u32;
    let mut count = 0;
    for byte in bytes {
        bits = (bits << 8) | u32::from(*byte);
        count += 8;
        while count >= 6 {
            count -= 6;
            out.push(char::from(ALPHABET[((bits >> count) & 63) as usize]));
        }
    }
    if count > 0 {
        out.push(char::from(ALPHABET[((bits << (6 - count)) & 63) as usize]));
    }
    out.push('=');
    out
}
proptest! {
    #[test]
    fn arbitrary_input_never_formats_secrets(junk in ".{0,18000}", raw in any::<[u8; 32]>(), psk in any::<[u8; 32]>(), placement in 0..5_u8) {
        let private = base64(&raw); let psk64 = base64(&psk);
        let mut text = input().replace(PRIVATE, &private) + &format!("PresharedKey = {psk64}\n");
        match placement {
            0 => text.push_str(&junk),
            1 => text = format!("{junk}\n{text}"),
            2 => text = text.replace("192.0.2.53", &junk),
            3 => text = text.replace("[Peer]", &format!("[{junk}]\n[Peer]")),
            _ => text = text.replace("Endpoint", &junk),
        }
        let formatted = match parse_provider(&text) {
            Ok(parsed) => format!("{parsed:?} {} {:?}", parsed.summary(&PublicKey(PUBLIC.into())), parsed.summary(&PublicKey(PUBLIC.into()))),
            Err(error) => format!("{error:?} {error}"),
        };
        for secret in [&private, &psk64] { prop_assert!(!formatted.contains(secret)); prop_assert!(!formatted.contains(secret.trim_end_matches('='))); }
        for secret in [raw, psk] { prop_assert!(!formatted.as_bytes().windows(secret.len()).any(|bytes| bytes == secret)); }
    }
}
