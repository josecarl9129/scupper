//! Bounded secret input and value-free validation for gateway URL provisioning.
use scupper_core::config::valid_https_url;
use std::{
    fmt,
    io::{self, BufRead, Read, Write},
};
use zeroize::Zeroizing;

/// Validated URL and its deliberately limited public confirmation.
pub struct UrlValue {
    value: Zeroizing<Vec<u8>>,
    confirmation: String,
}
impl fmt::Debug for UrlValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UrlValue(<redacted>)")
    }
}
impl UrlValue {
    /// Validate an HTTPS URL without retaining invalid input in diagnostics.
    /// # Errors
    /// Returns a fixed message for invalid syntax or more than 4 KiB.
    pub fn url(value: &[u8]) -> Result<Self, &'static str> {
        let text = std::str::from_utf8(value).map_err(|_| "invalid HTTPS URL")?;
        if value.len() > 4096 || !valid_https_url(text) {
            return Err("invalid HTTPS URL (https, host, no userinfo, at most 4 KiB required)");
        }
        let authority = text
            .strip_prefix("https://")
            .ok_or("invalid HTTPS URL")?
            .split(['/', '?', '#'])
            .next()
            .ok_or("invalid HTTPS URL")?;
        // Exclude ports as well as the entire request target from confirmations.
        let host = if authority.starts_with('[') {
            authority
                .split_once(']')
                .map_or(authority, |(host, _)| host)
                .trim_start_matches('[')
        } else {
            authority.split(':').next().ok_or("invalid HTTPS URL")?
        };
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.into()
        };
        Ok(Self {
            value: Zeroizing::new(value.to_vec()),
            confirmation: format!("https://{host}/…"),
        })
    }

    /// Build a Telegram credential URL from separately supplied fields.
    /// # Errors
    /// Returns fixed messages for invalid fields or an oversized resulting URL.
    pub fn telegram(token: &[u8], chat: &[u8]) -> Result<Self, &'static str> {
        let token = std::str::from_utf8(token).map_err(|_| "invalid Telegram bot token")?;
        let chat = std::str::from_utf8(chat).map_err(|_| "invalid Telegram chat id")?;
        if !valid_telegram_token(token) {
            return Err("invalid Telegram bot token");
        }
        if !valid_telegram_chat(chat) {
            return Err("invalid Telegram chat id");
        }
        // Validate the total length before allocating the assembled credential.
        if token.len() + chat.len() + "https://api.telegram.org/bot/sendMessage?chat_id=".len()
            > 4096
        {
            return Err("Telegram URL exceeds 4 KiB");
        }
        let value = Zeroizing::new(format!(
            "https://api.telegram.org/bot{token}/sendMessage?chat_id={chat}"
        ));
        let mut result = Self::url(value.as_bytes())?;
        let digits = token
            .split(':')
            .next()
            .ok_or("invalid Telegram bot token")?;
        result.confirmation = format!(
            "telegram bot {}… chat {chat}",
            &digits[..digits.len().min(4)]
        );
        Ok(result)
    }

    /// Borrow credential bytes solely for the durable writer.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.value
    }

    /// Safe operator confirmation, excluding URL path, query and bot credential.
    #[must_use]
    pub fn confirmation(&self) -> &str {
        &self.confirmation
    }
}

/// Telegram token syntax: decimal bot id and at least 35 URL-safe characters.
#[must_use]
pub fn valid_telegram_token(token: &str) -> bool {
    token.split_once(':').is_some_and(|(id, key)| {
        !id.is_empty()
            && id.bytes().all(|b| b.is_ascii_digit())
            && key.len() >= 35
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    })
}

/// Telegram numeric chat id or an ASCII channel username.
#[must_use]
pub fn valid_telegram_chat(chat: &str) -> bool {
    if let Some(channel) = chat.strip_prefix('@') {
        !channel.is_empty()
            && channel
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    } else {
        let digits = chat.strip_prefix('-').unwrap_or(chat);
        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
    }
}

/// Read one bounded line; permit a final EOF in place of a newline.
/// All read failures have fixed, value-free diagnostics.
fn line(reader: &mut impl BufRead) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(4097));
    reader
        .take(4098)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| "secret input read failed")?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.len() > 4096 {
        return Err("secret input exceeds 4 KiB");
    }
    if bytes.is_empty() {
        return Err("secret input is empty");
    }
    Ok(bytes)
}

/// Read one URL line or two Telegram lines from a pipe, requiring EOF afterward.
/// # Errors
/// Rejects missing/extra lines, oversized input and invalid credentials.
pub fn read_stdin(reader: &mut impl BufRead, telegram: bool) -> Result<UrlValue, &'static str> {
    let first = line(reader)?;
    let value = if telegram {
        UrlValue::telegram(&first, &line(reader)?)?
    } else {
        UrlValue::url(&first)?
    };
    let mut extra = [0];
    let count = reader
        .read(&mut extra)
        .map_err(|_| "secret input read failed")?;
    extra.fill(0);
    if count != 0 {
        return Err("unexpected extra secret input");
    }
    Ok(value)
}

struct EchoGuard(rustix::termios::Termios);
impl Drop for EchoGuard {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(
            rustix::stdio::stdin(),
            rustix::termios::OptionalActions::Now,
            &self.0,
        );
    }
}

fn prompt(
    reader: &mut impl BufRead,
    label: &str,
    hidden: bool,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};
    let guard = if hidden {
        let original =
            tcgetattr(rustix::stdio::stdin()).map_err(|_| "cannot read terminal settings")?;
        let mut settings = original.clone();
        settings
            .local_modes
            .remove(LocalModes::ECHO | LocalModes::ECHONL | LocalModes::ICANON | LocalModes::ISIG);
        tcsetattr(rustix::stdio::stdin(), OptionalActions::Now, &settings)
            .map_err(|_| "cannot hide terminal input")?;
        Some(EchoGuard(original))
    } else {
        None
    };
    eprint!("{label}: ");
    io::stderr()
        .flush()
        .map_err(|_| "cannot write secret prompt")?;
    // In hidden mode read bytes ourselves: disabling ISIG lets Ctrl-C cancel
    // through this guard and restore echo instead of leaving the terminal hidden.
    let result = if hidden {
        hidden_line(reader)
    } else {
        line(reader)
    };
    drop(guard);
    if hidden {
        eprintln!();
    }
    result
}

fn hidden_line(reader: &mut impl BufRead) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut value = Zeroizing::new(Vec::with_capacity(4096));
    loop {
        let mut byte = [0];
        reader
            .read_exact(&mut byte)
            .map_err(|_| "secret input read failed")?;
        match byte[0] {
            b'\n' | b'\r' => return Ok(value),
            3 | 4 => return Err("secret input cancelled"),
            8 | 127 => {
                value.pop();
            }
            21 => value.clear(),
            b => {
                if value.len() == 4096 {
                    return Err("secret input exceeds 4 KiB");
                }
                value.push(b);
            }
        }
    }
}

/// Read from the terminal, hiding URL/token input and showing Telegram chat ids.
/// # Errors
/// Returns fixed diagnostics for failed terminal access, input or validation.
pub fn read_tty(telegram: bool) -> Result<UrlValue, &'static str> {
    let mut reader = io::stdin().lock();
    if telegram {
        let token = prompt(&mut reader, "Bot token", true)?;
        let chat = prompt(&mut reader, "Chat id", false)?;
        UrlValue::telegram(&token, &chat)
    } else {
        UrlValue::url(&prompt(&mut reader, "URL", true)?)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn https_uses_daemon_rules_and_limit() {
        for value in [
            "https://example.com",
            "https://hc-ping.example/fake-check?key=fake",
            "https://example.com:8443/path",
            "https://[2001:db8::1]/fake",
        ] {
            assert!(UrlValue::url(value.as_bytes()).is_ok());
        }
        for value in [
            "http://example.com/path",
            "https:///path",
            "https://user@example.com/path",
            "https://user:pass@example.com/path",
            "https://example.com/bad\n",
            "https://example.com/bad path",
            "https://example.com\\path",
            "https://example.com:0/path",
            "https://example.com:99999/path",
            "https://example.com\r",
            "https://example.com/\0",
        ] {
            assert!(UrlValue::url(value.as_bytes()).is_err());
        }
        let mut boundary = "https://example.com/".to_owned();
        boundary.extend(std::iter::repeat_n('x', 4096 - boundary.len()));
        assert!(UrlValue::url(boundary.as_bytes()).is_ok());
        assert!(read_stdin(&mut format!("{boundary}\n").as_bytes(), false).is_ok());
        boundary.push('x');
        assert!(UrlValue::url(boundary.as_bytes()).is_err());
        assert!(read_stdin(&mut boundary.as_bytes(), false).is_err());
        for value in [
            b"".as_slice(),
            b"https://example.com/\n\n",
            b"https://example.com/\r\n",
            b"\xff\n",
        ] {
            assert!(read_stdin(&mut &*value, false).is_err());
        }
    }

    #[test]
    fn telegram_field_forms_and_bounded_assembly() {
        let token = "00000000:FAKE_token_for_tests_only_00000000000";
        assert!(valid_telegram_token(token));
        for token in [
            "",
            "1234",
            ":abcdefghijklmnopqrstuvwxyz0123456789",
            "abcd:abcdefghijklmnopqrstuvwxyz0123456789",
            "0000:short",
            "0000:abcdefghijklmnopqrstuvwxyz01234567=",
            "0000:abcdefghijklmnopqrstuvwxyz01234567/",
            "0000:abcdefghijklmnopqrstuvwxyz01234567:bad",
        ] {
            assert!(!valid_telegram_token(token));
        }
        for chat in ["0", "-000000", "@fake_channel", "@FakeChannel_000"] {
            assert!(valid_telegram_chat(chat));
            let value = UrlValue::telegram(token.as_bytes(), chat.as_bytes()).unwrap();
            assert_eq!(
                value.confirmation(),
                format!("telegram bot 0000… chat {chat}")
            );
            assert_eq!(
                value.expose(),
                format!("https://api.telegram.org/bot{token}/sendMessage?chat_id={chat}")
                    .as_bytes()
            );
        }
        for chat in [
            "",
            "-",
            "--1",
            "+1",
            "@",
            "@bad-channel",
            "@bad/name",
            "@bad?key=1",
            "123 456",
            "１２３",
        ] {
            assert!(!valid_telegram_chat(chat));
        }
        let oversized = format!("0000:{}", "x".repeat(4096));
        assert!(UrlValue::telegram(oversized.as_bytes(), b"@fake_channel").is_err());
        assert!(read_stdin(&mut format!("{token}\n@fake_channel\n").as_bytes(), true).is_ok());
        assert!(read_stdin(&mut format!("{token}\n").as_bytes(), true).is_err());
        assert!(
            read_stdin(
                &mut format!("{token}\n@fake_channel\nextra").as_bytes(),
                true
            )
            .is_err()
        );
    }

    #[test]
    fn hidden_line_cancels_and_edits_without_echoing_input() {
        assert_eq!(
            &*hidden_line(&mut &b"abc\x7fd\x15fake\n"[..]).unwrap(),
            b"fake"
        );
        assert!(hidden_line(&mut &b"fake\x03"[..]).is_err());
        assert!(hidden_line(&mut &b"fake\x04"[..]).is_err());
    }
}
