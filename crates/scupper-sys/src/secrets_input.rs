//! Bounded secret input and value-free validation for gateway URL provisioning.
use super::valid_delivery_url;
use std::{
    fmt,
    io::{self, Read, Write},
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
        if value.len() > 4096 || !valid_delivery_url(text) {
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
        let mut value = Zeroizing::new(String::with_capacity(
            token.len() + chat.len() + "https://api.telegram.org/bot/sendMessage?chat_id=".len(),
        ));
        value.push_str("https://api.telegram.org/bot");
        value.push_str(token);
        value.push_str("/sendMessage?chat_id=");
        value.push_str(chat);
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
fn line(reader: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(4097));
    let mut byte = Zeroizing::new([0]);
    loop {
        let count = reader
            .read(&mut *byte)
            .map_err(|_| "secret input read failed")?;
        if count == 0 || byte[0] == b'\n' {
            break;
        }
        bytes.push(byte[0]);
        if bytes.len() > 4096 {
            break;
        }
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
pub fn read_stdin(reader: &mut impl Read, telegram: bool) -> Result<UrlValue, &'static str> {
    let first = line(reader)?;
    let value = if telegram {
        UrlValue::telegram(&first, &line(reader)?)?
    } else {
        UrlValue::url(&first)?
    };
    let mut extra = Zeroizing::new([0]);
    let count = reader
        .read(&mut *extra)
        .map_err(|_| "secret input read failed")?;
    extra.fill(0);
    if count != 0 {
        return Err("unexpected extra secret input");
    }
    Ok(value)
}

/// Disable core dumps before the process first reads a credential.
/// # Errors
/// Returns a fixed message if hardening cannot be applied.
pub fn disable_core_dumps() -> Result<(), &'static str> {
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|_| "cannot disable secret core dumps")?;
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|_| "cannot disable secret core dumps")
}

/// Duplicate stdin without using the unzeroized global buffered reader.
/// # Errors
/// Returns a fixed message if stdin cannot be duplicated.
pub fn stdin_reader() -> Result<std::fs::File, &'static str> {
    rustix::io::dup(rustix::stdio::stdin())
        .map(std::fs::File::from)
        .map_err(|_| "cannot open secret input")
}

// Keep one listener alive for the process: signal-hook does not restore default
// dispositions when a subscription is removed. Between prompts the listener
// still applies the default action, without touching terminal settings.
mod prompt_signals {
    use rustix::termios::{OptionalActions, Termios, tcsetattr};
    use signal_hook::{
        consts::{SIGHUP, SIGINT, SIGTERM},
        iterator::Signals,
    };
    use std::sync::{Arc, Mutex, OnceLock};

    type Saved = Arc<Mutex<Option<Termios>>>;
    static SAVED: OnceLock<Result<Saved, &'static str>> = OnceLock::new();
    const ERROR: &str = "cannot protect secret terminal settings";

    fn listen() -> Result<Saved, &'static str> {
        // Linux exposes dispositions safely through procfs. Inspect before
        // registering anything so inherited SIG_IGN (including nohup) survives.
        let status = std::fs::read_to_string("/proc/self/status").map_err(|_| ERROR)?;
        let ignored = status
            .lines()
            .find_map(|line| line.strip_prefix("SigIgn:"))
            .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
            .ok_or(ERROR)?;
        let mut signals = Signals::new(
            [SIGHUP, SIGINT, SIGTERM]
                .into_iter()
                .filter(|number| ignored & (1_u64 << (number - 1)) == 0),
        )
        .map_err(|_| ERROR)?;
        let saved: Saved = Arc::new(Mutex::new(None));
        let thread_saved = Arc::clone(&saved);
        std::thread::Builder::new()
            .name("secret-terminal".into())
            .spawn(move || {
                for number in signals.forever() {
                    // Serialize restoration with hiding and normal guard cleanup.
                    let settings = thread_saved
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if let Some(original) = settings.as_ref() {
                        let _ = tcsetattr(rustix::stdio::stdin(), OptionalActions::Now, original);
                    }
                    let _ = signal_hook::low_level::emulate_default_handler(number);
                }
            })
            .map_err(|_| ERROR)?;
        Ok(saved)
    }

    pub(super) struct Guard {
        saved: Saved,
    }
    impl Guard {
        pub(super) fn hide(original: Termios, hidden: &Termios) -> Result<Self, &'static str> {
            let saved = SAVED.get_or_init(listen).as_ref().map_err(|error| *error)?;
            let mut settings = saved.lock().map_err(|_| ERROR)?;
            if settings.is_some() {
                return Err("secret prompt already active");
            }
            tcsetattr(rustix::stdio::stdin(), OptionalActions::Now, hidden)
                .map_err(|_| "cannot hide terminal input")?;
            *settings = Some(original);
            Ok(Self {
                saved: Arc::clone(saved),
            })
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            let mut settings = self
                .saved
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(original) = settings.take() {
                let _ = tcsetattr(rustix::stdio::stdin(), OptionalActions::Now, &original);
            }
        }
    }
}

fn prompt(
    reader: &mut impl Read,
    label: &str,
    hidden: bool,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    use rustix::termios::{LocalModes, tcgetattr};
    let guard = if hidden {
        let original =
            tcgetattr(rustix::stdio::stdin()).map_err(|_| "cannot read terminal settings")?;
        let mut settings = original.clone();
        settings
            .local_modes
            .remove(LocalModes::ECHO | LocalModes::ECHONL | LocalModes::ICANON | LocalModes::ISIG);
        Some(prompt_signals::Guard::hide(original, &settings)?)
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

fn hidden_line(reader: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut value = Zeroizing::new(Vec::with_capacity(4096));
    loop {
        let mut byte = Zeroizing::new([0]);
        reader
            .read_exact(&mut *byte)
            .map_err(|_| "secret input read failed")?;
        match byte[0] {
            b'\n' | b'\r' => return Ok(value),
            3 | 4 => return Err("secret input cancelled"),
            8 | 127 => {
                if let Some(last) = value.last_mut() {
                    *last = 0;
                }
                value.pop();
            }
            21 => {
                value.fill(0);
                value.clear();
            }
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
    let mut reader = stdin_reader()?;
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
            "https://example.com:443/path",
        ] {
            assert!(UrlValue::url(value.as_bytes()).is_ok());
        }
        for value in [
            "https://example.com:8443/path",
            "https://[2001:db8::1]/fake",
            "https://example.com/path#fragment",
            "https://example.com/é",
            "https://example.com/?é",
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
        boundary.extend(std::iter::repeat_n(
            'x',
            crate::probe::MAX_TARGET_BYTES - crate::heartbeat::MAX_SUFFIX_BYTES - 1,
        ));
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
        let too_long_for_delivery = format!("0000:{}", "x".repeat(2048));
        assert!(UrlValue::telegram(too_long_for_delivery.as_bytes(), b"@fake_channel").is_err());
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
    fn stdin_line_limit_is_independent_of_url_validation() {
        let boundary = vec![b'x'; 4096];
        assert_eq!(&*line(&mut boundary.as_slice()).unwrap(), &boundary);
        let mut newline = boundary.clone();
        newline.push(b'\n');
        assert_eq!(&*line(&mut newline.as_slice()).unwrap(), &boundary);
        let oversized = vec![b'x'; 4097];
        assert_eq!(
            line(&mut oversized.as_slice()).unwrap_err(),
            "secret input exceeds 4 KiB"
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
