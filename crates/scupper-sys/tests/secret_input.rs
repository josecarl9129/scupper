//! Arbitrary input must never enter confirmations, errors or Debug output.
#![allow(clippy::unwrap_used)]
use proptest::prelude::*;
use scupper_sys::secrets::input::{UrlValue, read_stdin};

proptest! {
    #[test]
    fn arbitrary_input_has_only_fixed_errors_and_redacted_debug(input in prop::collection::vec(any::<u8>(), 0..9000), telegram in any::<bool>()) {
        let result = read_stdin(&mut input.as_slice(), telegram);
        let debug = format!("{result:?}");
        match result {
            Ok(value) => {
                prop_assert_eq!(debug, "Ok(UrlValue(<redacted>))");
                let text = std::str::from_utf8(value.expose()).unwrap();
                if telegram {
                    let (token, chat) = text.strip_prefix("https://api.telegram.org/bot").unwrap().split_once("/sendMessage?chat_id=").unwrap();
                    let id = token.split(':').next().unwrap();
                    prop_assert_eq!(value.confirmation(), format!("telegram bot {}… chat {chat}", &id[..id.len().min(4)]));
                } else {
                    let authority = text.strip_prefix("https://").unwrap().split(['/', '?', '#']).next().unwrap();
                    let host = if authority.starts_with('[') {
                        format!("{}]", authority.split(']').next().unwrap())
                    } else { authority.split(':').next().unwrap().into() };
                    prop_assert_eq!(value.confirmation(), format!("https://{host}/…"));
                }
            }
            Err(error) => {
                prop_assert!(matches!(error,
                    "secret input read failed" | "secret input exceeds 4 KiB" | "secret input is empty" | "invalid HTTPS URL" |
                    "invalid HTTPS URL (https, host, no userinfo, at most 4 KiB required)" | "invalid Telegram bot token" |
                    "invalid Telegram chat id" | "Telegram URL exceeds 4 KiB" | "unexpected extra secret input"));
                prop_assert_eq!(debug, format!("Err({error:?})"));
            }
        }
    }

    #[test]
    fn valid_url_targets_never_change_confirmation(path in "[a-zA-Z0-9/?=&%_-]{0,2000}") {
        let value = UrlValue::url(format!("https://example.com/{path}").as_bytes()).unwrap();
        prop_assert_eq!(value.confirmation(), "https://example.com/…");
        prop_assert_eq!(format!("{value:?}"), "UrlValue(<redacted>)");
    }

    #[test]
    fn valid_tokens_never_change_confirmation(key in "[a-zA-Z0-9_-]{35,300}", chat in "-?[0-9]{1,20}|@[a-zA-Z_]{1,32}") {
        let value = UrlValue::telegram(format!("00000000:{key}").as_bytes(), chat.as_bytes()).unwrap();
        prop_assert_eq!(value.confirmation(), format!("telegram bot 0000… chat {chat}"));
        prop_assert_eq!(format!("{value:?}"), "UrlValue(<redacted>)");
    }
}
