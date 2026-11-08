//! Pure canonical ruleset equality and fingerprint tests.

use std::error::Error;

use scupper_core::canon::{canonicalize, fingerprint};
use serde_json::json;

const NFT_LIVE: &str = include_str!("../../scupper-sys/tests/fixtures/ubuntu-24.04/nft-live.json");
const NFT_WANT: &str = include_str!("../../scupper-sys/tests/fixtures/ubuntu-24.04/nft-want.json");
const NFT_EXTRA: &str =
    include_str!("../../scupper-sys/tests/fixtures/ubuntu-24.04/case-06-nft.json");

#[test]
fn captured_host_and_netns_rulesets_are_equal_v04() -> Result<(), Box<dyn Error>> {
    let live = canonicalize(NFT_LIVE)?;
    let want = canonicalize(NFT_WANT)?;
    assert_eq!(live, want);
    assert_eq!(fingerprint(&live)?, fingerprint(&want)?);
    Ok(())
}

#[test]
fn captured_unsafe_rulesets_differ_from_want() -> Result<(), Box<dyn Error>> {
    let want = canonicalize(NFT_WANT)?;
    for (case, json) in [
        ("06: extra accept", NFT_EXTRA),
        (
            "07: unconstrained ct",
            include_str!("../../scupper-sys/tests/fixtures/ubuntu-24.04/case-07-nft.json"),
        ),
        (
            "08: foreign ip table with dup",
            include_str!("../../scupper-sys/tests/fixtures/ubuntu-24.04/case-08-nft.json"),
        ),
        (
            "09: netdev fwd",
            include_str!("../../scupper-sys/tests/fixtures/ubuntu-24.04/case-09-nft.json"),
        ),
    ] {
        let live = canonicalize(json)?;
        assert_ne!(live, want, "case {case}");
        assert_ne!(fingerprint(&live)?, fingerprint(&want)?, "case {case}");
    }
    Ok(())
}

#[test]
fn canonical_metadata_and_key_order() -> Result<(), Box<dyn Error>> {
    let input = r#"{"nftables":[{"metainfo":{"version":"1.0.9"}},{"table":{"family":"inet","name":"scupper","handle":10}},{"rule":{"handle":2,"expr":[{"counter":{"packets":20,"bytes":1234,"name":"named","handle":3}},{"accept":null}],"packets":99}}]}"#;
    let expected = json!({"nftables": [{"table":{"family":"inet","name":"scupper"}},{"rule":{"expr":[{"counter":{"name":"named"}},{"accept":null}],"packets":99}}]});
    assert_eq!(canonicalize(input)?, expected);
    assert_eq!(
        canonicalize(r#"{"nftables":[{"rule":{"expr":[{"counter":{"packets":1,"bytes":2}}]}}]}"#)?,
        json!({"nftables":[{"rule":{"expr":[{"counter":{}}]}}]})
    );
    let reordered = r#"{"nftables":[{"table":{"name":"scupper","family":"inet"}},{"rule":{"packets":99,"expr":[{"counter":{"name":"named"}},{"accept":null}]}}]}"#;
    assert_eq!(
        fingerprint(&canonicalize(input)?)?,
        fingerprint(&canonicalize(reordered)?)?
    );
    for input in [
        "",
        "garbage",
        "[]",
        "{}",
        r#"{"nftables":{}}"#,
        r#"{"nftables":[1]}"#,
    ] {
        assert!(canonicalize(input).is_err());
    }
    Ok(())
}
