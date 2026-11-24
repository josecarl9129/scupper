//! Qualification-only inventories, traversal and findings; never a native review flag.
use crate::{
    decode::pfanchor::{self, Text},
    platform::SysError,
};
use std::{collections::BTreeSet, fmt::Write as _};

/// A kernel-only child must be traversed before the harness can journal absence.
/// Missing-parent evidence must agree; a failed ioctl never reaches this seam.
pub(super) fn merge(
    text: Text,
    kernel: Option<Vec<String>>,
    parent: &str,
) -> Result<Text, SysError> {
    match text {
        Text::Present(text) => {
            let mut names = pfanchor::inventory_at(&text, parent)?
                .into_iter()
                .map(str::to_owned)
                .collect::<BTreeSet<_>>();
            if kernel.is_none() {
                return Err(SysError::Unknown);
            }
            names.extend(kernel.unwrap_or_default());
            let mut merged = String::new();
            for child in names {
                // Validate kernel names with the same adapter containment grammar.
                let path = if parent.is_empty() {
                    child
                } else {
                    format!("{parent}/{child}")
                };
                writeln!(&mut merged, "  {path}").map_err(|_| SysError::Unknown)?;
            }
            pfanchor::inventory_at(&merged, parent)?;
            Ok(Text::Present(merged))
        }
        Text::MissingParent(name) if name == parent && kernel.is_none() => {
            Ok(Text::MissingParent(name))
        }
        _ => Err(SysError::Unknown),
    }
}
/// A missing text parent is the exact rc-0 EINVAL diagnostic, not any failed
/// inventory command or an arbitrary stderr line accompanying empty stdout.
pub(super) fn text_names(
    parent: &str,
    listing: &super::Evidence,
) -> Result<Option<BTreeSet<String>>, String> {
    if !listing.complete() {
        return Err("text inventory command incomplete".into());
    }
    let diagnostic = listing
        .stderr
        .as_bytes()
        .strip_prefix(crate::decode::pftext::ALTQ_PREAMBLE)
        .ok_or("text inventory diagnostics unpinned")?;
    let missing = !parent.is_empty()
        && listing.stdout.is_empty()
        && diagnostic == format!("Anchor '{parent}' not found.\n").as_bytes();
    if !diagnostic.is_empty() && !missing {
        return Err("text inventory diagnostics unpinned".into());
    }
    if missing {
        return Ok(None);
    }
    pfanchor::inventory_at(&listing.stdout, parent)
        .map(|names| Some(names.into_iter().map(str::to_owned).collect()))
        .map_err(|error| format!("text inventory malformed: {error:?}"))
}

/// Compare stable per-parent censuses around the text read. Failure or a
/// changed kernel set is incomplete; stable differences are contract findings.
pub(super) fn compare(
    parent: &str,
    text: Result<Option<BTreeSet<String>>, String>,
    before: Result<Option<Vec<String>>, String>,
    after: Result<Option<Vec<String>>, String>,
) -> serde_json::Value {
    let normalize = |result: Result<Option<Vec<String>>, String>| {
        result.map(|names| names.map(|names| names.into_iter().collect::<BTreeSet<_>>()))
    };
    let before = normalize(before);
    let after = normalize(after);
    match (text, before, after) {
        (Ok(text), Ok(before), Ok(after)) if before == after => {
            let missing = after.is_none();
            let text_missing = text.is_none();
            let text = text.unwrap_or_default();
            let kernel = after.unwrap_or_default();
            let kernel_only = kernel.difference(&text).collect::<Vec<_>>();
            let text_only = text.difference(&kernel).collect::<Vec<_>>();
            let mut findings = Vec::new();
            if missing != text_missing {
                findings.push(format!("{parent}: inventory disagreement: existence"));
            }
            if !kernel_only.is_empty() {
                findings.push(format!(
                    "{parent}: text inventory incomplete: {kernel_only:?}"
                ));
            }
            if !text_only.is_empty() {
                findings.push(format!("{parent}: inventory disagreement: {text_only:?}"));
            }
            serde_json::json!({"kernel_complete":true,"kernel_path_missing":missing,
                "text_path_missing":text_missing,"agreement":text == kernel && missing == text_missing,"text_names":text,"kernel_names":kernel,
                "kernel_only":kernel_only,"text_only":text_only,"inventory_findings":findings})
        }
        (text, before, after) => {
            // Still traverse every name observed by either reader. Failed reads
            // cannot grant completeness, even when the known union is empty.
            let text_names = text.as_ref().ok().cloned().flatten().unwrap_or_default();
            let kernel_names = before
                .as_ref()
                .ok()
                .into_iter()
                .chain(after.as_ref().ok())
                .filter_map(Option::as_ref)
                .flatten()
                .cloned()
                .collect::<BTreeSet<_>>();
            serde_json::json!({"kernel_complete":false,
                "issue":"enumeration failure or concurrent mutation", "text_names":text_names,"kernel_names":kernel_names,
                "text_result":format!("{text:?}"),"kernel_before":format!("{before:?}"),"kernel_after":format!("{after:?}")})
        }
    }
}

pub(super) fn verdict(findings: &[(bool, String)]) -> super::Verdict {
    if findings.iter().any(|(violation, _)| *violation) {
        super::Verdict::ContractViolation
    } else if findings.is_empty() {
        super::Verdict::AssumptionHolds
    } else {
        super::Verdict::Inconclusive
    }
}

pub(super) fn findings(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::Object(fields) => {
            let mut found = fields
                .get("inventory_findings")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>();
            for (key, child) in fields {
                if key != "inventory_findings" {
                    found.extend(findings(child));
                }
            }
            found
        }
        serde_json::Value::Array(values) => values.iter().flat_map(findings).collect(),
        _ => Vec::new(),
    }
}

pub(super) const ROOT: &str = "scupper-qual/children";
/// Deep fixture targets are qualified separately from the immutable two-part
/// production `AnchorPath`; they never broaden that adapter namespace.
pub(super) fn target_path(path: &str) -> bool {
    path.strip_prefix("scupper-qual/children/")
        .is_some_and(|suffix| {
            let parts = suffix.split('/').collect::<Vec<_>>();
            path.len() < 1024
                && parts.len() <= 8
                && parts.iter().all(|part| {
                    !part.is_empty()
                        && !matches!(*part, "." | "..")
                        && part
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn text_missing_parent_needs_exact_successful_diagnostic() {
        let mut listing: super::super::Evidence = serde_json::from_value(serde_json::json!({
            "command":["/sbin/pfctl"],"stdin":null,"pid":1,"exit_code":0,
            "started_unix_ms":0,"elapsed_ms":0,"timed_out":false,"truncated":false,
            "stdout":"","stderr":"No ALTQ support in kernel\nALTQ related functions disabled\nAnchor 'scupper-qual/children/fresh' not found.\n"
        })).unwrap();
        let parent = "scupper-qual/children/fresh";
        assert_eq!(text_names(parent, &listing), Ok(None));
        assert!(text_names("other-parent", &listing).is_err());
        listing.exit_code = Some(1);
        assert!(text_names(parent, &listing).is_err());
        listing.exit_code = Some(0);
        listing.stderr.push('x');
        assert!(text_names(parent, &listing).is_err());
        listing.stderr = String::from_utf8(crate::decode::pftext::ALTQ_PREAMBLE.to_vec()).unwrap();
        listing.stdout = format!("  {parent}/x\n  {parent}/_hidden\n");
        assert_eq!(
            text_names(parent, &listing),
            Ok(Some(BTreeSet::from(["_hidden".into(), "x".into()])))
        );
    }
    #[test]
    fn stable_inventory_differences_are_findings_and_mutation_is_inconclusive() {
        let text = || {
            Ok(Some(BTreeSet::from([
                "visible".to_owned(),
                "text-only".to_owned(),
            ])))
        };
        let kernel = || Ok(Some(vec!["visible".to_owned(), "_hidden".to_owned()]));
        let row = compare(ROOT, text(), kernel(), kernel());
        assert_eq!(row["kernel_complete"], true);
        assert_eq!(row["agreement"], false);
        let found = findings(&row);
        assert_eq!(found.len(), 2);
        assert_eq!(
            verdict(
                &found
                    .iter()
                    .cloned()
                    .map(|finding| (true, finding))
                    .collect::<Vec<_>>()
            ),
            super::super::Verdict::ContractViolation
        );
        assert_eq!(
            verdict(&[(false, "enumeration failure".into())]),
            super::super::Verdict::Inconclusive
        );
        assert_eq!(verdict(&[]), super::super::Verdict::AssumptionHolds);
        assert!(found[0].contains("text inventory incomplete"));
        assert!(found[1].contains("inventory disagreement"));
        assert_eq!(row["kernel_only"], serde_json::json!(["_hidden"]));
        assert_eq!(row["text_only"], serde_json::json!(["text-only"]));
        let changed = compare(ROOT, text(), kernel(), Ok(Some(vec!["changed".into()])));
        assert_eq!(changed["kernel_complete"], false);
        assert_eq!(
            changed["text_names"],
            serde_json::json!(["text-only", "visible"])
        );
        assert_eq!(
            changed["kernel_names"],
            serde_json::json!(["_hidden", "changed", "visible"])
        );
        assert_eq!(findings(&changed), Vec::<String>::new());
        for row in [
            compare(ROOT, text(), Err("ioctl failed".into()), kernel()),
            compare(ROOT, Err("text incomplete".into()), kernel(), kernel()),
        ] {
            assert_eq!(row["kernel_complete"], false);
            assert_eq!(findings(&row), Vec::<String>::new());
        }
        let equal = compare(
            ROOT,
            Ok(Some(BTreeSet::from(["a".into(), "b".into()]))),
            Ok(Some(vec!["b".into(), "a".into()])),
            Ok(Some(vec!["a".into(), "b".into()])),
        );
        assert_eq!(equal["agreement"], true);
        assert_eq!(findings(&equal), Vec::<String>::new());
        let absent = compare(ROOT, Ok(None), Ok(None), Ok(None));
        assert_eq!(absent["kernel_complete"], true);
        assert_eq!(findings(&absent), Vec::<String>::new());
    }
    #[test]
    fn existence_disagreements_are_findings_even_with_empty_names() {
        let mut listing: super::super::Evidence = serde_json::from_value(serde_json::json!({
            "command":["/sbin/pfctl"],"stdin":null,"pid":1,"exit_code":0,
            "started_unix_ms":0,"elapsed_ms":0,"timed_out":false,"truncated":false,
            "stdout":"","stderr":"No ALTQ support in kernel\nALTQ related functions disabled\n"
        }))
        .unwrap();
        for text_missing in [false, true] {
            let preamble =
                String::from_utf8(crate::decode::pftext::ALTQ_PREAMBLE.to_vec()).unwrap();
            listing.stderr = if text_missing {
                format!("{preamble}Anchor '{ROOT}' not found.\n")
            } else {
                preamble
            };
            for kernel_missing in [false, true] {
                let kernel = if kernel_missing { None } else { Some(vec![]) };
                let row = compare(
                    ROOT,
                    text_names(ROOT, &listing),
                    Ok(kernel.clone()),
                    Ok(kernel),
                );
                assert_eq!(row["kernel_path_missing"], kernel_missing);
                assert_eq!(row["text_path_missing"], text_missing);
                assert_eq!(row["agreement"], text_missing == kernel_missing);
                let found = findings(&row);
                if text_missing == kernel_missing {
                    assert_eq!(found, Vec::<String>::new());
                } else {
                    assert_eq!(
                        found,
                        vec![format!("{ROOT}: inventory disagreement: existence")]
                    );
                    assert_eq!(
                        verdict(&[(true, found[0].clone())]),
                        super::super::Verdict::ContractViolation
                    );
                }
            }
        }
        let changed = compare(ROOT, Ok(None), Ok(None), Ok(Some(vec![])));
        assert_eq!(changed["kernel_complete"], false);
        assert_eq!(findings(&changed), Vec::<String>::new());
    }
    #[test]
    fn deep_targets_do_not_broaden_the_adapter_path_contract() {
        assert_eq!(ROOT, "scupper-qual/children");
        for path in [
            "scupper-qual/children/p",
            "scupper-qual/children/p/_x",
            "scupper-qual/children/p/qchild/_x",
        ] {
            assert!(target_path(path));
            assert!(pfanchor::AnchorPath::new(path).is_err());
        }
        for path in [
            "scupper-qual/children",
            "scupper-qual/children/../foreign",
            "scupper-qual/children/p/*",
            "com.apple/scupper/p",
        ] {
            assert!(!target_path(path));
        }
    }
    #[test]
    fn kernel_only_children_are_traversed_and_missing_parent_must_agree() {
        let parent = "scupper-qual/children/fresh";
        let Text::Present(text) = merge(
            Text::Present(String::new()),
            Some(vec!["_x".into()]),
            parent,
        )
        .unwrap() else {
            panic!("inventory");
        };
        assert_eq!(
            pfanchor::inventory_at(&text, parent).unwrap(),
            BTreeSet::from(["_x"])
        );
        assert!(merge(Text::MissingParent(parent.into()), Some(vec![]), parent).is_err());
        assert_eq!(
            merge(Text::MissingParent(parent.into()), None, parent),
            Ok(Text::MissingParent(parent.into()))
        );
        assert!(merge(Text::Present(text), None, parent).is_err());
        assert!(
            merge(
                Text::Present(String::new()),
                Some(vec!["../escape".into()]),
                parent
            )
            .is_err()
        );
        assert!(merge(Text::Present(String::new()), None, parent).is_err());
        assert!(merge(Text::MissingParent("other-parent".into()), None, parent).is_err());
    }
}
