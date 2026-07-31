//! Strict, privacy-preserving parser for Codex `apply_patch` payloads.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    Create {
        path: String,
        content: String,
    },
    Update {
        path: String,
        old: Option<String>,
        new: Option<String>,
        move_to: Option<String>,
    },
    Delete {
        path: String,
    },
}

fn clean_path(raw: &str) -> Result<String, &'static str> {
    let path = raw.trim();
    if path.is_empty() || path.contains('\0') {
        return Err("invalid target path");
    }
    Ok(path.replace('\\', "/"))
}

/// Parse the patch envelope into create, update, delete, rename, and multi-file
/// operations. Errors name only the schema condition, never patch content.
///
/// **`Update File` is not hunk-accurate.** Multiple `@@` hunks in one block are
/// flattened into single `old`/`new` blobs with the hunk boundaries discarded,
/// so `old`/`new` do NOT map 1:1 to a single hunk and the blobs are not a
/// diff you could apply. That is deliberate and sufficient for the consumer this
/// exists for — guards scan for the *presence* of content a patch introduces or
/// removes, never reconstruct the file. A future consumer that needs to apply or
/// locate a change must extend this to carry hunks, not reinterpret these fields.
pub fn parse(raw: &str) -> Result<Vec<Operation>, &'static str> {
    let mut lines = raw.lines().peekable();
    if lines.next() != Some("*** Begin Patch") {
        return Err("missing begin marker");
    }
    let mut operations = Vec::new();
    loop {
        let Some(line) = lines.next() else {
            return Err("missing end marker");
        };
        if line == "*** End Patch" {
            if lines.any(|tail| !tail.trim().is_empty()) {
                return Err("content after end marker");
            }
            return Ok(operations);
        }
        if let Some(path) = line.strip_prefix("*** Add File: ") {
            let path = clean_path(path)?;
            let mut content = Vec::new();
            while let Some(next) = lines.peek() {
                if next.starts_with("*** ") {
                    break;
                }
                let next = lines.next().expect("peeked line");
                let Some(added) = next.strip_prefix('+') else {
                    return Err("add line missing plus prefix");
                };
                content.push(added);
            }
            operations.push(Operation::Create {
                path,
                content: content.join("\n"),
            });
            continue;
        }
        if let Some(path) = line.strip_prefix("*** Delete File: ") {
            operations.push(Operation::Delete {
                path: clean_path(path)?,
            });
            continue;
        }
        if let Some(path) = line.strip_prefix("*** Update File: ") {
            let path = clean_path(path)?;
            let mut move_to = None;
            if let Some(next) = lines.peek()
                && let Some(destination) = next.strip_prefix("*** Move to: ")
            {
                move_to = Some(clean_path(destination)?);
                lines.next();
            }
            let mut old = Vec::new();
            let mut new = Vec::new();
            let mut saw_hunk = false;
            while let Some(next) = lines.peek() {
                if *next == "*** End of File" {
                    lines.next();
                    continue;
                }
                if next.starts_with("*** ") {
                    break;
                }
                let next = lines.next().expect("peeked line");
                if next == "@@" || next.starts_with("@@ ") {
                    saw_hunk = true;
                    continue;
                }
                match next.as_bytes().first() {
                    Some(b'-') => old.push(&next[1..]),
                    Some(b'+') => new.push(&next[1..]),
                    Some(b' ') => {
                        old.push(&next[1..]);
                        new.push(&next[1..]);
                    }
                    // An EMPTY line is a blank context line, not a malformed
                    // one. A unified diff spells one `" "` (a lone space), but a
                    // producer that trims trailing whitespace — most editors,
                    // most formatters — emits `""` instead, and `first()` on an
                    // empty line is `None`. Falling to the reject arm below made
                    // every such patch a hard block on all 13 security-critical
                    // hooks under Codex, with a message saying the patch was
                    // malformed. Fail-closed, so not a hole — but the likely
                    // operator response ("Codex hooks are broken, unset
                    // CADENCE_HARNESS") turns it into one.
                    None => {
                        old.push("");
                        new.push("");
                    }
                    _ => return Err("invalid update line prefix"),
                }
            }
            if !saw_hunk && move_to.is_none() {
                return Err("update missing hunk");
            }
            operations.push(Operation::Update {
                path,
                old: (!old.is_empty()).then(|| old.join("\n")),
                new: (!new.is_empty()).then(|| new.join("\n")),
                move_to,
            });
            continue;
        }
        return Err("unknown operation marker");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_create_update_delete_rename_and_multi_file() {
        let patch = "*** Begin Patch\n*** Add File: a.txt\n+one\n*** Update File: b.txt\n*** Move to: c.txt\n@@\n-old\n+new\n*** Delete File: d.txt\n*** End Patch\n";
        let operations = parse(patch).unwrap();
        assert_eq!(operations.len(), 3);
        assert!(matches!(operations[0], Operation::Create { .. }));
        assert!(matches!(
            operations[1],
            Operation::Update {
                move_to: Some(_),
                ..
            }
        ));
        assert!(matches!(operations[2], Operation::Delete { .. }));
    }

    #[test]
    fn malformed_inputs_fail_without_echoing_content() {
        let error = parse("*** Begin Patch\nSECRET\n*** End Patch").unwrap_err();
        assert_eq!(error, "unknown operation marker");
        assert!(!error.contains("SECRET"));
    }

    #[test]
    fn preserves_traversal_for_guards_to_reject() {
        let operations =
            parse("*** Begin Patch\n*** Delete File: ../../vault/x\n*** End Patch").unwrap();
        assert_eq!(
            operations,
            vec![Operation::Delete {
                path: "../../vault/x".to_string()
            }]
        );
    }

    /// A blank context line is legal in a unified diff, and a producer that
    /// trims trailing whitespace emits it as `""` rather than `" "`. Rejecting
    /// it hard-blocked every security-critical hook under Codex on ordinary
    /// edits.
    #[test]
    fn blank_context_line_in_a_hunk_is_not_a_schema_error() {
        let operations = parse(
            "*** Begin Patch\n*** Update File: a\n@@\n first\n\n-old\n+new\n last\n*** End Patch",
        )
        .expect("a blank context line is legal");
        assert_eq!(
            operations,
            vec![Operation::Update {
                path: "a".to_string(),
                old: Some("first\n\nold\nlast".to_string()),
                new: Some("first\n\nnew\nlast".to_string()),
                move_to: None,
            }]
        );
    }

    /// The blank line lands on BOTH sides, exactly as a spaced context line
    /// does — so a content guard scanning `new` sees the same document either
    /// way, and the two spellings cannot disagree.
    #[test]
    fn blank_and_spaced_context_lines_parse_identically() {
        let blank =
            parse("*** Begin Patch\n*** Update File: a\n@@\n x\n\n y\n*** End Patch").unwrap();
        let spaced =
            parse("*** Begin Patch\n*** Update File: a\n@@\n x\n \n y\n*** End Patch").unwrap();
        assert_eq!(blank, spaced);
    }

    /// The widening is scoped to *empty*: a line whose first byte is neither
    /// `-`, `+`, nor a space is still a schema error, so the parser has not
    /// become a "accept anything" reader.
    #[test]
    fn a_non_empty_unprefixed_line_is_still_rejected() {
        assert_eq!(
            parse("*** Begin Patch\n*** Update File: a\n@@\nUNPREFIXED\n*** End Patch")
                .unwrap_err(),
            "invalid update line prefix"
        );
    }

    #[test]
    fn accepts_end_of_file_marker_inside_update() {
        let operations = parse(
            "*** Begin Patch\n*** Update File: a\n@@\n-old\n+new\n*** End of File\n*** End Patch",
        )
        .unwrap();
        assert_eq!(operations.len(), 1);
    }
}
