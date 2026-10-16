//! Where the body of a `gh` posting command comes from.
//!
//! Shared by `warn-inline-body` and `warn-unreviewed-ready-flip`: the body
//! flag `gh` actually uses ([`last_body_flag`]), whether the body file is
//! written earlier in the same command so the copy on disk is stale
//! ([`body_written_earlier`]), and, for the one shape that can be read
//! exactly, the text a same-command heredoc writes into it
//! ([`same_command_heredoc_body`]). Every function here is pure: no file is
//! opened.
//!
//! These lived in the retired `guard-body-budget` module until it was removed
//! (cameronsjo/cadence-hooks#1373); their behaviour is unchanged.

use cadence_hooks_core::gh_bodies::{glued_short_value, strip_flag_prefix};
use cadence_hooks_core::shell::{
    command_segments, command_word, executable_tokens, heredoc_introducers, redirect_targets,
    skip_transparent_prefixes, strip_group_wrappers, tokenize, unescape_word,
};
use regex::Regex;
use std::sync::LazyLock;

/// Where the body a command would post comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyArg {
    /// A literal `--body`/`-b` value.
    Inline(String),
    /// A `--body-file`/`-F` path, still to be read.
    File(String),
}

/// The LAST body flag on a segment, which is the one `gh` uses.
///
/// `gh` takes the last occurrence of a repeated body flag, so measuring the
/// first would measure text the command never posts. Pure: the file behind a
/// `--body-file` is not opened here.
pub fn last_body_flag(segment: &str) -> Option<BodyArg> {
    let tokens = tokenize(segment);
    let mut found: Option<BodyArg> = None;
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        // Flag names are read as the shell passes them: `--bo\dy` is `--body`.
        let name = unescape_word(tok);
        if matches!(name.as_ref(), "--body" | "-b")
            && let Some(v) = tokens.get(i + 1)
        {
            found = Some(BodyArg::Inline(v.clone()));
            i += 2;
            continue;
        }
        if matches!(name.as_ref(), "--body-file" | "-F")
            && let Some(p) = tokens.get(i + 1)
        {
            found = Some(BodyArg::File(p.clone()));
            i += 2;
            continue;
        }
        if let Some(v) = strip_flag_prefix(tok, "--body=") {
            found = Some(BodyArg::Inline(v.to_string()));
            i += 1;
            continue;
        }
        if let Some(p) = strip_flag_prefix(tok, "--body-file=") {
            found = Some(BodyArg::File(p.to_string()));
            i += 1;
            continue;
        }
        // Glued short forms: `-bBODY`, `-FPATH`.
        if let Some(v) = glued_short_value(tok, "-b") {
            found = Some(BodyArg::Inline(v.to_string()));
            i += 1;
            continue;
        }
        if let Some(p) = glued_short_value(tok, "-F") {
            found = Some(BodyArg::File(p.to_string()));
            i += 1;
            continue;
        }
        i += 1;
    }
    found
}

/// Whether `a` and `b` can name the same file: equal after a leading `./`, or
/// the same final component. The final-component arm over-matches on purpose
/// (`cd /x && printf > b.md; --body-file /x/b.md` must match) — the price is
/// a spurious "cannot measure" nudge, never a missed measurement.
fn same_file_name(a: &str, b: &str) -> bool {
    let norm = |p: &str| p.strip_prefix("./").unwrap_or(p).to_string();
    let base = |p: &str| p.rsplit('/').next().unwrap_or(p).to_string();
    norm(a) == norm(b) || (!base(a).is_empty() && base(a) == base(b))
}

/// Whether one earlier segment writes `path`: a redirect target, a `tee`
/// operand, or the destination (last operand) of `cp`/`mv`. Pure.
fn segment_writes_file(segment: &str, path: &str) -> bool {
    if redirect_targets(segment)
        .iter()
        .any(|t| same_file_name(t, path))
    {
        return true;
    }
    let tokens = executable_tokens(strip_group_wrappers(segment));
    let rest = skip_transparent_prefixes(&tokens);
    let Some(head) = rest.first() else {
        return false;
    };
    let operands = || rest[1..].iter().filter(|t| !t.starts_with('-'));
    match command_word(head).as_ref() {
        "tee" => operands().any(|t| same_file_name(t, path)),
        "cp" | "mv" => operands()
            .next_back()
            .is_some_and(|t| same_file_name(t, path)),
        _ => false,
    }
}

/// Whether the body file `path` is written by a segment that runs BEFORE the
/// posting `segment` in the same command. The file on disk at hook time is
/// then stale: measuring it can call a 500-word body 5 words
/// (cameronsjo/cadence-hooks#984). Pure.
pub(crate) fn body_written_earlier(segs: &[String], segment: &str, path: &str) -> bool {
    // Past this many segments the walk (segments x posting segments) is not
    // worth its cost: say "cannot measure" instead of scanning (perf bound).
    const MAX_SEGMENTS: usize = 256;
    if segs.len() > MAX_SEGMENTS {
        return true;
    }
    let Some(pos) = segs.iter().position(|s| strip_group_wrappers(s) == segment) else {
        return false;
    };
    segs[..pos].iter().any(|s| segment_writes_file(s, path))
}

/// The one shape whose body a same-command write can still be measured from:
/// a bare `cat` clobbering exactly the body file from a heredoc, in either
/// operand order (`cat > F <<'EOF'`, `cat <<'EOF' > F`). Captures the target
/// (quotes optional) from whichever arm matched.
static CAT_HEREDOC_WRITE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^\s*cat\s+(?:>\|?\s*(?:"([^"]+)"|'([^']+)'|([^\s"'<>|&;]+))\s*<<-?\s*\S+|<<-?\s*\S+\s+>\|?\s*(?:"([^"]+)"|'([^']+)'|([^\s"'<>|&;]+)))\s*$"#,
    )
    .expect("cat heredoc write pattern compiles")
});

/// The file a [`CAT_HEREDOC_WRITE`] segment writes, or `None` for any other
/// segment.
fn cat_heredoc_target(segment: &str) -> Option<String> {
    let caps = CAT_HEREDOC_WRITE.captures(segment)?;
    (1..=6)
        .find_map(|i| caps.get(i))
        .map(|m| m.as_str().to_string())
}

/// Whether two body-file spellings are the same path exactly (a leading `./`
/// aside). Stricter than [`same_file_name`] on purpose: that one over-matches
/// to say "cannot measure", but text measured from the wrong heredoc would be
/// a wrong number, so only an exact match is measured.
fn exact_same_path(a: &str, b: &str) -> bool {
    let norm = |p: &str| p.strip_prefix("./").unwrap_or(p).to_string();
    norm(a) == norm(b)
}

/// The text a same-command heredoc writes into the body file `path`, when the
/// guard can read it exactly (cameronsjo/cadence-hooks#1334).
///
/// `cadence:redaction`'s gated form writes the body, scans it and posts it in
/// one command, so the file on disk is stale at hook time. The one shape read
/// here is the common one: the ONLY segment in the command that writes `path`
/// is a bare `cat > path <<'EOF'` before the post, its heredoc is the only one
/// on its line, the terminator is found, and the body cannot expand (a quoted
/// delimiter, or no `$` or backtick in the text). Anything else answers `None`
/// and the caller keeps today's "cannot measure" nudge. Pure.
pub(crate) fn same_command_heredoc_body(
    segs: &[String],
    segment: &str,
    path: &str,
    command: &str,
) -> Option<String> {
    // Exactly one writer of the file in the whole command, and it is the
    // heredoc `cat`, before the post.
    let writers: Vec<usize> = segs
        .iter()
        .enumerate()
        .filter(|(_, s)| segment_writes_file(s, path))
        .map(|(i, _)| i)
        .collect();
    let [writer] = writers.as_slice() else {
        return None;
    };
    let post = segs
        .iter()
        .position(|s| strip_group_wrappers(s) == segment)?;
    if *writer >= post {
        return None;
    }
    // A relative body path names one file only when the writer and the post
    // run in the same directory. A directory change before the post
    // (`(cd /x && cat > b.md <<EOF … EOF) && gh … --body-file b.md`, or a
    // `cd` between the two) can split them, so the body stays unmeasured
    // (review M2).
    if segs[..post].iter().any(|s| {
        executable_tokens(strip_group_wrappers(s))
            .first()
            .is_some_and(|w| matches!(unescape_word(w).as_ref(), "cd" | "pushd" | "popd"))
    }) {
        return None;
    }
    let target = cat_heredoc_target(segs[*writer].trim())?;
    if !exact_same_path(&target, path) {
        return None;
    }

    // Find that heredoc's body: the one logical line with one introducer whose
    // own segment is a cat-heredoc write of this exact path.
    let physical: Vec<&str> = command.split('\n').collect();
    let mut found: Option<String> = None;
    let mut i = 0;
    while i < physical.len() {
        let mut line = physical[i].to_string();
        i += 1;
        while i < physical.len() && (line.len() - line.trim_end_matches('\\').len()) % 2 == 1 {
            line.pop();
            line.push_str(physical[i]);
            i += 1;
        }
        if !line.contains("<<") {
            continue;
        }
        let intros = heredoc_introducers(&line);
        let writes_here = command_segments(&line)
            .iter()
            .any(|s| cat_heredoc_target(s.trim()).is_some_and(|t| exact_same_path(&t, path)));
        let mut bodies: Vec<(Vec<&str>, bool)> = Vec::new();
        for intro in &intros {
            let dash = line[intro.start..].starts_with("<<-");
            let mut body: Vec<&str> = Vec::new();
            let mut terminated = false;
            while i < physical.len() {
                let candidate = physical[i];
                i += 1;
                let bare = if dash {
                    candidate.trim_start_matches('\t')
                } else {
                    candidate
                };
                if bare == intro.word {
                    terminated = true;
                    break;
                }
                body.push(bare);
            }
            bodies.push((body, terminated));
        }
        if !writes_here {
            continue;
        }
        // A second heredoc writing the same file, or a line this reading
        // cannot pin to one heredoc, is not measured.
        if found.is_some() || intros.len() != 1 {
            return None;
        }
        let (body, terminated) = bodies.pop()?;
        let text = body.join("\n");
        if !terminated || (intros[0].expands && (text.contains('$') || text.contains('`'))) {
            return None;
        }
        found = Some(text);
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_body_flag_takes_the_last_occurrence() {
        assert_eq!(
            last_body_flag("gh pr create --body first --body second"),
            Some(BodyArg::Inline("second".into()))
        );
        assert_eq!(
            last_body_flag("gh pr create --body inline --body-file /tmp/b.md"),
            Some(BodyArg::File("/tmp/b.md".into()))
        );
        assert_eq!(
            last_body_flag("gh pr create --body-file /tmp/b.md --body inline"),
            Some(BodyArg::Inline("inline".into()))
        );
        assert_eq!(last_body_flag("gh pr create --title x"), None);
    }

    #[test]
    fn last_body_flag_covers_every_spelling() {
        for (cmd, want) in [
            ("gh pr create -b hi", BodyArg::Inline("hi".into())),
            ("gh pr create --body=hi", BodyArg::Inline("hi".into())),
            ("gh pr create -bhi", BodyArg::Inline("hi".into())),
            ("gh pr create -F p.md", BodyArg::File("p.md".into())),
            (
                "gh pr create --body-file=p.md",
                BodyArg::File("p.md".into()),
            ),
            ("gh pr create -Fp.md", BodyArg::File("p.md".into())),
            // bash drops an unquoted backslash in a flag name, so each of these
            // passes the flag itself (`printf '%s\n' --bo\dy` prints `--body`).
            (r"gh pr create --bo\dy hi", BodyArg::Inline("hi".into())),
            (r"gh pr create --bo\dy=hi", BodyArg::Inline("hi".into())),
            (r"gh pr create -\bhi", BodyArg::Inline("hi".into())),
            (
                r"gh pr create --body-fi\le p.md",
                BodyArg::File("p.md".into()),
            ),
            (r"gh pr create -\F p.md", BodyArg::File("p.md".into())),
            (
                r"gh pr create --body x --bo\dy last",
                BodyArg::Inline("last".into()),
            ),
        ] {
            assert_eq!(last_body_flag(cmd), Some(want), "{cmd:?}");
        }
    }

    // ---- same-command body writes ----
    //
    // These cases were pinned through `guard-body-budget`'s verdicts before
    // that guard was retired (cameronsjo/cadence-hooks#984, #1334); they now
    // pin the helpers directly.

    /// The command's segments and its `gh` posting segment, the way the
    /// callers build them.
    fn post_of(command: &str) -> (Vec<String>, String) {
        let segs = command_segments(command);
        let post = segs
            .iter()
            .map(|s| strip_group_wrappers(s))
            .find(|s| s.contains("gh "))
            .expect("a gh segment")
            .to_string();
        (segs, post)
    }

    /// What a caller reads for `command`'s body file `path`: `Some(text)` for
    /// a same-command heredoc read exactly, `None` for a write it cannot
    /// read, and the on-disk marker when the file is not written earlier.
    fn read_as_caller(command: &str, path: &str) -> Option<String> {
        let (segs, post) = post_of(command);
        if body_written_earlier(&segs, &post, path) {
            same_command_heredoc_body(&segs, &post, path, command)
        } else {
            Some("<on disk>".to_string())
        }
    }

    #[test]
    fn a_body_file_written_by_an_earlier_segment_is_not_read() {
        let p = "/tmp/b-984/body.md";
        for writer in [
            format!("printf hi > {p}"),
            format!("printf hi >> {p}"),
            format!("echo hi | tee {p}"),
            format!("echo hi | tee -a {p}"),
            format!("cp /tmp/other {p}"),
            format!("mv /tmp/other {p}"),
            // A heredoc that cannot be read exactly (#1334).
            format!("cat > {p} <<EOF\n$(date)\nEOF"),
            format!("cat > {p} <<'EOF'\nbody\nEOF\necho more >> {p}"),
            format!("cat > {p} <<'EOF'\nunterminated"),
        ] {
            let cmd = format!("{writer} && gh issue create --title x --body-file {p}");
            let (segs, post) = post_of(&cmd);
            assert!(body_written_earlier(&segs, &post, p), "{cmd}");
            assert_eq!(read_as_caller(&cmd, p), None, "{cmd}");
        }
    }

    #[test]
    fn a_same_command_heredoc_body_is_read_exactly() {
        let p = "/tmp/b-1334/gated.md";
        let long = "word ".repeat(400);
        for cmd in [
            format!(
                "cat > {p} <<'EOF'\n{long}\nEOF\nscan {p} && gh pr create --title x --body-file {p}"
            ),
            format!("cat <<'EOF' > \"{p}\" && gh pr create --title x --body-file {p}\n{long}\nEOF"),
            format!("cat > {p} <<EOF\n{long}\nEOF\ngh pr create --title x --body-file {p}"),
        ] {
            let text = read_as_caller(&cmd, p).unwrap_or_default();
            assert_eq!(text.split_whitespace().count(), 400, "{cmd}: {text:?}");
        }
        let short = format!(
            "cat > {p} <<'EOF'\nfive short words here ok\nEOF\ngh pr create --title x --body-file {p}"
        );
        assert_eq!(
            read_as_caller(&short, p).as_deref(),
            Some("five short words here ok")
        );
    }

    #[test]
    fn a_heredoc_written_in_another_directory_is_not_read() {
        // Review M2: the writer and the post must run in the same directory
        // for the relative body path to name one file.
        let long = "word ".repeat(400);
        for cmd in [
            format!(
                "(cd /tmp && cat > b.md <<'EOF'\n{long}\nEOF\n) && gh pr create --title x --body-file b.md"
            ),
            format!(
                "cat > b.md <<'EOF'\n{long}\nEOF\ncd /tmp && gh pr create --title x --body-file b.md"
            ),
        ] {
            assert_eq!(read_as_caller(&cmd, "b.md"), None, "{cmd}");
        }
    }

    #[test]
    fn a_body_file_not_written_before_the_post_is_read_from_disk() {
        let p = "/tmp/b-984/body.md";
        for cmd in [
            format!("gh issue create --title x --body-file {p}"),
            // Writes a DIFFERENT file, and reads (not writes) the body file.
            format!(
                "printf hi > /tmp/elsewhere-x.txt && gh issue create --title x --body-file {p}"
            ),
            format!("cp {p} /tmp/copy-x.txt && gh issue create --title x --body-file {p}"),
            // Written AFTER the post: the post reads what is on disk now.
            format!("gh issue create --title x --body-file {p} && printf hi > {p}"),
        ] {
            assert_eq!(
                read_as_caller(&cmd, p).as_deref(),
                Some("<on disk>"),
                "{cmd}"
            );
        }
    }
}
