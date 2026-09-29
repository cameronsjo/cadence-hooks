//! Command substitutions a guard can read without running them
//! (cadence-hooks#1142).
//!
//! `$(echo git) push --force` runs `git push --force`, and `cat .env$(true)`
//! reads `.env`, but a guard that judges the text sees neither. Two readings
//! are surfaced beside the segment as written:
//!
//! - **evaluated** — every substitution whose body is a plain literal
//!   `echo`/`printf` replaced by the text it prints, so the command the shell
//!   runs is judged by every guard that already judges it spelled out;
//! - **globbed** — the same, plus every OTHER substitution glued into a word
//!   (`.env$(true)`, `"$(pwd)"/.env`) replaced by `*`, so a word whose static
//!   part names a secret family is judged as the glob it may expand to.
//!
//! A substitution standing alone as a word is never globbed: `cd "$(…)"` and
//! `rm "$(mktemp)"` stay as written.
//!
//! Only text the shell would NOT re-parse is substituted. Bash word-splits and
//! globs a substitution's output but never reads operators or quotes in it, so
//! a printed `;` or `>` is re-emitted single-quoted.

use super::{
    Quote, backtick_span_end, carries_substitution, executable_tokens, is_assignment_word,
    peel_command_runners, scan_quote_syntax, scan_substitution_body, skip_transparent_prefixes,
};

/// The two readings of [`rewrite`].
pub(super) struct Rewrite {
    /// Static substitutions replaced by their output, or `None` when none was.
    pub evaluated: Option<String>,
    /// Static substitutions replaced, and glued unknown ones read as `*`, or
    /// `None` when no unknown one was glued.
    pub globbed: Option<String>,
}

/// The text a `$(…)`/backtick `body` prints, when it is a literal `echo` or
/// `printf` whose every word is known without running anything.
///
/// Refused (`None`): any expansion, backslash, glob, brace, redirect, or
/// operator in the body, an `echo`/`printf` flag beyond `-n`/`-e`/`-E`, and a
/// `printf` format other than `%s` or one with no conversion.
pub(super) fn static_output(body: &str) -> Option<String> {
    let body = body.trim();
    let split = body.find([' ', '\t']).unwrap_or(body.len());
    let (head, rest) = body.split_at(split);
    let printf = match head {
        "echo" | "/bin/echo" | "/usr/bin/echo" => false,
        "printf" | "/usr/bin/printf" => true,
        _ => return None,
    };
    let words = literal_words(rest)?;
    if words.iter().any(|w| w.contains('\\')) {
        return None;
    }
    if printf {
        let (format, args) = words.split_first()?;
        return match format.as_str() {
            "%s" => Some(args.concat()),
            f if !f.contains('%') => Some(f.to_string()),
            _ => None,
        };
    }
    let flags = words
        .iter()
        .take_while(|w| {
            w.len() > 1 && w.starts_with('-') && w[1..].chars().all(|c| "neE".contains(c))
        })
        .count();
    Some(words[flags..].join(" "))
}

/// The words of `text` with quotes removed, or `None` when any word could
/// expand or carry syntax: `$`, a backtick, a backslash, or an unquoted glob,
/// brace, tilde, `#`, `!`, redirect or operator character.
fn literal_words(text: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '\'' => break,
                        q => word.push(q),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '"' => break,
                        '$' | '`' | '\\' | '!' => return None,
                        q => word.push(q),
                    }
                }
            }
            '$' | '`' | '\\' | ';' | '&' | '|' | '<' | '>' | '(' | ')' | '{' | '}' | '*' | '?'
            | '[' | ']' | '~' | '#' | '!' | '\n' => return None,
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }
    if in_word {
        words.push(word);
    }
    Some(words)
}

/// Whether `c` survives unquoted in a re-spelled word without changing how the
/// tokenizers read it. Glob characters stay unquoted on purpose: bash globs
/// a substitution's output, and the guards judge the glob.
fn is_plain(c: char) -> bool {
    c.is_alphanumeric() || "_./:=@%+,-*?[]~^".contains(c)
}

/// `output` as the source text that makes bash see the same words. In
/// `"…"`, the output is one word and is inserted as it is; unquoted, it is
/// split at blanks the way bash splits it and any word with a shell
/// metacharacter goes in single-quoted. `None` when the output cannot be
/// spelled safely (a quote or `$` inside double quotes, a `'` in a word that
/// needs quoting).
fn splice(output: &str, in_double: bool) -> Option<String> {
    if in_double {
        return (!output.contains(['"', '$', '`', '\\'])).then(|| output.to_string());
    }
    let blank = |c: char| matches!(c, ' ' | '\t' | '\n');
    let mut spelled = Vec::new();
    for word in output.split(blank).filter(|w| !w.is_empty()) {
        if word.chars().all(is_plain) {
            spelled.push(word.to_string());
        } else if !word.contains('\'') {
            spelled.push(format!("'{word}'"));
        } else {
            return None;
        }
    }
    let mut text = spelled.join(" ");
    if output.starts_with(blank) {
        text.insert(0, ' ');
    }
    if output.ends_with(blank) && !text.ends_with(' ') {
        text.push(' ');
    }
    Some(text)
}

/// Whether the span `chars[start..end]` shares its word with other text.
/// Quote characters beside it are looked through: `"$(x)"` is alone,
/// `"$(x)"/.env` and `x"$(y)"` are not.
fn glued(chars: &[char], start: usize, end: usize) -> bool {
    let word = |c: char| !c.is_whitespace() && !";&|<>()".contains(c);
    let mut left = start;
    while left > 0 && matches!(chars[left - 1], '"' | '\'') {
        left -= 1;
    }
    let mut right = end;
    while right < chars.len() && matches!(chars[right], '"' | '\'') {
        right += 1;
    }
    // A `)` before the span closes the substitution beside it (`$(a)$(b)`).
    (left > 0 && (word(chars[left - 1]) || chars[left - 1] == ')'))
        || (right < chars.len() && word(chars[right]))
}

/// Read every confidently bounded substitution in `segment`; see the module
/// docs. `None` when neither reading differs from the segment. A substitution
/// the scan cannot bound ends the rewrite there and leaves the rest as
/// written.
pub(super) fn rewrite(segment: &str) -> Option<Rewrite> {
    if !carries_substitution(segment) {
        return None;
    }
    let chars: Vec<char> = segment.chars().collect();
    let mut evaluated = String::with_capacity(segment.len());
    let mut globbed = String::with_capacity(segment.len());
    let (mut evaluates, mut globs) = (false, false);
    let mut quote: Option<Quote> = None;
    let mut i = 0;
    let push = |evaluated: &mut String, globbed: &mut String, from: usize, to: usize| {
        let text: String = chars[from..to.min(chars.len())].iter().collect();
        evaluated.push_str(&text);
        globbed.push_str(&text);
    };
    while i < chars.len() {
        if matches!(quote, Some(Quote::Single | Quote::AnsiC))
            && let Some(next) = scan_quote_syntax(&chars, i, &mut quote)
        {
            push(&mut evaluated, &mut globbed, i, next);
            i = next;
            continue;
        }
        let c = chars[i];
        if c == '\\' {
            push(&mut evaluated, &mut globbed, i, i + 2);
            i += 2;
            continue;
        }
        let bounded =
            if c == '$' && chars.get(i + 1) == Some(&'(') && chars.get(i + 2) != Some(&'(') {
                match scan_substitution_body(&chars, i + 2, true) {
                    Ok((body, end)) => Some((body, end)),
                    Err(_) => {
                        push(&mut evaluated, &mut globbed, i, chars.len());
                        break;
                    }
                }
            } else if c == '`' {
                match backtick_span_end(&chars, i) {
                    Some(end) => Some((chars[i + 1..end - 1].iter().collect::<String>(), end)),
                    None => {
                        push(&mut evaluated, &mut globbed, i, chars.len());
                        break;
                    }
                }
            } else {
                None
            };
        if let Some((body, end)) = bounded {
            let replacement = static_output(&body)
                .and_then(|output| splice(&output, quote == Some(Quote::Double)));
            match replacement {
                Some(text) => {
                    evaluated.push_str(&text);
                    globbed.push_str(&text);
                    evaluates = true;
                }
                None => {
                    let span: String = chars[i..end].iter().collect();
                    evaluated.push_str(&span);
                    if glued(&chars, i, end) {
                        globbed.push('*');
                        globs = true;
                    } else {
                        globbed.push_str(&span);
                    }
                }
            }
            i = end;
            continue;
        }
        if let Some(next) = scan_quote_syntax(&chars, i, &mut quote) {
            push(&mut evaluated, &mut globbed, i, next);
            i = next;
            continue;
        }
        evaluated.push(c);
        globbed.push(c);
        i += 1;
    }
    (evaluates || globs).then_some(Rewrite {
        evaluated: evaluates.then_some(evaluated),
        globbed: globs.then_some(globbed),
    })
}

/// Whether the command `segment` runs is named by a substitution no guard can
/// read: its command word, or the subcommand word of `git`/`gh`, carries
/// `$(…)` or a backtick that is not a literal `echo`/`printf`
/// (`$(which python) x.py`, `"$(git rev-parse --show-toplevel)/x.sh"`, `gh
/// $(x) delete`). A nudge tier, never a block (cadence-hooks#1142).
pub fn names_command_by_unknown_substitution(segment: &str) -> bool {
    let read = match rewrite(segment) {
        Some(Rewrite {
            evaluated: Some(text),
            ..
        }) => text,
        _ => segment.to_string(),
    };
    let tokens = executable_tokens(&read);
    let mut argv = peel_command_runners(skip_transparent_prefixes(&tokens));
    while let Some((first, rest)) = argv.split_first() {
        if !is_assignment_word(first) {
            break;
        }
        argv = rest;
    }
    let Some(head) = argv.first() else {
        return false;
    };
    if carries_substitution(head) {
        return true;
    }
    let base = head.rsplit('/').next().unwrap_or(head);
    matches!(base, "git" | "gh") && argv.get(1).is_some_and(|w| carries_substitution(w))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_output_reads_only_literal_echo_and_printf() {
        for (body, want) in [
            ("echo git", Some("git")),
            ("echo", Some("")),
            ("echo -n git", Some("git")),
            ("echo 'cat .env'", Some("cat .env")),
            ("echo \"cat .env\"", Some("cat .env")),
            ("echo rm   .env", Some("rm .env")),
            ("printf git", Some("git")),
            ("printf 'cat .env'", Some("cat .env")),
            ("printf %s git", Some("git")),
            ("/bin/echo git", Some("git")),
            ("echo $HOME", None),
            ("echo $(x)", None),
            ("echo *", None),
            ("echo {a,b}", None),
            ("echo a > f", None),
            ("echo a; rm b", None),
            ("echo a | b", None),
            ("echo 'a\\nb'", None),
            ("printf '%s %s' a b", None),
            ("printf", None),
            ("cat .env", None),
            ("which python", None),
            ("git rev-parse --show-toplevel", None),
        ] {
            assert_eq!(static_output(body).as_deref(), want, "{body}");
        }
    }

    #[test]
    fn rewrite_evaluates_static_substitutions() {
        for (segment, want) in [
            ("$(echo git) push --force", "git push --force"),
            ("`echo git` push", "git push"),
            ("gh $(echo repo) delete o/r", "gh repo delete o/r"),
            ("$(echo rm .env)", "rm .env"),
            (".en$(echo)v", ".env"),
            ("cat .en$(echo v)", "cat .env"),
            ("x$(echo ' a')", "x a"),
            ("git push $(echo --force) origin", "git push --force origin"),
            ("eval \"$(echo 'cat .env')\"", "eval \"cat .env\""),
            ("x $(echo ';') y", "x ';' y"),
            ("x $(echo 'a b;c')", "x a 'b;c'"),
        ] {
            let got = rewrite(segment)
                .and_then(|r| r.evaluated)
                .unwrap_or_else(|| segment.to_string());
            assert_eq!(got, want, "{segment}");
        }
    }

    #[test]
    fn rewrite_leaves_what_it_cannot_read() {
        for segment in [
            "echo '$(echo git)'",
            "echo \\$(echo git)",
            "cat $(which python)",
            "echo $(echo $HOME)",
            "echo $((1 + 2))",
            "echo $(echo \"a$X\")",
            "echo \"$(echo 'a\"b')\"",
        ] {
            assert!(
                rewrite(segment).is_none_or(|r| r.evaluated.is_none()),
                "{segment}"
            );
        }
    }

    #[test]
    fn rewrite_globs_only_substitutions_glued_into_a_word() {
        for (segment, want) in [
            ("cat .env$(true)", Some("cat .env*")),
            ("echo x > .env$(: a b)", Some("echo x > .env*")),
            ("cat \"$(pwd)\"/.env", Some("cat \"*\"/.env")),
            ("cat .env`true`", Some("cat .env*")),
            ("cat x$(a)$(b)", Some("cat x**")),
            ("cat \"$(pwd)\"", None),
            ("cat $(pwd)", None),
            ("cd \"$(git rev-parse --show-toplevel)\" && ls", None),
            ("(cat $(x))", None),
            ("cat > $(mktemp)", None),
        ] {
            let got = rewrite(segment).and_then(|r| r.globbed);
            assert_eq!(got.as_deref(), want, "{segment}");
        }
    }

    #[test]
    fn unknown_substitution_names_the_command() {
        for (segment, want) in [
            ("$(which python) x.py", true),
            ("\"$(git rev-parse --show-toplevel)/x.sh\"", true),
            ("`which python` x.py", true),
            ("FOO=1 $(which x) y", true),
            ("gh $(which x) delete", true),
            ("git $(x) push", true),
            ("$(echo git) push", false),
            ("git push $(echo --force)", false),
            ("cat $(which python)", false),
            ("cd \"$(git rev-parse --show-toplevel)\"", false),
            ("echo $(date)", false),
            ("FOO=$(date) ls", false),
            ("git commit -m \"$(date)\"", false),
            ("ls", false),
        ] {
            assert_eq!(
                names_command_by_unknown_substitution(segment),
                want,
                "{segment}"
            );
        }
    }
}
