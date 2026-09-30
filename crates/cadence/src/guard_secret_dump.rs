//! Ask before a command prints a bare, unnamed secret value
//! (cameronsjo/cadence-hooks#776). PreToolUse, `Bash`, **Ask-only**.
//!
//! The backstop for `redact-secret-output`. That hook masks values by the
//! *name* printed beside them, so it is structurally blind to a command whose
//! output is the value alone. This guard covers exactly those producers:
//!
//! - `security find-generic-password|find-internet-password … -w` (macOS
//!   Keychain: prints the password and nothing else);
//! - `kubectl get secret … -o jsonpath|go-template|template|custom-columns`,
//!   `--template`, and `-o json|yaml` piped into `jq`/`yq` (the filter strips
//!   the key names the redactor masks by);
//! - `op read op://…` and `op item get … --reveal` (1Password);
//! - `vault read|kv get -field=…`, `aws secretsmanager get-secret-value`,
//!   `gcloud secrets versions access`, `pass show`.
//!
//! `Ask`, never `Block`: both motivating incidents were legitimate work, and
//! the prompt is its own escape hatch — so no bypass or dismiss exists.
//!
//! **Egress predicate — why this stays quiet on real work.** The top-level
//! pipeline is walked from the producing segment
//! (`split_segments_with_ops_joining_redirects`, so `&>` stays a redirect).
//! The value never reaches the transcript, and the guard says nothing, when:
//! - a segment in the pipeline sends stdout to a file (`> f`, `>> f`, `&> f`,
//!   `1> f`, `>/dev/null`) — not `>&2`, `/dev/stdout`, `/dev/stderr`,
//!   `/dev/tty`, `/dev/fd/*`, `/dev/pts/*` or `/proc/*/fd/*`, which still
//!   reach the terminal. A `tee` anywhere downstream counts as printing,
//!   whatever follows it;
//! - a downstream segment is a **terminal sink**: a hash (`shasum`,
//!   `sha256sum`, `md5sum`, `md5`, `b2sum`, `cksum`, `openssl dgst|sha*|md5`),
//!   `wc`, or `grep`/`egrep`/`fgrep`/`rg` with `-c`/`-q`/`-l`/`-L` (or their
//!   long forms);
//! - a downstream segment takes the secret on stdin by design
//!   (`--password-stdin`, `--with-token`).
//!
//! So `kubectl get secret s -o jsonpath='{.data.k}' | base64 -d | shasum` is
//! silent, and the same command without the hash asks.
//!
//! **Deliberately allowed (not asked about):**
//! - a producer inside a script FILE (`bash scripts/x.sh`), which the command
//!   text does not show. Producers inside `$(…)`, backticks, `<(…)`,
//!   `sh -c`/`bash -c` and `eval` ARE judged (core's read-only
//!   `child_scripts`), each against its own pipeline — but only where the
//!   child's output can reach the terminal: a wrapper that runs it, a printing
//!   command (`echo`, `cat`, `diff`, …), or a bare assignment/`export`
//!   (`X=$(op read …)` is one `echo $X` away). A substitution feeding another
//!   command's argument or here-string (`curl -H "…$(op read …)"`,
//!   `psql "…$(pass show …)"`, `docker login --password-stdin <<< "$(…)"`,
//!   `TOKEN=$(op read …) gh api …`) is allowed;
//! - `echo $(op read … | sha256sum)` asks: core's top-level splitter cuts the
//!   substitution at its inner pipe, so the hash cannot be proven to contain
//!   the value;
//! - `kubectl get secret -o yaml|json`: the output carries key names, which
//!   `redact-secret-output` masks;
//! - `sops -d`: owned by `guard-sops-decrypt` (a hard block);
//! - `op read --out-file|-o <f>`: the value goes to a file.
//!
//! Known accepted gap: `docker inspect -f '{{json .Config}}'` and other
//! producers whose output names its values are left to the redactor.
//!
//! Fails open (ADR-0001): no command means allow.

use cadence_hooks_core::shell::{
    MAX_WRAPPER_DEPTH, child_scripts, command_word, is_redirect_token, peel_command_runners,
    split_segments_with_ops_joining_redirects, strip_group_wrappers, tokenize,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Asks before a bare secret value is printed to the transcript.
pub struct SecretDumpGuard;

impl Check for SecretDumpGuard {
    fn name(&self) -> &str {
        "guard-secret-dump"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };
        match first_exposed_dump(command) {
            Some(producer) => CheckResult::ask(ask_message(producer)),
            None => CheckResult::allow(),
        }
    }
}

fn ask_message(producer: &str) -> String {
    format!(
        "🔑 guard-secret-dump: `{producer}` prints a bare secret value, and nothing in this \
         command keeps it out of the transcript.\n   \
         A value with no name beside it cannot be masked after the fact.\n   \
         To check it without printing it: pipe to `shasum` / `wc -c`, or `grep -q`.\n   \
         To use it: capture it (`X=$(…)`) or pipe it to a `--password-stdin` consumer.\n   \
         Approve only if the value itself must be shown."
    )
}

/// The label of the first bare-value producer whose stdout reaches the
/// transcript, or `None`.
pub fn first_exposed_dump(command: &str) -> Option<&'static str> {
    exposed_in(command, 0)
}

/// [`first_exposed_dump`] over one script, recursing into every child script
/// the shell runs from a segment — `$(…)`, backticks, `<(…)`, `sh -c`/`bash
/// -c`, `eval` — via core's read-only `child_scripts`, up to
/// `MAX_WRAPPER_DEPTH`. A producer inside a substitution is judged against its
/// own pipeline: `$(op read … | sha256sum)` is contained, `X=$(op read …)`
/// is not.
fn exposed_in(script: &str, depth: usize) -> Option<&'static str> {
    let segments = split_segments_with_ops_joining_redirects(script);
    let argvs: Vec<Vec<String>> = segments
        .iter()
        .map(|(segment, _)| {
            let tokens = tokenize(strip_group_wrappers(segment));
            peel_command_runners(&tokens).to_vec()
        })
        .collect();
    for (i, argv) in argvs.iter().enumerate() {
        if depth < MAX_WRAPPER_DEPTH {
            let stripped = strip_group_wrappers(&segments[i].0);
            let mut children = child_scripts(argv, stripped);
            children.extend(process_substitutions(stripped));
            // A child whose output only feeds another command's argument or
            // stdin (`curl -H "…$(op read …)"`, `psql "…$(pass show …)"`,
            // `docker login --password-stdin <<< "$(op read …)"`) never
            // reaches the terminal. Judge children only where their output can:
            // a wrapper that runs them (`sh -c`, `eval`), a printing command,
            // or a bare assignment (the value is one `echo $X` away).
            if !children.is_empty() && !child_output_can_print(stripped) {
                children.clear();
            }
            for child in children {
                if let Some(label) = exposed_in(&child, depth + 1) {
                    return Some(label);
                }
            }
        }
        let Some(label) =
            producer(argv).or_else(|| structured_secret_filtered(&segments, &argvs, i))
        else {
            continue;
        };
        if !pipeline_contains_it(&segments, &argvs, i) {
            return Some(label);
        }
    }
    None
}

/// Commands that print what they are given (as arguments or on stdin).
const PRINTERS: &[&str] = &[
    "echo", "printf", "print", "cat", "tac", "head", "tail", "less", "more", "diff", "grep",
    "egrep", "fgrep", "rg", "awk", "sed", "jq", "yq", "sort", "uniq", "tee", "xxd", "od",
    "hexdump", "base64", "column", "printenv", "nl", "fold", "cut", "tr", "strings", "rev",
    "paste", "pr", "fmt", "expand", "logger",
];

/// Commands that run their child script with the terminal as its stdout.
const WRAPPERS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "fish", "eval", "exec", "xargs", "watch", "source", ".",
];

/// Can the output of a child script in this segment reach the terminal?
/// True for a wrapper that runs it, a printing command, an unknown command
/// word (a variable or substitution), or a bare assignment / `export` (the
/// value is stored for a later `echo $X`).
fn child_output_can_print(segment: &str) -> bool {
    let Some(word) = segment_command_word(segment) else {
        return true;
    };
    let word = command_word(&word);
    word.is_empty()
        || word.starts_with(['$', '`', '(', '"', '\''])
        || matches!(
            word.as_ref(),
            "export" | "local" | "declare" | "readonly" | "typeset"
        )
        || WRAPPERS.contains(&word.as_ref())
        || PRINTERS.contains(&word.as_ref())
}

/// The command word of `segment` after its leading `NAME=value` assignments,
/// read from the text so a value holding `$(…)`, quotes or backticks is
/// skipped whole. `None` when the segment is assignments only.
fn segment_command_word(segment: &str) -> Option<String> {
    let mut rest = segment.trim_start();
    loop {
        let name_len = rest
            .chars()
            .take_while(|&c| c.is_ascii_alphanumeric() || c == '_')
            .count();
        let is_assignment = name_len > 0
            && rest[..name_len].starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && rest[name_len..].starts_with('=');
        if !is_assignment {
            break;
        }
        rest = skip_word(&rest[name_len + 1..]).trim_start();
    }
    let word: String = rest
        .chars()
        .take_while(|c| !c.is_whitespace() && !matches!(c, ';' | '|' | '&'))
        .collect();
    (!word.is_empty()).then_some(word)
}

/// `text` after one shell word, honouring quotes, backticks and `$(…)`
/// nesting (bounded by the text; an unclosed construct runs to the end).
fn skip_word(text: &str) -> &str {
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) => {
                if b == b'\\' && q != b'\'' {
                    i += 1;
                } else if b == q {
                    quote = None;
                } else if q == b'"' && b == b'$' && bytes.get(i + 1) == Some(&b'(') {
                    depth += 1;
                    i += 1;
                }
            }
            None => match b {
                b'\\' => i += 1,
                b'"' | b'\'' | b'`' => quote = Some(b),
                b'$' if bytes.get(i + 1) == Some(&b'(') => {
                    depth += 1;
                    i += 1;
                }
                b'(' if depth > 0 => depth += 1,
                b')' if depth > 0 => depth -= 1,
                c if depth == 0 && (c as char).is_ascii_whitespace() => break,
                _ => {}
            },
        }
        if quote.is_some() && depth > 0 && b == b')' {
            depth -= 1;
        }
        i += 1;
    }
    text.get(i.min(text.len())..).unwrap_or("")
}

/// Bodies of `<(…)` / `>(…)` process substitutions in `segment`, which core's
/// `child_scripts` does not return. Outside single quotes only; an unclosed
/// body (the splitter may have cut the segment at a `|` inside it) runs to
/// the end — erring toward judging more, never less.
fn process_substitutions(segment: &str) -> Vec<String> {
    let bytes = segment.as_bytes();
    let mut out = Vec::new();
    let mut in_single = false;
    let mut i = 0;
    while i + 1 < bytes.len() {
        match bytes[i] {
            b'\'' => in_single = !in_single,
            b'<' | b'>' if !in_single && bytes[i + 1] == b'(' => {
                let body_start = i + 2;
                let mut depth = 1;
                let mut j = body_start;
                while j < bytes.len() && depth > 0 {
                    match bytes[j] {
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        _ => {}
                    }
                    j += 1;
                }
                let body_end = if depth == 0 { j - 1 } else { bytes.len() };
                if let Some(body) = segment.get(body_start..body_end) {
                    out.push(body.to_string());
                }
                i = j;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// Does the pipeline starting at segment `start` keep the producer's stdout
/// out of the transcript?
fn pipeline_contains_it(
    segments: &[(String, Option<&'static str>)],
    argvs: &[Vec<String>],
    start: usize,
) -> bool {
    let mut i = start;
    loop {
        let argv = &argvs[i];
        // `tee` prints to its own file operands (`/dev/stderr`, `/dev/tty`)
        // as well as down the pipe: whatever follows it, treat it as printing.
        if i > start && argv.first().is_some_and(|w| command_word(w) == "tee") {
            return false;
        }
        if stdout_to_file(argv) {
            return true;
        }
        if i > start && (is_terminal_sink(argv) || takes_secret_on_stdin(argv)) {
            return true;
        }
        if segments[i].1 != Some("|") || i + 1 >= argvs.len() {
            return false;
        }
        i += 1;
    }
}

/// The producer label when `argv` prints a bare secret value.
fn producer(argv: &[String]) -> Option<&'static str> {
    let word = command_word(argv.first()?);
    let rest = &argv[1..];
    match word.as_ref() {
        "security" => {
            let finds = rest
                .iter()
                .any(|t| t == "find-generic-password" || t == "find-internet-password");
            let w_flag = rest.iter().any(|t| {
                t.len() > 1
                    && t.starts_with('-')
                    && !t.starts_with("--")
                    && t[1..].chars().all(|c| c.is_ascii_alphabetic())
                    && t.contains('w')
            });
            (finds && w_flag).then_some("security find-*-password -w")
        }
        "kubectl" => {
            let gets = rest.iter().any(|t| t == "get");
            let secret = rest.iter().any(|t| names_secret_resource(t));
            (gets && secret && bare_output_format(rest)).then_some("kubectl get secret -o jsonpath")
        }
        "op" => {
            // `-o`/`--out-file` keeps the value off the terminal only when the
            // target is a real file, not `/dev/stdout` and friends.
            let to_file = rest.iter().enumerate().any(|(i, t)| {
                let target = if t == "-o" || t == "--out-file" {
                    rest.get(i + 1).map(String::as_str)
                } else {
                    t.strip_prefix("--out-file=")
                };
                target.is_some_and(|f| !f.is_empty() && !is_terminal_path(f))
            });
            let reads = rest.iter().any(|t| t == "read")
                && rest.iter().any(|t| t.starts_with("op://"))
                && !to_file;
            let reveals = rest.windows(2).any(|w| w[0] == "item" && w[1] == "get")
                && rest.iter().any(|t| t == "--reveal");
            if reads {
                Some("op read")
            } else if reveals {
                Some("op item get --reveal")
            } else {
                None
            }
        }
        "vault" => {
            let reads = rest.first().is_some_and(|t| t == "read")
                || rest.windows(2).any(|w| w[0] == "kv" && w[1] == "get");
            let field = rest
                .iter()
                .any(|t| t == "-field" || t.starts_with("-field=") || t.starts_with("--field"));
            (reads && field).then_some("vault read -field")
        }
        "aws" => {
            let gets = rest.iter().any(|t| t == "secretsmanager")
                && rest.iter().any(|t| t == "get-secret-value");
            gets.then_some("aws secretsmanager get-secret-value")
        }
        "gcloud" => {
            let access = rest
                .windows(3)
                .any(|w| w[0] == "secrets" && w[1] == "versions" && w[2] == "access");
            access.then_some("gcloud secrets versions access")
        }
        "pass" => rest
            .iter()
            .find(|t| !t.starts_with('-'))
            .is_some_and(|t| t == "show")
            .then_some("pass show"),
        _ => None,
    }
}

/// `kubectl get secret -o json|yaml` piped into `jq`/`yq`: the filter strips
/// the key names the redactor would mask by, so the value comes out bare.
fn structured_secret_filtered(
    segments: &[(String, Option<&'static str>)],
    argvs: &[Vec<String>],
    start: usize,
) -> Option<&'static str> {
    let argv = &argvs[start];
    if argv.first().is_none_or(|w| command_word(w) != "kubectl") {
        return None;
    }
    let rest = &argv[1..];
    let structured = rest.iter().any(|t| t == "get")
        && rest.iter().any(|t| names_secret_resource(t))
        && output_format(rest).is_some_and(|f| f == "json" || f == "yaml");
    if !structured {
        return None;
    }
    let mut i = start;
    while segments[i].1 == Some("|") && i + 1 < argvs.len() {
        i += 1;
        if argvs[i]
            .first()
            .is_some_and(|w| matches!(command_word(w).as_ref(), "jq" | "yq" | "gojq" | "jaq"))
        {
            return Some("kubectl get secret -o json|yaml | jq");
        }
    }
    None
}

/// The `-o`/`--output` value, whichever spelling.
fn output_format(rest: &[String]) -> Option<&str> {
    rest.iter().enumerate().find_map(|(i, t)| {
        if t == "-o" || t == "--output" {
            rest.get(i + 1).map(String::as_str)
        } else if let Some(v) = t.strip_prefix("--output=") {
            Some(v)
        } else {
            t.strip_prefix("-o")
                .map(|v| v.strip_prefix('=').unwrap_or(v))
        }
    })
}

/// `secret`, `secrets`, `secret/<name>`, or a comma list naming one.
fn names_secret_resource(token: &str) -> bool {
    token.split(',').any(|part| {
        let kind = part.split('/').next().unwrap_or(part);
        matches!(kind, "secret" | "secrets")
    })
}

/// An output mode that prints bare field values: `-o jsonpath|go-template|
/// template|custom-columns…` in any spelling, or `--template`.
fn bare_output_format(rest: &[String]) -> bool {
    let is_bare = |value: &str| {
        ["jsonpath", "go-template", "template", "custom-columns"]
            .iter()
            .any(|f| value.starts_with(f))
    };
    output_format(rest).is_some_and(is_bare)
        || rest
            .iter()
            .any(|t| t == "--template" || t.starts_with("--template="))
}

/// Does `argv` redirect its stdout to a file (so nothing reaches the
/// terminal)? Reads each redirect token's descriptor and target.
fn stdout_to_file(argv: &[String]) -> bool {
    let mut i = 0;
    while i < argv.len() {
        let token = &argv[i];
        if !is_redirect_token(token) {
            i += 1;
            continue;
        }
        let both = token.starts_with("&>");
        let body = token.trim_start_matches('&');
        let digits: String = body.chars().take_while(char::is_ascii_digit).collect();
        let after_fd = &body[digits.len()..];
        let is_stdout = both || digits.is_empty() || digits == "1";
        let op_len = after_fd
            .chars()
            .take_while(|c| matches!(c, '>' | '|'))
            .count();
        let writes = after_fd.starts_with('>');
        let glued = &after_fd[op_len..];
        // `>&2`: stdout duplicated onto stderr — still the terminal.
        let dup = glued.starts_with('&');
        let target = if glued.is_empty() {
            i += 1;
            argv.get(i).map(String::as_str).unwrap_or("")
        } else {
            glued
        };
        if is_stdout && writes && !dup && !target.is_empty() && !is_terminal_path(target) {
            return true;
        }
        i += 1;
    }
    false
}

/// A path that is the terminal, not a file: writing there prints.
fn is_terminal_path(target: &str) -> bool {
    matches!(target, "/dev/stdout" | "/dev/stderr" | "/dev/tty")
        || target.starts_with("/dev/fd/")
        || target.starts_with("/dev/pts/")
        || (target.starts_with("/proc/") && target.contains("/fd/"))
}

/// A consumer whose output cannot carry the value: a hash, a count, or a
/// quiet/list-only grep.
fn is_terminal_sink(argv: &[String]) -> bool {
    let Some(first) = argv.first() else {
        return false;
    };
    let word = command_word(first);
    let rest = &argv[1..];
    match word.as_ref() {
        "shasum" | "sha1sum" | "sha224sum" | "sha256sum" | "sha384sum" | "sha512sum" | "md5sum"
        | "md5" | "b2sum" | "cksum" | "wc" => true,
        "openssl" => rest.first().is_some_and(|sub| {
            matches!(
                sub.as_str(),
                "dgst" | "sha1" | "sha256" | "sha384" | "sha512" | "md5"
            )
        }),
        "grep" | "egrep" | "fgrep" | "rg" => rest.iter().any(|t| {
            matches!(
                t.as_str(),
                "--count"
                    | "--quiet"
                    | "--silent"
                    | "--files-with-matches"
                    | "--files-without-match"
            ) || (t.len() > 1
                && t.starts_with('-')
                && !t.starts_with("--")
                && t[1..].chars().all(|c| c.is_ascii_alphabetic())
                && t[1..].chars().any(|c| matches!(c, 'c' | 'q' | 'l' | 'L')))
        }),
        _ => false,
    }
}

/// A consumer that reads the secret from stdin by design and does not echo it.
fn takes_secret_on_stdin(argv: &[String]) -> bool {
    argv.iter()
        .any(|t| t == "--password-stdin" || t == "--with-token")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposed_dumps_ask() {
        let cases: &[(&str, &str)] = &[
            (
                "security find-generic-password -s svc -a me -w",
                "security find-*-password -w",
            ),
            (
                "security find-internet-password -s host -w | cat",
                "security find-*-password -w",
            ),
            (
                "sudo security find-generic-password -ws svc",
                "security find-*-password -w",
            ),
            (
                "kubectl get secret app -o jsonpath='{.data.token}' | base64 -d",
                "kubectl get secret -o jsonpath",
            ),
            (
                "kubectl -n prod get secrets/app -ojsonpath={.data.k}",
                "kubectl get secret -o jsonpath",
            ),
            (
                "kubectl get secret app --output=go-template='{{.data.k}}'",
                "kubectl get secret -o jsonpath",
            ),
            (
                "kubectl get secret app --output jsonpath={.data}",
                "kubectl get secret -o jsonpath",
            ),
            ("op read op://vault/item/password", "op read"),
            ("op read 'op://vault/item/password' >&2", "op read"),
            ("op read op://v/i/f > /dev/stdout", "op read"),
            (
                "op item get db --fields password --reveal",
                "op item get --reveal",
            ),
            (
                "echo start; security find-generic-password -s x -w && echo done",
                "security find-*-password -w",
            ),
            // A sink before the producer does not protect it.
            ("echo x | shasum; op read op://v/i/f", "op read"),
            // grep that prints matching lines is not a sink.
            ("op read op://v/i/f | grep -i abc", "op read"),
            // Gate 2 (#776 review): tee and terminal paths print.
            (
                "security find-generic-password -s svc -w | tee /dev/stderr | sha256sum",
                "security find-*-password -w",
            ),
            (
                "security find-generic-password -s svc -w | tee x | docker login --password-stdin",
                "security find-*-password -w",
            ),
            (
                "security find-generic-password -s svc -w > /proc/self/fd/1",
                "security find-*-password -w",
            ),
            (
                "security find-generic-password -s svc -w >/dev/fd/1",
                "security find-*-password -w",
            ),
            ("op read op://v/i/f -o /dev/stdout", "op read"),
            ("op read op://v/i/f --out-file /dev/stdout", "op read"),
            ("op read op://v/i/f --out-file=/dev/stdout", "op read"),
            ("op read op://v/i/f -o /dev/stderr", "op read"),
            // Gate 2: more bare-value producers.
            (
                "kubectl get secret s --template='{{.data.p}}'",
                "kubectl get secret -o jsonpath",
            ),
            (
                "kubectl get secret s -o custom-columns=P:.data.p",
                "kubectl get secret -o jsonpath",
            ),
            (
                "kubectl get secret s -o json | jq -r .data.p | base64 -d",
                "kubectl get secret -o json|yaml | jq",
            ),
            (
                "kubectl get secret s -o yaml | yq .data.p",
                "kubectl get secret -o json|yaml | jq",
            ),
            ("vault kv get -field=password secret/x", "vault read -field"),
            ("vault read -field=value secret/x", "vault read -field"),
            (
                "aws secretsmanager get-secret-value --secret-id x --query SecretString --output text",
                "aws secretsmanager get-secret-value",
            ),
            (
                "gcloud secrets versions access latest --secret=x",
                "gcloud secrets versions access",
            ),
            ("pass show x", "pass show"),
            // Round 2: producers inside substitutions and wrappers.
            ("echo $(op read op://v/i/f)", "op read"),
            (
                "echo \"$(kubectl get secret s -o jsonpath={.data.p} | base64 -d)\"",
                "kubectl get secret -o jsonpath",
            ),
            ("echo `pass show x`", "pass show"),
            ("sh -c 'pass show x'", "pass show"),
            ("bash -c 'op read op://v/i/f'", "op read"),
            ("eval 'vault kv get -field=p secret/x'", "vault read -field"),
            (
                "X=$(security find-generic-password -s svc -w); echo $X",
                "security find-*-password -w",
            ),
            ("cat <(pass show x)", "pass show"),
            ("cat <<< \"$(op read op://v/i/f)\"", "op read"),
            // The top-level splitter cuts `$(… | …)` at its inner pipe, so a
            // hash inside a substitution cannot be proven to contain the
            // value: ask rather than guess.
            ("echo $(op read op://v/i/f | sha256sum)", "op read"),
        ];
        for (command, want) in cases {
            assert_eq!(first_exposed_dump(command), Some(*want), "{command}");
        }
    }

    #[test]
    fn contained_or_unrelated_commands_stay_silent() {
        let cases: &[&str] = &[
            "kubectl get secret app -o jsonpath='{.data.token}' | base64 -d | shasum",
            "kubectl get secret app -o jsonpath='{.data.token}' | wc -c",
            "security find-generic-password -s svc -w | sha256sum",
            "security find-generic-password -s svc -w > /tmp/pw",
            "security find-generic-password -s svc -w >/dev/null",
            "security find-generic-password -s svc -w &>/dev/null",
            "security find-generic-password -s svc -w | docker login -u me --password-stdin",
            "op read op://v/i/token | gh auth login --with-token",
            "op read op://v/i/f | grep -q expected",
            "op read op://v/i/f | grep -c x",
            "op read op://v/i/f | openssl dgst -sha256",
            "op read --out-file /tmp/f op://v/i/f",
            "op read -o /tmp/f op://v/i/f",
            // Round 3: a substitution consumed as an argument or here-string
            // of a non-printing command never reaches the terminal.
            "TOKEN=$(op read op://v/i/f) gh api user",
            "curl -H \"Authorization: Bearer $(op read op://v/i/f)\" https://x",
            "psql \"postgres://u:$(pass show db)@h/db\"",
            "docker login --password-stdin <<< \"$(op read op://v/i/f)\"",
            "gh auth login --with-token < <(op read op://v/i/f)",
            "kubectl get secret s -o json | jq -r .data.p | base64 -d | sha256sum",
            "vault kv get secret/x",
            "pass ls",
            // Output names its values: the redactor's job.
            "kubectl get secret app -o yaml",
            "kubectl get secret app -o json",
            "kubectl get pods -o jsonpath='{.items[*].metadata.name}'",
            // Not a -w read.
            "security find-generic-password -s svc",
            "op item get db --fields username",
            "op item list",
            // Prose, not a command.
            "echo 'security find-generic-password -w'",
            "git commit -m 'op read op://x'",
            "",
        ];
        for command in cases {
            assert_eq!(first_exposed_dump(command), None, "{command}");
        }
    }

    #[test]
    fn check_asks_with_message() {
        let input = HookInput::from_json(
            r#"{"tool_name":"Bash","tool_input":{"command":"op read op://v/i/f"}}"#,
        )
        .unwrap();
        let result = SecretDumpGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Ask);
        assert!(result.message.unwrap().contains("op read"));

        let quiet =
            HookInput::from_json(r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#).unwrap();
        assert_eq!(
            SecretDumpGuard.run(&quiet).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn adversarial_200kb_command_stays_fast() {
        let long = format!("op read op://v/i/f{}", " | cat".repeat(40_000));
        let started = std::time::Instant::now();
        assert_eq!(first_exposed_dump(&long), Some("op read"));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
}
