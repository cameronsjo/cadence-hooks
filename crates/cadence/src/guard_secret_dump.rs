//! Ask before a command prints a bare, unnamed secret value
//! (cameronsjo/cadence-hooks#776). PreToolUse, `Bash`, **Ask-only**.
//!
//! The backstop for `redact-secret-output`. That hook masks values by the
//! *name* printed beside them, so it is structurally blind to a command whose
//! output is the value alone. This guard covers exactly those producers:
//!
//! - `security find-generic-password|find-internet-password … -w` (macOS
//!   Keychain: prints the password and nothing else);
//! - `kubectl get secret … -o jsonpath=…|go-template=…|template=…` (no key name
//!   in the output);
//! - `op read op://…` and `op item get … --reveal` (1Password: a bare value).
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
//!   `/dev/tty`, which still reach the terminal;
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
//! - a producer inside a command substitution (`X=$(security … -w)`,
//!   `gh … --token "$(op read …)"`): the value is captured, not printed. Only
//!   top-level segments are judged, which is also why
//! - a producer inside a shell wrapper (`bash -c '…'`) or a script is unseen —
//!   the wrapper and substitution readers in `core::shell` return both kinds
//!   of child together, and splitting them is a parser change this guard does
//!   not make;
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
    command_word, is_redirect_token, peel_command_runners,
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
    let segments = split_segments_with_ops_joining_redirects(command);
    let argvs: Vec<Vec<String>> = segments
        .iter()
        .map(|(segment, _)| {
            let tokens = tokenize(strip_group_wrappers(segment));
            peel_command_runners(&tokens).to_vec()
        })
        .collect();
    for (i, argv) in argvs.iter().enumerate() {
        let Some(label) = producer(argv) else {
            continue;
        };
        if !pipeline_contains_it(&segments, &argvs, i) {
            return Some(label);
        }
    }
    None
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
            let to_file = rest
                .iter()
                .any(|t| t == "-o" || t == "--out-file" || t.starts_with("--out-file="));
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
        _ => None,
    }
}

/// `secret`, `secrets`, `secret/<name>`, or a comma list naming one.
fn names_secret_resource(token: &str) -> bool {
    token.split(',').any(|part| {
        let kind = part.split('/').next().unwrap_or(part);
        matches!(kind, "secret" | "secrets")
    })
}

/// A `-o`/`--output` value that prints bare field values.
fn bare_output_format(rest: &[String]) -> bool {
    let is_bare = |value: &str| {
        ["jsonpath", "go-template", "template"]
            .iter()
            .any(|f| value.starts_with(f))
    };
    rest.iter().enumerate().any(|(i, t)| {
        let next = rest.get(i + 1).map(String::as_str);
        if t == "-o" || t == "--output" {
            next.is_some_and(is_bare)
        } else if let Some(v) = t.strip_prefix("--output=") {
            is_bare(v)
        } else if let Some(v) = t.strip_prefix("-o") {
            is_bare(v.strip_prefix('=').unwrap_or(v))
        } else {
            false
        }
    })
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

fn is_terminal_path(target: &str) -> bool {
    matches!(
        target,
        "/dev/stdout" | "/dev/stderr" | "/dev/tty" | "/dev/fd/1" | "/dev/fd/2"
    )
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
            // Captured by substitution: never printed.
            "TOKEN=$(op read op://v/i/f) gh api user",
            "export PW=\"$(security find-generic-password -s svc -w)\"",
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
