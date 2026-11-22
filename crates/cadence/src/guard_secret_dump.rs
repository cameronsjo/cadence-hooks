//! Block a command that prints a bare, unnamed secret value, and ask before
//! one hands it to a consumer (cameronsjo/cadence-hooks#776, #1662).
//! PreToolUse, `Bash`.
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
//! **Where the value goes decides the verdict** (#1662, cadence-ecosystem
//! ADR-0046 rule 2: a secret entering the context is a block kind, because a
//! leaked value has to be rotated and a rotation cannot be undone):
//! - **to the context → block.** The producer's stdout is the command's own
//!   output (it ends its pipeline, or every later stage is a [`PASS_THROUGH`]
//!   command, with no redirect to a real file; `>&2` and terminal paths still
//!   print), or a pass-through command is fed the value (here-string, `<(…)`,
//!   heredoc body), or the value is a substitution in an argument word of
//!   `echo`/`printf`/`print` (not `-v`, a redirect word or its target, or a
//!   process-substitution word), or the first word is exactly one
//!   substitution (the shell reports the value as an unknown command), or a
//!   `sh -c`/`eval` script prints it to that output. Never confirm-tier.
//!   `op inject` with no output file and a producer behind the perl timeout
//!   runner count only here (review round 1).
//!
//!   **The taint rule** (#1663 review round 3): whether a producer form's
//!   output carries a value is decided at the producer alone (the
//!   per-executable tables, [`CLOUD_READS`], the kubectl selectors that reach
//!   data). From there every later `jq`, `yq` or [`PASS_THROUGH`] stage
//!   keeps the value, whatever its filter, script or selection says (`sed
//!   -n 1p` and `tail -n +2` included). The guard reads no filter to call a
//!   stage safe, with one exception: a bare `jq .`, with options that keep
//!   each key beside its value, after the two cloud reads the redactor is
//!   proven to mask keeps their ask ([`keeps_names`]). So `… --query SecretString --output text |
//!   jq -r .password`, `kubectl get secrets -o json | jq '.items[] |
//!   select(…)'` and `kubectl get secret s -o json | jq '.metadata.name'` all
//!   block. Names and metadata come from kubectl's own selectors (`-o name`,
//!   a jsonpath, custom-columns or go-template naming only metadata, `type`,
//!   `kind` or counts), which keep main's verdict.
//! - **to a consumer → ask, unchanged.** A pipe into a program outside the
//!   pass-through table, a substitution used as an argument (including of a
//!   command named by a variable, `$HOME/bin/tool --token "$(…)"`),
//!   assignment, `printf -v` or inline prefix, a here-string or heredoc fed to
//!   such a program, a process substitution, a clipboard flag, and a default
//!   output the redactor masks ([`never_printed`]). The guard cannot prove the
//!   consumer quiet, so the prompt stays; it must not become a block.
//! - **contained → silent**, as below.
//!
//! The limit: a consumer outside the pass-through table that prints what it
//! receives, a later command that prints a variable (`X=$(…); echo $X`), a
//! remote command (`ssh h "echo $(…)"`), and a print inside a script file are
//! outside what one command's text shows, and keep the ask or pass. A script
//! inside a `{ … }`/`( … )` group keeps the ask too: the group's redirect is
//! not visible per segment.
//!
//! No escape variable: `CADENCE_DISABLE=guard-secret-dump` (this guard is not
//! protected) and `CADENCE_BYPASS=1` in the hook's environment are the
//! existing ways for a person to see a value through Claude.
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
//! - the pipeline's LAST stage is a pure hash (`shasum`, `sha*sum`, `md5sum`,
//!   `md5`, `b2sum`, `cksum`), judged by command word alone.
//!
//! Nothing else counts, by design: counters and quiet greps need flag parsing,
//! and every "consumer that takes the secret on stdin" exemption
//! (`--password-stdin`, `--with-token`) produced bypasses over three review
//! rounds, so `op read … | docker login --password-stdin` asks too.
//!
//! So `kubectl get secret s -o jsonpath='{.data.k}' | base64 -d | shasum` is
//! silent, and the same command without the hash asks.
//!
//! **Deliberately allowed (not asked about):**
//! - a producer inside a script FILE (`bash scripts/x.sh`), which the command
//!   text does not show. Producers inside `$(…)`, backticks, `<(…)`,
//!   `sh -c`/`bash -c` and `eval` ARE judged (core's read-only
//!   `child_scripts`), each against its own pipeline, whatever consumes the
//!   substitution: an argument can be printed by the command itself, a runner
//!   (`sudo echo`, `env … printenv`), `set -x` or a verbose flag, so a
//!   "safe consumer" allow list only generated bypasses and was cut (review
//!   round 4), as was the later login-stdin exemption (round 6);
//! - `echo $(op read … | sha256sum)` asks: core's top-level splitter cuts the
//!   substitution at its inner pipe, so the hash cannot be proven to contain
//!   the value;
//! - `kubectl get secret -o yaml|json` that feeds a consumer or a file keeps
//!   main's verdict; printed, through any `jq`/`yq` filter or none, it
//!   blocks, because the redactor leaves ordinary key names (`config.json`,
//!   `DATABASE_URL`) unmasked and base64 is not masking (review rounds 2
//!   and 3). `kubectl describe secret` keeps main's verdict;
//! - `sops -d`: owned by `guard-sops-decrypt` (a hard block);
//! - `op read --out-file|-o <f>`: the value goes to a file.
//!
//! Known accepted gap: `docker inspect -f '{{json .Config}}'` and other
//! producers whose output names its values are left to the redactor.
//!
//! Fails open (ADR-0001): no command means allow.

use cadence_hooks_core::shell::{
    MAX_WRAPPER_DEPTH, child_scripts, command_word, is_redirect_token, peel_command_runners,
    split_segments_with_ops_joining_redirects, strip_group_wrappers, substitution_bodies, tokenize,
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
        match judge(command) {
            Some(Finding {
                label,
                exposure: Exposure::Printed,
            }) => CheckResult::block(block_message(label)),
            Some(Finding {
                label,
                exposure: Exposure::Exposed,
            }) => CheckResult::ask(ask_message(label)),
            None => CheckResult::allow(),
        }
    }
}

/// Where a producer's bare value goes, as far as one command's text shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exposure {
    /// The value lands in the command's own output, so it enters the
    /// conversation context: a block (cameronsjo/cadence-hooks#1662).
    Printed,
    /// The value goes to a consumer (a pipe, a substitution used as an
    /// argument or assignment, a here-string, a process substitution) that
    /// the guard cannot prove keeps it quiet: an ask, as before.
    Exposed,
}

/// A producer and where its value goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Finding {
    pub label: &'static str,
    pub exposure: Exposure,
}

fn block_message(producer: &str) -> String {
    let kubectl = if producer.starts_with("kubectl") {
        "\nFor a Secret's names or metadata, use kubectl's own selector, not jq or yq (any \
         filter on a Secret's json or yaml counts as printing it): `-o name`, or \
         `-o jsonpath='{.metadata.name}'`; `kubectl describe secret <name>` shows key names and \
         sizes, not values."
    } else {
        ""
    };
    format!(
        "BLOCKED: guard-secret-dump\n\
         Found: `{producer}` would print a bare secret value into this conversation, and a \
         secret that reaches the context is leaked and has to be rotated.\n\
         Fix: hand the value to the program that needs it without printing it: pipe it in \
         (`… | docker login --password-stdin`), put it on the clipboard (`… | pbcopy`), or \
         pass it by reference so the consumer resolves it (`op run -- <cmd>`, \
         `TOKEN=\"$(op read …)\" <cmd>`). The clipboard, a pipe into a login and an inline \
         variable still raise a permission prompt; the tool's own run form (`op run -- <cmd>`) \
         does not. To check a value without seeing it, end the pipeline with `shasum`.{kubectl}"
    )
}

fn ask_message(producer: &str) -> String {
    format!(
        "🔑 guard-secret-dump: `{producer}` reads a bare secret value and hands it to a \
         program the guard cannot prove keeps it quiet.\n   \
         A value with no name beside it cannot be masked after the fact.\n   \
         To check it without printing it: end the pipeline with `shasum`, or \
         redirect it to a file.\n   \
         Approve if the value only feeds a command that will not print it \
         (`--password-stdin`, an API header), or if it must be shown."
    )
}

/// The label of the first bare-value producer [`judge`] finds printed or
/// exposed, whichever verdict it gets, or `None`.
pub fn first_exposed_dump(command: &str) -> Option<&'static str> {
    judge(command).map(|finding| finding.label)
}

/// The verdict for `command`: the first producer whose value is printed
/// ([`Exposure::Printed`]), else the first whose value reaches a consumer the
/// guard cannot prove quiet ([`Exposure::Exposed`]), else `None`.
pub fn judge(command: &str) -> Option<Finding> {
    let mut first_exposed = None;
    let printed = exposed_in(command, 0, true, false, &mut first_exposed);
    printed
        .map(|label| Finding {
            label,
            exposure: Exposure::Printed,
        })
        .or_else(|| {
            first_exposed.map(|label| Finding {
                label,
                exposure: Exposure::Exposed,
            })
        })
}

/// Commands that print their arguments: a substitution in one of their
/// argument words lands in their output ([`printed_bodies`] excludes
/// `printf -v`, redirect words and process substitutions). Three builtins,
/// `echo`, `printf` and zsh `print`; any other program that takes the value as
/// an argument is a consumer (cameronsjo/cadence-hooks#1662).
const ARGUMENT_PRINTERS: &[&str] = &["echo", "printf", "print"];

/// Pass-through commands: they copy what they read from stdin to stdout,
/// possibly transformed, and have no destination of their own. A pipeline
/// whose stages after the producer all pass it through, the last printing,
/// prints the value (cameronsjo/cadence-hooks#1663 review round 1). One row
/// per executable says which options take a value and which operand is the
/// command's own script; see [`PassThrough`].
const PASS_THROUGH: &[PassThrough] = &[
    PassThrough {
        name: "cat",
        valued: &[],
        script: false,
    },
    PassThrough {
        name: "tee",
        valued: &[],
        script: false,
    },
    PassThrough {
        name: "head",
        valued: &["-n", "-c"],
        script: false,
    },
    PassThrough {
        name: "tail",
        valued: &["-n", "-c"],
        script: false,
    },
    PassThrough {
        name: "base64",
        valued: &["-w", "-b", "--wrap", "--break"],
        script: false,
    },
    PassThrough {
        name: "xxd",
        valued: &["-c", "-g", "-l", "-o", "-s", "-n"],
        script: false,
    },
    PassThrough {
        name: "od",
        valued: &["-A", "-j", "-N", "-t", "-w"],
        script: false,
    },
    PassThrough {
        name: "jq",
        valued: JQ_VALUED,
        script: true,
    },
    PassThrough {
        name: "gojq",
        valued: JQ_VALUED,
        script: true,
    },
    PassThrough {
        name: "jaq",
        valued: JQ_VALUED,
        script: true,
    },
    PassThrough {
        name: "yq",
        valued: &[
            "--arg",
            "-p",
            "-o",
            "-I",
            "--indent",
            "--input-format",
            "--output-format",
        ],
        script: true,
    },
    PassThrough {
        name: "tr",
        valued: &[],
        script: false,
    },
    PassThrough {
        name: "sed",
        valued: &["-e", "-f", "--expression", "--file"],
        script: true,
    },
    PassThrough {
        name: "cut",
        valued: &["-d", "-f", "-c", "-b"],
        script: false,
    },
];

/// jq-family options that take a value (`--arg`, `--argjson`, `--slurpfile`
/// and `--rawfile` take two, so the filter is the word after both).
const JQ_VALUED: &[&str] = &[
    "--arg",
    "--argjson",
    "--slurpfile",
    "--rawfile",
    "--indent",
    "-f",
    "--from-file",
    "-L",
];

/// One [`PASS_THROUGH`] row: the options that take a separate value, and
/// whether the first operand is the command's own script or filter (`jq`,
/// `yq`, `sed`) rather than a file.
struct PassThrough {
    name: &'static str,
    valued: &'static [&'static str],
    script: bool,
}

/// Does `argv` copy its stdin to its stdout? Its row must be in
/// [`PASS_THROUGH`], and none of these may hold:
/// - a file operand other than `-` (the command then reads that file, not
///   stdin; `tee`'s operands are outputs, so they do not count);
/// - an option that writes elsewhere: `base64 -o`, `-i`/`--input`, `sed -i`
///   in any cluster, `yq -i`/`--inplace`, `xxd` with an output operand.
///
/// A script, filter or selection is not read: the guard cannot prove one
/// drops the value, so `jq keys`, `jq '.items[] | select(…)'`,
/// `jq 'map_values(@base64d)'`, `sed -n 1p` and `tail -n +2` all pass it
/// through (the taint rule, #1663 review rounds 3 and 4; a multi-line value
/// such as a key or a `pass` entry's later lines is printed by them).
fn is_pass_through(argv: &[String]) -> bool {
    copies_input(argv, false)
}

/// [`is_pass_through`], or with `fed` also accepting `<(…)` operands as input:
/// a pass-through command prints what it reads, stdin or such a file.
fn copies_input(argv: &[String], fed: bool) -> bool {
    let Some(first) = argv.first() else {
        return false;
    };
    let word = command_word(first);
    let Some(row) = PASS_THROUGH.iter().find(|r| r.name == word.as_ref()) else {
        return false;
    };
    let mut rest: &[String] = &argv[1..];
    if row.name == "yq" && rest.first().is_some_and(|t| t == "e" || t == "eval") {
        rest = &rest[1..];
    }
    let mut operands: Vec<&str> = Vec::new();
    let mut script_given = false;
    let mut i = 0;
    while i < rest.len() {
        let t = rest[i].as_str();
        if t.starts_with("<<<") {
            // A here-string feeds stdin; the tokenizer may split its word, so
            // the words after it are read as that word, not as operands.
            break;
        }
        if t.starts_with("<(") || t.starts_with(">(") {
            // A process substitution, which the tokenizer splits at its
            // blanks: `<(…)` is a file operand, read below from the raw
            // text by `fed_bodies`; `>(…)` is an output. Skip its words.
            let mut depth = 0i64;
            while i < rest.len() {
                let word = rest[i].as_str();
                depth += word.matches('(').count() as i64 - word.matches(')').count() as i64;
                i += 1;
                if depth <= 0 {
                    break;
                }
            }
            if t.starts_with("<(") && row.name != "tee" {
                operands.push(if fed { "-" } else { "<(…)" });
            }
            continue;
        }
        if is_redirect_token(t) {
            // A redirect and, when it stands alone, its target are not
            // operands (`cat <<< "$(…)"`, `cat > f`).
            let alone = t
                .trim_start_matches(|c: char| c.is_ascii_digit() || c == '&')
                .trim_start_matches(['<', '>', '|', '&'])
                .is_empty();
            // `cat < <(…)`: a process substitution as the target is read by
            // its own branch above.
            let procsub_next = rest.get(i + 1).is_some_and(|n| n.starts_with("<("));
            i += if alone && !procsub_next { 2 } else { 1 };
            continue;
        }
        // `tail +2` is the old spelling of `tail -n +2`, an option.
        let tail_offset = row.name == "tail" && t.starts_with('+');
        if !tail_offset && (t == "-" || !t.starts_with('-') || t.len() == 1) {
            operands.push(t);
            i += 1;
            continue;
        }
        if t == "--" {
            operands.extend(rest[i + 1..].iter().map(String::as_str));
            break;
        }
        let drops_or_diverts = match row.name {
            "base64" => {
                matches!(t, "-o" | "--output" | "-i" | "--input")
                    || t.starts_with("--output=")
                    || t.starts_with("--input=")
            }
            "sed" => t.starts_with("--in-place") || (!t.starts_with("--") && t.contains('i')),
            "yq" => t == "-i" || t == "--inplace",
            _ => false,
        };
        if drops_or_diverts {
            return false;
        }
        // The script comes from an option, so every operand is input: `sed
        // -e`/`-f`, `jq -f filter.jq data.json` reads `data.json` (code
        // review of round 3).
        let script_option = match row.name {
            "sed" => matches!(t, "-e" | "--expression" | "-f" | "--file"),
            "jq" | "gojq" | "jaq" => {
                matches!(t, "-f" | "--from-file") || t.starts_with("--from-file=")
            }
            _ => false,
        };
        if script_option {
            script_given = true;
        }
        let two = row.script
            && row.name != "sed"
            && matches!(t, "--arg" | "--argjson" | "--slurpfile" | "--rawfile");
        i += if two {
            3
        } else if row.valued.contains(&t) {
            2
        } else {
            1
        };
    }
    if row.script && !script_given {
        // The first operand is the script: the jq/yq filter (none means `.`)
        // or the sed script. Its text is never read: whatever a jq or yq
        // filter says, the stage keeps the value (#1663 review round 3).
        if operands.is_empty() {
            if row.name == "sed" {
                return false;
            }
        } else {
            operands.remove(0);
        }
    }
    match row.name {
        "tee" | "tr" => true,
        "xxd" => operands.iter().all(|o| *o == "-") && operands.len() <= 1,
        _ => operands.iter().all(|o| *o == "-"),
    }
}

/// A producer form whose value never reaches the context through its own
/// output, so it keeps main's verdict and never blocks:
/// - a help or version call on any producer ([`help_or_version`]);
/// - a clipboard flag on `pass`, `gopass` or `lpass` (the value goes to the
///   clipboard);
/// - a cloud CLI read whose output hides the value ([`cloud_value_hidden`]);
/// - a kubectl selector that does not reach a Secret's data
///   ([`selector_reaches_data`]), or whose type position names no Secret
///   ([`kubectl_gets_secret`]).
///
/// `keeps_names` says every later stage keeps the key names, and
/// `env_format` is an output-format variable set before the command
/// (`AWS_DEFAULT_OUTPUT=text`, `AZURE_CORE_OUTPUT=tsv`).
fn never_printed(argv: &[String], keeps_names: bool, env_format: Option<&str>) -> bool {
    let Some(first) = argv.first() else {
        return false;
    };
    let rest = &argv[1..];
    if help_or_version(rest) {
        return true;
    }
    let word = command_word(first);
    let clip = |t: &String| {
        t == "--clip"
            || t.starts_with("--clip=")
            // `-c`, `-c2`, or a letter cluster holding `c` (`-co`).
            || (t.starts_with('-')
                && !t.starts_with("--")
                && t[1..].contains('c')
                && t[1..].chars().all(|c| c.is_ascii_alphanumeric()))
    };
    match word.as_ref() {
        "pass" | "gopass" | "lpass" => rest.iter().any(clip),
        "az" | "aws" => cloud_value_hidden(&word, rest, keeps_names, env_format),
        "kubectl" => {
            bare_output_format(rest) && (!selector_reaches_data(rest) || !kubectl_gets_secret(rest))
        }
        _ => false,
    }
}

/// `-h`, `-help`, `--help`, `--version`, a `help` as the last word
/// (`aws … get-secret-value help`) or a `version` as the first (`bw
/// version`): the call prints usage or a version, not a value. One rule for
/// every producer (review round 2). A bare word elsewhere can be an item
/// name (`pass show version`) and is not read as help.
fn help_or_version(rest: &[String]) -> bool {
    let last = rest.len().saturating_sub(1);
    rest.iter().enumerate().any(|(i, t)| match t.as_str() {
        "-h" | "-help" | "--help" => true,
        "help" => i == last,
        "version" => i == 0,
        // `az keyvault secret show --version <id>` selects a version: only a
        // `--version` with no value after it asks for the tool's version.
        "--version" => rest.get(i + 1).is_none_or(|next| next.starts_with('-')),
        _ => false,
    })
}

/// One cloud CLI read that prints a secret value: the fields of its response
/// that hold the value, and the output formats in which
/// `redact-secret-output` masks that value (each proven by a test here,
/// `structured_values_the_redactor_masks`). A format outside the list prints
/// the value unmasked.
struct CloudRead {
    tool: &'static str,
    words: &'static [&'static str],
    value_fields: &'static [&'static str],
    /// Objects that hold a value field, selected whole by a query that is
    /// exactly one of them (`--query Parameter`).
    parents: &'static [&'static str],
    masked_formats: &'static [&'static str],
}

/// The value-field table, one row per executable and subcommand (review
/// round 2). A `--query` that names none of the row's fields selects
/// something else (an id, a version, an expiry) and keeps main's verdict.
const CLOUD_READS: &[CloudRead] = &[
    CloudRead {
        tool: "aws",
        words: &["secretsmanager", "get-secret-value"],
        value_fields: &["SecretString", "SecretBinary"],
        parents: &[],
        masked_formats: &["json", "yaml", "yaml-stream"],
    },
    CloudRead {
        tool: "aws",
        words: &["ssm", "get-parameter"],
        value_fields: &["Value"],
        parents: &["Parameter"],
        masked_formats: &[],
    },
    CloudRead {
        tool: "aws",
        words: &["ssm", "get-parameters"],
        value_fields: &["Value"],
        parents: &["Parameters", "Parameters[]", "Parameters[*]"],
        masked_formats: &[],
    },
    CloudRead {
        tool: "aws",
        words: &["ssm", "get-parameters-by-path"],
        value_fields: &["Value"],
        parents: &["Parameters", "Parameters[]", "Parameters[*]"],
        masked_formats: &[],
    },
    CloudRead {
        tool: "az",
        words: &["account", "get-access-token"],
        value_fields: &["accessToken"],
        parents: &[],
        masked_formats: &["json", "jsonc", "yaml"],
    },
    CloudRead {
        tool: "az",
        words: &["keyvault", "secret", "show"],
        value_fields: &["value"],
        parents: &[],
        masked_formats: &[],
    },
];

/// Does this az/aws read keep its value out of the output? `-o none` prints
/// nothing. A `--query` hides the value unless it names a value field or
/// projects the whole response (`@`). With no query, the value is hidden only
/// in a masked format and while later stages keep the key names
/// (`… | jq -r .SecretString` strips the name the redactor masks by). The
/// format comes from `-o`/`--output` (glued or not), else the environment
/// prefix, else the CLI default, `json`; a CLI configured for another default
/// is outside what the command shows.
fn cloud_value_hidden(
    tool: &str,
    rest: &[String],
    keeps_names: bool,
    env_format: Option<&str>,
) -> bool {
    let Some(read) = CLOUD_READS
        .iter()
        .find(|r| r.tool == tool && r.words.iter().all(|w| rest.iter().any(|t| t == w)))
    else {
        return false;
    };
    let whole_parent = |path: &str| selects_parent_whole(path, read.parents);
    let format_flags: &[&str] = if tool == "az" {
        &["-o", "--output"]
    } else {
        &["--output"]
    };
    let flag_format = rest.iter().enumerate().find_map(|(i, t)| {
        if format_flags.contains(&t.as_str()) {
            rest.get(i + 1).map(String::as_str)
        } else if let Some(v) = t.strip_prefix("--output=") {
            Some(v)
        } else if tool == "az" && t.starts_with("-o") && t.len() > 2 {
            // A glued `-otsv`.
            Some(t[2..].trim_start_matches('='))
        } else {
            None
        }
    });
    let format = flag_format.or(env_format).unwrap_or("json");
    if format == "none" {
        return true;
    }
    let query = rest.iter().enumerate().find_map(|(i, t)| {
        if t == "--query" {
            rest.get(i + 1).map(String::as_str)
        } else {
            t.strip_prefix("--query=")
        }
    });
    match query {
        Some(q) => {
            let names_value = q
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .any(|word| read.value_fields.contains(&word));
            let bare = q.trim().trim_matches(['\'', '"']).trim();
            let whole = matches!(bare, "@" | "*") || whole_parent(bare);
            !names_value && !whole
        }
        None => keeps_names && read.masked_formats.contains(&format),
    }
}

/// Does `path` (a `--query` or a jq path without its leading `.`) select one
/// of `parents` whole, optionally indexed or filtered (`Parameter`,
/// `Parameters[0]`, `Parameters[?Name=='x']`), so it prints the value inside?
/// `Parameter.Version` walks on to another field and does not (code review
/// of round 2).
fn selects_parent_whole(path: &str, parents: &[&str]) -> bool {
    let path = path.trim().trim_matches(['\'', '"']).trim();
    parents.iter().any(|parent| {
        let name = parent.trim_end_matches("[*]").trim_end_matches("[]");
        let Some(rest) = path.strip_prefix(name) else {
            return false;
        };
        // `Parameter.*` projects every field of the parent.
        let rest = rest.strip_suffix(".*").unwrap_or(rest);
        // Only bracket groups may follow the parent's name.
        let mut depth = 0i32;
        rest.chars().all(|c| {
            match c {
                '[' => depth += 1,
                ']' => depth -= 1,
                _ if depth > 0 => {}
                _ => return false,
            }
            true
        }) && depth == 0
    })
}

/// Does a kubectl jsonpath, template or custom-columns selector reach a
/// Secret's data: name `data`/`stringData` (`.data`, `index .data`,
/// `range $k, $v := .data`), or print a whole object (`{@}`, `{.}`,
/// `{.items[*]}`, `{{.}}`, `{{json .}}`)? A selector that names only
/// metadata, `type` or `kind`, or one the guard cannot read, does not, and
/// keeps main's verdict (review round 2).
fn selector_reaches_data(rest: &[String]) -> bool {
    let mut expression = String::new();
    if let Some(format) = output_format(rest) {
        expression.push_str(format);
    }
    for (i, t) in rest.iter().enumerate() {
        if t == "--template" {
            expression.push_str(rest.get(i + 1).map_or("", String::as_str));
        } else if let Some(v) = t.strip_prefix("--template=") {
            expression.push_str(v);
        }
    }
    // `data` as its own word (`.data`, `index .data`, `["data"]`) or
    // `stringData`; `metadata` holds the letters but is not a data field.
    let names_data = expression.match_indices("data").any(|(at, _)| {
        let before = expression[..at].chars().next_back();
        let after = expression[at + "data".len()..].chars().next();
        before.is_none_or(|c| !c.is_ascii_alphabetic())
            && after.is_none_or(|c| !c.is_ascii_alphabetic())
    }) || expression.contains("stringData");
    // `last-applied-configuration` keeps the applied manifest, data
    // included, so the annotations or the whole metadata reach it too
    // (security review of round 2).
    let squeezed_meta: String = expression.chars().filter(|c| !c.is_whitespace()).collect();
    let names_annotations = expression.contains("annotations")
        || squeezed_meta.contains(".metadata}")
        || squeezed_meta.contains(".metadata,")
        || squeezed_meta.ends_with(".metadata");
    if names_data || names_annotations {
        return true;
    }
    let squeezed: String = expression.chars().filter(|c| !c.is_whitespace()).collect();
    // Recursive descent (`{..password}`) can reach any field, and an indexed
    // item (`{.items[0]}`) is a whole Secret (code review of round 2).
    if squeezed.contains("..") {
        return true;
    }
    if let Some(at) = squeezed.rfind(".items[") {
        let tail = &squeezed[at + ".items[".len()..];
        if tail.split_once(']').is_some_and(|(_, after)| after == "}") {
            return true;
        }
    }
    ["{@}", "{.}", "{$}", "{{.}}", "{{json.}}", "{{toJson.}}"]
        .iter()
        .any(|whole| squeezed.contains(whole))
        || squeezed.ends_with(".items[*]}")
        || squeezed.ends_with(".items}")
        || squeezed.ends_with("=@")
}

/// `kubectl get secret(s) … -o json|yaml`: the whole Secret, data included,
/// which `redact-secret-output` does not mask for ordinary key names
/// (`config.json`, `DATABASE_URL`; a test here shows it). It blocks when its
/// pipeline prints, through any `jq`/`yq` filter (the taint rule); a consumer
/// shape behind it keeps main's verdict.
fn structured_secret(argv: &[String]) -> bool {
    argv.first().is_some_and(|w| command_word(w) == "kubectl")
        && kubectl_gets_secret(&argv[1..])
        && output_format(&argv[1..]).is_some_and(|f| f == "json" || f == "yaml")
        && !help_or_version(&argv[1..])
}

/// The label of a printed `kubectl get secret -o json|yaml`.
const STRUCTURED_SECRET: &str = "kubectl get secret -o json|yaml";

/// The value of the output-format variable `tool` reads, set before the
/// command in `segment` (`AWS_DEFAULT_OUTPUT=text aws …`, `env
/// AZURE_CORE_OUTPUT=tsv az …`), which the CLI reads like its `--output`
/// flag. Each tool reads only its own variable.
fn output_format_variable(segment: &str, tool: &str) -> Option<String> {
    let name = match tool {
        "aws" => "AWS_DEFAULT_OUTPUT=",
        "az" => "AZURE_CORE_OUTPUT=",
        _ => return None,
    };
    tokenize(segment)
        .iter()
        .find_map(|t| t.strip_prefix(name).map(str::to_string))
}

/// Are two substitution bodies the same once quotes are set aside? A printed
/// body is read from tokenized words, which drop the quotes inside it
/// (`"$(op read "op://v/i/f")"`), while a child script is read from the raw
/// text (code review round 1).
fn same_body(a: &str, b: &str) -> bool {
    let bare = |s: &str| {
        s.chars()
            .filter(|c| !matches!(c, '"' | '\''))
            .collect::<String>()
    };
    a == b || bare(a) == bare(b)
}

/// Is a `jq` stage's argument list the identity filter with only options that
/// keep each `"key": value` pair (`-c`, `-r`, `-S`, `-M`, `-C`, `--tab`,
/// `--indent N`, `--arg k v`)? `--stream` and any other option change the
/// output's shape, which no redactor test covers (security review of round 3).
fn jq_identity_keeps_names(args: &[String]) -> bool {
    let mut filter = None;
    let mut i = 0;
    while let Some(t) = args.get(i) {
        match t.as_str() {
            "-c" | "-r" | "-S" | "-M" | "-C" | "--tab" | "--compact-output" | "--raw-output"
            | "--sort-keys" => i += 1,
            "--indent" => i += 2,
            "--arg" | "--argjson" => i += 3,
            t if t.starts_with('-') => return false,
            t if filter.is_none() => {
                filter = Some(t);
                i += 1;
            }
            // A file operand: jq reads it, not the producer's output.
            _ => return false,
        }
    }
    filter.is_none_or(|f| f == ".")
}

/// Does every pipeline stage after segment `start` leave its input's lines
/// whole (`cat`, `tee`, `head`, `tail`, or a `jq .` per
/// [`jq_identity_keeps_names`]), so key names printed beside values survive
/// to the output?
fn keeps_names(
    segments: &[(String, Option<&'static str>)],
    argvs: &[Vec<String>],
    start: usize,
) -> bool {
    let mut i = start;
    while segments[i].1 == Some("|") && i + 1 < argvs.len() {
        i += 1;
        let argv = &argvs[i];
        let whole = argv
            .first()
            .is_some_and(|w| match command_word(w).as_ref() {
                "cat" | "tee" => true,
                // `-c`/`--bytes` can cut the key name off and leave part of
                // the value (security review round 2).
                "head" | "tail" => !argv[1..]
                    .iter()
                    .any(|t| t.starts_with("-c") || t.starts_with("--bytes")),
                // `jq .` reformats but keeps every key.
                "jq" | "gojq" | "jaq" => jq_identity_keeps_names(&argv[1..]),
                _ => false,
            });
        if !whole {
            return false;
        }
    }
    true
}

/// A producer that only counts when its value is printed: `op inject` with no
/// `-i`-only output file prints every resolved secret of the template, but on
/// main it passed silently, so a consumer shape behind it (a pipe into
/// `kubectl apply -f -`) keeps passing (review round 1).
fn print_only_producer(argv: &[String]) -> Option<&'static str> {
    let first = argv.first()?;
    if command_word(first) != "op" {
        return None;
    }
    let rest = &argv[1..];
    if rest
        .iter()
        .find(|t| !t.starts_with('-'))
        .is_none_or(|t| t != "inject")
    {
        return None;
    }
    let to_file = rest.iter().enumerate().any(|(i, t)| {
        let target = if t == "-o" || t == "--out-file" {
            rest.get(i + 1).map(String::as_str)
        } else {
            t.strip_prefix("--out-file=")
        };
        target.is_some_and(|f| !f.is_empty() && !is_terminal_path(f))
    });
    let help = help_or_version(rest);
    (!to_file && !help).then_some("op inject")
}

/// `perl -e 'alarm N; exec @ARGV' <cmd>`, the macOS timeout runner, peeled
/// like `env` or `timeout`: the words of `<cmd>` and `true`, or `argv`
/// unchanged and `false`.
fn peel_perl_alarm(argv: &[String]) -> (Vec<String>, bool) {
    let is_runner = argv.first().is_some_and(|w| command_word(w) == "perl")
        && argv.get(1).is_some_and(|f| f == "-e")
        && argv
            .get(2)
            .is_some_and(|s| s.contains("alarm") && s.contains("exec @ARGV"));
    if is_runner && argv.len() > 3 {
        (peel_command_runners(&argv[3..]).to_vec(), true)
    } else {
        (argv.to_vec(), false)
    }
}

/// Is stdout closed (`>&-`, `1>&-`), or duplicated onto a stderr already sent
/// to a real file (`2>/dev/null >&2`, read in order)? Nothing prints, but
/// [`stdout_to_file`] does not read either, so such a segment is never judged
/// printing and keeps its ask (security review N1).
fn stdout_closed_or_dup_to_file(argv: &[String]) -> bool {
    let mut stderr_to_file = false;
    let mut i = 0;
    while i < argv.len() {
        let token = &argv[i];
        if !is_redirect_token(token) || token.starts_with("&>") {
            i += 1;
            continue;
        }
        let digits: String = token.chars().take_while(char::is_ascii_digit).collect();
        let after_fd = &token[digits.len()..];
        if !after_fd.starts_with('>') {
            i += 1;
            continue;
        }
        let glued = after_fd.trim_start_matches(['>', '|']);
        let (dup, target) = match glued.strip_prefix('&') {
            // `>& out.txt`: the target is the next word.
            Some("") => {
                i += 1;
                (true, argv.get(i).cloned().unwrap_or_default())
            }
            Some(fd) => (true, fd.to_string()),
            None if glued.is_empty() => {
                i += 1;
                (false, argv.get(i).cloned().unwrap_or_default())
            }
            None => (false, glued.to_string()),
        };
        let fd = if digits.is_empty() {
            "1"
        } else {
            digits.as_str()
        };
        match (fd, dup) {
            ("2", false) => stderr_to_file = !target.is_empty() && !is_terminal_path(&target),
            ("1", true) if target == "-" => return true,
            // `>&out.txt`: a file, not a descriptor (both streams go there).
            ("1", true) if !target.chars().all(|c| c.is_ascii_digit()) => return true,
            ("1", true) if target == "2" && stderr_to_file => return true,
            _ => {}
        }
        i += 1;
    }
    false
}

/// Can segment `argv`'s own stdout reach the terminal, as far as its words
/// show?
fn stage_can_print(argv: &[String]) -> bool {
    !stdout_to_file(argv) && !glued_redirect(argv) && !stdout_closed_or_dup_to_file(argv)
}

/// For each segment: does its pipeline put its output into the command's
/// output? Either it ends its pipeline, or every later stage is a
/// [`PASS_THROUGH`] command; each stage's stdout must be able to reach the
/// terminal. Computed from the last segment back, so a long pipeline costs
/// one pass.
fn pipeline_prints(
    segments: &[(String, Option<&'static str>)],
    argvs: &[Vec<String>],
) -> Vec<bool> {
    let mut out = vec![false; argvs.len()];
    for i in (0..argvs.len()).rev() {
        let next = argvs.get(i + 1);
        out[i] = stage_can_print(&argvs[i])
            && (segments[i].1 != Some("|")
                || next.is_some_and(|n| is_pass_through(n) && out[i + 1])
                || next.is_some_and(|n| tees_to_terminal(n)));
    }
    out
}

/// `tee /dev/tty` or `tee /dev/stderr`: the value reaches the terminal
/// through tee's own operand, whatever the pipe does next.
fn tees_to_terminal(argv: &[String]) -> bool {
    argv.first().is_some_and(|w| command_word(w) == "tee")
        && argv[1..].iter().any(|t| is_terminal_path(t))
}

/// Bodies a [`PASS_THROUGH`] command prints because they feed it: a
/// here-string's substitutions (`cat <<< "$(…)"`), read from the segment's
/// words, and `<(…)` file operands (`cat <(…)`), read from its raw text, since
/// the tokenizer splits a process substitution at its blanks.
fn fed_bodies(argv: &[String], segment: &str) -> Vec<String> {
    if !copies_input(argv, true) {
        return Vec::new();
    }
    let mut out = process_substitutions(segment, true);
    // A here-string's word, read from the raw text after `<<<`: the
    // tokenizer splits a word whose substitution holds a quoted blank.
    if let Some(at) = segment.find("<<<") {
        out.extend(substitution_bodies(&segment[at + 3..]));
    }
    out
}

/// [`judge`] over one script, recursing into every child script the shell
/// runs from a segment — `$(…)`, backticks, `<(…)`, `sh -c`/`bash -c`,
/// `eval` — via core's read-only `child_scripts`, up to `MAX_WRAPPER_DEPTH`.
///
/// `reaches_context` says whether this script's own stdout ends up in the
/// command's output: true at the top, inherited by a `-c`/`eval` script,
/// false for a substitution body (the shell captures it) unless
/// [`printed_bodies`] finds it in an argument word of an
/// [`ARGUMENT_PRINTERS`] command or as the whole first word (the shell then
/// reports the value as an unknown command), and false for a process
/// substitution (a consumer reads it).
///
/// Returns the label of the first producer whose value is printed. The first
/// producer whose value is merely exposed (today's ask) is kept in
/// `first_exposed`.
fn exposed_in(
    script: &str,
    depth: usize,
    reaches_context: bool,
    print_only: bool,
    first_exposed: &mut Option<&'static str>,
) -> Option<&'static str> {
    let segments = split_segments_with_ops_joining_redirects(script);
    // Each segment's words with runners peeled, the perl timeout runner
    // included, and whether that runner was peeled: behind it only a printed
    // value counts, since main never saw past it and its consumer shapes
    // passed (review round 1).
    let (argvs, behind_perl): (Vec<Vec<String>>, Vec<bool>) = segments
        .iter()
        .map(|(segment, _)| {
            let tokens = tokenize(strip_group_wrappers(segment));
            peel_perl_alarm(peel_command_runners(&tokens))
        })
        .unzip();
    // A `{ …; } > f` or `( … ) | x` group sends its members' output somewhere
    // the per-segment view cannot see, so nothing in a grouped script is
    // judged printed; it keeps today's ask.
    let grouped = segments.iter().any(|(segment, _)| is_group_edge(segment));
    // The splitter strips a heredoc body and re-appends each substitution in
    // it as a segment of its own, so `$(op read …)` from the body of
    // `kubectl apply -f - <<EOF` looks like a lone substitution in command
    // position. Where it really goes is the stdin of the heredoc's command, a
    // consumer, so a script holding a heredoc never takes the command-position
    // rule (security review round 1).
    let heredoc = has_heredoc(script);
    let prints: Vec<bool> = pipeline_prints(&segments, &argvs)
        .into_iter()
        .map(|p| p && reaches_context && !grouped)
        .collect();
    // A heredoc's body goes to its command's stdin. When that command is a
    // pass-through whose pipeline prints (`cat <<EOF`), the body's
    // substitutions are printed; otherwise they feed a consumer.
    let heredoc_prints = heredoc && {
        let mut introducers = (0..argvs.len()).filter(|&j| has_heredoc(&segments[j].0));
        match (introducers.next(), introducers.next()) {
            (Some(j), None) => prints[j] && is_pass_through(&argvs[j]),
            _ => false,
        }
    };
    for (i, argv) in argvs.iter().enumerate() {
        let segment_prints = prints[i];
        let quiet_here = print_only || behind_perl[i];
        if depth < MAX_WRAPPER_DEPTH {
            let stripped = strip_group_wrappers(&segments[i].0);
            let substitutions = substitution_bodies(stripped);
            // Read from the unstripped segment: `strip_group_wrappers` trims
            // the closing `)` of `echo $(…)`, and a printing segment is never
            // inside a group anyway.
            let mut printed = Vec::new();
            if segment_prints {
                let (raw, _) =
                    peel_perl_alarm(peel_command_runners(&tokenize(segments[i].0.trim())));
                printed = printed_bodies(&raw, segments[i].0.trim(), !heredoc || heredoc_prints);
                printed.extend(fed_bodies(&raw, segments[i].0.trim()));
            }
            // Children main read from the segment as typed. Behind the perl
            // runner, one it reads only once the runner is peeled is judged
            // print-only, like the runner's own producer.
            let as_typed = if behind_perl[i] {
                child_scripts(&tokenize(strip_group_wrappers(&segments[i].0)), stripped)
            } else {
                Vec::new()
            };
            let mut children: Vec<(String, bool, bool)> = child_scripts(argv, stripped)
                .into_iter()
                .map(|child| {
                    // A `-c`/`eval` script writes to this segment's stdout; a
                    // substitution is captured unless this segment prints it.
                    let child_prints = if substitutions.contains(&child) {
                        printed.iter().any(|p| same_body(p, &child))
                    } else {
                        segment_prints
                    };
                    let child_quiet = print_only || (behind_perl[i] && !as_typed.contains(&child));
                    (child, child_prints, child_quiet)
                })
                .collect();
            children.extend(
                process_substitutions(stripped, false)
                    .into_iter()
                    .map(|child| {
                        let child_prints = printed.iter().any(|p| same_body(p, &child));
                        (child, child_prints, print_only)
                    }),
            );
            // Every child is judged, wherever its output goes, with no
            // exceptions: an argument can be printed by the command, a runner,
            // `set -x` or a verbose flag, and each "safe consumer" or "stdin
            // sink" exemption tried here produced bypasses (review rounds 4-6).
            // Only the printed/exposed split depends on where it goes.
            for (child, child_prints, child_quiet) in children {
                if let Some(label) =
                    exposed_in(&child, depth + 1, child_prints, child_quiet, first_exposed)
                {
                    return Some(label);
                }
            }
        }
        if segment_prints && let Some(label) = print_only_producer(argv) {
            return Some(label);
        }
        // A Secret's json or yaml: printed whenever its pipeline prints,
        // whatever a `jq`/`yq` filter on it says (the taint rule, review
        // round 3); otherwise main's verdict (an ask behind `jq`/`yq`, a pass
        // otherwise).
        if segment_prints && structured_secret(argv) {
            return Some(STRUCTURED_SECRET);
        }
        let direct = producer(argv);
        let Some(label) = direct.or_else(|| structured_secret_filtered(&segments, &argvs, i))
        else {
            continue;
        };
        let env_format = argv
            .first()
            .and_then(|w| output_format_variable(&segments[i].0, &command_word(w)));
        if segment_prints
            && direct.is_some()
            && !never_printed(
                argv,
                keeps_names(&segments, &argvs, i),
                env_format.as_deref(),
            )
        {
            return Some(label);
        }
        if !quiet_here && !pipeline_contains_it(&segments, &argvs, i) {
            first_exposed.get_or_insert(label);
        }
    }
    None
}

/// Substitution bodies whose value lands in the output of the segment whose
/// (runner-peeled) words are `argv`: every body of a first word that is one
/// whole substitution (the shell runs the value as a command and reports it
/// when that fails), and the bodies in the argument words of an
/// [`ARGUMENT_PRINTERS`] command. Redirect words and their targets,
/// process-substitution words, words before the printer (assignments, runner
/// options), and `printf -v` (which assigns, not prints) contribute nothing.
///
/// The printer's bodies are read from the raw `segment` text, since the
/// tokenizer splits a word whose substitution holds a quoted blank
/// (`"$(op read "op://v/i name/f")"`); the excluded words are read from the
/// tokens, so an exclusion it cannot read only keeps a body printed in a word
/// that really is an argument (code review round 1).
fn printed_bodies(argv: &[String], segment: &str, command_position: bool) -> Vec<String> {
    let Some(first) = argv.first() else {
        return Vec::new();
    };
    if is_lone_substitution(first) {
        return if command_position {
            substitution_bodies(first)
        } else {
            Vec::new()
        };
    }
    let word = command_word(first);
    if !ARGUMENT_PRINTERS.contains(&word.as_ref()) {
        return Vec::new();
    }
    let args = &argv[1..];
    let assigns = matches!(word.as_ref(), "printf" | "print")
        && args
            .iter()
            .take_while(|t| t.starts_with('-') && *t != "--")
            .any(|t| !t.starts_with("--") && t[1..].contains('v'));
    if assigns {
        return Vec::new();
    }
    let mut excluded = process_substitutions(segment, false);
    let typed = tokenize(segment);
    let printer_at = typed
        .iter()
        .position(|t| ARGUMENT_PRINTERS.contains(&command_word(t).as_ref()))
        .unwrap_or(0);
    for token in &typed[..printer_at] {
        excluded.extend(substitution_bodies(token));
    }
    let mut target_next = false;
    for token in args {
        if std::mem::take(&mut target_next) {
            excluded.extend(substitution_bodies(token));
            continue;
        }
        if is_redirect_token(token) {
            // `>` alone takes the next word as its target; `2>x` glues it.
            target_next = token
                .trim_start_matches(|c: char| c.is_ascii_digit() || c == '&')
                .trim_start_matches(['<', '>', '|', '&'])
                .is_empty();
            excluded.extend(substitution_bodies(token));
        }
    }
    let mut out = substitution_bodies(segment);
    out.retain(|body| !excluded.iter().any(|e| same_body(e, body)));
    out
}

/// Does a word of `argv` that is not itself a redirect hold a `>`? The
/// tokenizer keeps a redirect glued to the word before it
/// (`op read x>token.txt`, `echo "$(…)">>.env`) inside that word, where
/// [`stdout_to_file`] cannot read it. Such a segment is never judged printing
/// and keeps its ask; a quoted `>` (`echo "a -> b"`) only does the same
/// (security review round 2).
fn glued_redirect(argv: &[String]) -> bool {
    argv.iter().any(|token| {
        if !is_redirect_token(token) {
            return token.contains('>');
        }
        // `2>&1>/dev/null`: a second redirect after the first one's target.
        token
            .trim_start_matches(|c: char| c.is_ascii_digit() || c == '&')
            .trim_start_matches(['<', '>', '|', '&'])
            .contains('>')
    })
}

/// Does `script` hold a heredoc operator (`<<`, `<<-`), as opposed to a
/// here-string (`<<<`)? Read from raw text, quotes included: a false yes only
/// keeps an ask.
fn has_heredoc(script: &str) -> bool {
    let bytes = script.as_bytes();
    bytes.windows(2).enumerate().any(|(i, w)| {
        w == b"<<" && bytes.get(i + 2) != Some(&b'<') && (i == 0 || bytes[i - 1] != b'<')
    })
}

/// Is `word` exactly one `$(…)` or backtick substitution?
fn is_lone_substitution(word: &str) -> bool {
    (word.starts_with("$(") && word.ends_with(')'))
        || (word.len() > 1
            && word.starts_with('`')
            && word.ends_with('`')
            && word.matches('`').count() == 2)
}

/// Does `segment` open or close a `{ … }` / `( … )` group? A brace group's
/// braces are words of their own (`{ op read x; } > f`), so `{.data.k}` and
/// `{a,b}` are not edges. A `)` counts only when the segment closes more
/// parentheses than it opens, so a segment ending in its own `$(…)` is not
/// one either. Erring toward "grouped" only keeps today's ask.
fn is_group_edge(segment: &str) -> bool {
    let trimmed = segment.trim();
    let opens_brace = trimmed == "{" || trimmed.starts_with("{ ") || trimmed.starts_with("{\t");
    if opens_brace || trimmed.starts_with(['}', '(', ')']) {
        return true;
    }
    trimmed.matches(')').count() > trimmed.matches('(').count()
}

/// Bodies of `<(…)` / `>(…)` process substitutions in `segment`, which core's
/// `child_scripts` does not return. Outside single quotes only; an unclosed
/// body (the splitter may have cut the segment at a `|` inside it) runs to
/// the end — erring toward judging more, never less. `inputs_only` keeps the
/// `<(…)` bodies alone, the ones a reader reads as a file.
fn process_substitutions(segment: &str, inputs_only: bool) -> Vec<String> {
    let bytes = segment.as_bytes();
    let mut out = Vec::new();
    let mut in_single = false;
    let mut i = 0;
    while i + 1 < bytes.len() {
        match bytes[i] {
            b'\'' => in_single = !in_single,
            b'<' | b'>'
                if !in_single && bytes[i + 1] == b'(' && (!inputs_only || bytes[i] == b'<') =>
            {
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
        // A pure hash as the LAST stage: its output is a digest, never the
        // value, and nothing after it can see the value either.
        let last = segments[i].1 != Some("|") || i + 1 >= argvs.len();
        if i > start && last && is_pure_hash(argv) {
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
            let secret = kubectl_names_secret(rest);
            (secret && bare_output_format(rest)).then_some("kubectl get secret -o jsonpath")
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
            // `op read <ref>`: the subcommand is the first non-flag word (an
            // `op://` reference is not required — any read prints a value).
            let reads = (rest
                .iter()
                .find(|t| !t.starts_with('-'))
                .is_some_and(|t| t == "read")
                || (rest.iter().any(|t| t == "read")
                    && rest.iter().any(|t| t.starts_with("op://"))))
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
            let has = |w: &str| rest.iter().any(|t| t == w);
            if has("secretsmanager") && has("get-secret-value") {
                Some("aws secretsmanager get-secret-value")
            } else if (has("ecr") || has("ecr-public")) && has("get-login-password") {
                Some("aws ecr get-login-password")
            } else if has("ssm")
                && rest.iter().any(|t| t.starts_with("get-parameter"))
                && has("--with-decryption")
            {
                Some("aws ssm get-parameter --with-decryption")
            } else if rest
                .windows(2)
                .any(|w| w[0] == "configure" && w[1] == "get")
                && rest.iter().any(|t| {
                    let t = t.to_ascii_lowercase();
                    t.contains("secret") || t.contains("token") || t.contains("password")
                })
            {
                Some("aws configure get <secret>")
            } else {
                None
            }
        }
        "az" => {
            let has3 = |a: &str, b: &str, c: &str| {
                rest.windows(3).any(|w| w[0] == a && w[1] == b && w[2] == c)
            };
            if has3("keyvault", "secret", "show") {
                Some("az keyvault secret show")
            } else if rest
                .windows(2)
                .any(|w| w[0] == "account" && w[1] == "get-access-token")
            {
                Some("az account get-access-token")
            } else {
                None
            }
        }
        "heroku" => rest
            .iter()
            .any(|t| t == "auth:token")
            .then_some("heroku auth:token"),
        "gopass" => rest
            .iter()
            .find(|t| !t.starts_with('-'))
            .is_some_and(|t| matches!(t.as_str(), "show" | "cat"))
            .then_some("gopass show"),
        "bw" => (rest
            .windows(2)
            .any(|w| w[0] == "get" && matches!(w[1].as_str(), "password" | "totp" | "notes")))
        .then_some("bw get password"),
        "lpass" => (rest.iter().any(|t| t == "show")
            && rest.iter().any(|t| {
                matches!(t.as_str(), "--password" | "--notes") || t.starts_with("--field")
            }))
        .then_some("lpass show --password"),
        "doppler" => (rest.windows(2).any(|w| w[0] == "secrets" && w[1] == "get")
            && rest.iter().any(|t| t == "--plain"))
        .then_some("doppler secrets get --plain"),
        "gcloud" => {
            let access = rest
                .windows(3)
                .any(|w| w[0] == "secrets" && w[1] == "versions" && w[2] == "access");
            let token = rest.iter().any(|t| t == "auth")
                && rest
                    .iter()
                    .any(|t| t == "print-access-token" || t == "print-identity-token");
            if access {
                Some("gcloud secrets versions access")
            } else if token {
                Some("gcloud auth print-access-token")
            } else {
                None
            }
        }
        // `pass show NAME`, and `pass NAME` (shorthand for show); the other
        // subcommands list, edit or manage the store.
        "pass" => rest
            .iter()
            .find(|t| !t.starts_with('-'))
            .is_some_and(|t| !PASS_SUBCOMMANDS.contains(&t.as_str()))
            .then_some("pass show"),
        _ => None,
    }
}

/// `pass` subcommands that do not print a secret.
const PASS_SUBCOMMANDS: &[&str] = &[
    "ls", "list", "find", "search", "grep", "insert", "add", "edit", "generate", "rm", "remove",
    "delete", "mv", "rename", "cp", "copy", "git", "init", "help", "version",
];

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
    let structured = kubectl_names_secret(rest)
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

/// kubectl options that take their value as the next word, so that word is
/// not the resource type (`-n secrets`, `-l app=secret`).
const KUBECTL_VALUED: &[&str] = &[
    "-n",
    "--namespace",
    "-l",
    "--selector",
    "--context",
    "--cluster",
    "--user",
    "--kubeconfig",
    "-o",
    "--output",
    "--field-selector",
    "--template",
    "--sort-by",
    "-c",
    "--container",
    "-f",
    "--filename",
];

/// main's rule for whether `kubectl … get …` reads Secrets: any word names
/// `secret`/`secrets`. It still decides every ask, so nothing main asked
/// about passes (review round 4).
fn kubectl_names_secret(rest: &[String]) -> bool {
    rest.iter().any(|t| t == "get") && rest.iter().any(|t| names_secret_resource(t))
}

/// Does `kubectl … get <type> …` read Secrets, for a block? The type is the
/// first word after `get` that is not an option or an option's value, so a
/// namespace or object named `secret` (`kubectl get pods -n secrets`,
/// `kubectl get deploy secret`) is not one (code review of round 3). A
/// [`KUBECTL_VALUED`] option takes the next word and a `--name=value` word
/// takes none; any other option might be either (`-w` is a flag, `--as
/// admin` takes a value), so both readings are followed, and the command is
/// a Secret read when either one's type names a Secret (review round 4). One
/// pass over the words: each index is reached or not.
///
/// This decides blocks only. Every ask follows [`kubectl_names_secret`],
/// main's rule, so a command this says no to keeps main's verdict.
fn kubectl_gets_secret(rest: &[String]) -> bool {
    let Some(at) = rest.iter().position(|t| t == "get") else {
        return false;
    };
    let words = &rest[at + 1..];
    let mut reached = vec![false; words.len() + 2];
    reached[0] = true;
    for (i, t) in words.iter().enumerate() {
        if !reached[i] {
            continue;
        }
        if !t.starts_with('-') {
            // A type candidate: this reading ends here.
            if names_secret_resource(t) {
                return true;
            }
        } else if KUBECTL_VALUED.contains(&t.as_str()) {
            reached[i + 2] = true;
        } else if t.starts_with("--") && t.contains('=') {
            reached[i + 1] = true;
        } else {
            reached[i + 1] = true;
            reached[i + 2] = true;
        }
    }
    false
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

/// A hash command: its output is a digest of stdin, never stdin itself.
/// Judged by command word alone — no flag parsing to get wrong.
fn is_pure_hash(argv: &[String]) -> bool {
    argv.first().is_some_and(|w| {
        matches!(
            command_word(w).as_ref(),
            "shasum"
                | "sha1sum"
                | "sha224sum"
                | "sha256sum"
                | "sha384sum"
                | "sha512sum"
                | "md5sum"
                | "md5"
                | "b2sum"
                | "cksum"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A made-up credential-shaped value planted in each sample output.
    const PLANTED: &str = "Zq9vKhunter7XwPq2LmN";

    fn masked(sample: &str) -> bool {
        let out = crate::redact_secret_output::redact(sample).unwrap_or_else(|| sample.to_string());
        !out.contains(PLANTED)
    }

    /// Review round 2: the yaml, yaml-stream and jsonc forms the CLOUD_READS
    /// table lists as masked are masked; a Secret's json or yaml with
    /// ordinary key names is not, so those forms block. Representative
    /// output with a made-up value.
    #[test]
    fn structured_values_the_redactor_masks() {
        let masked_forms = [
            (
                "aws secretsmanager --output yaml",
                format!(
                    "ARN: arn:aws:secretsmanager:us-east-1:123456789012:secret:x-AbCdEf\nName: x\nSecretString: {PLANTED}\nVersionStages:\n- AWSCURRENT\n"
                ),
            ),
            (
                "aws secretsmanager --output yaml (JSON string)",
                format!(
                    "ARN: arn:aws:x\nName: x\nSecretString: '{{\"password\":\"{PLANTED}\"}}'\n"
                ),
            ),
            (
                "aws secretsmanager --output yaml-stream",
                format!("- ARN: arn:aws:x\n  Name: x\n  SecretString: {PLANTED}\n"),
            ),
            (
                "az account get-access-token -o yaml",
                format!(
                    "accessToken: {PLANTED}\nexpiresOn: '2026-11-19 22:00:00.000000'\ntokenType: Bearer\n"
                ),
            ),
            (
                "az account get-access-token -o jsonc",
                format!(
                    "{{\n  \u{1b}[94m\"accessToken\"\u{1b}[0m: \u{1b}[92m\"{PLANTED}\"\u{1b}[0m,\n  \u{1b}[94m\"tokenType\"\u{1b}[0m: \u{1b}[92m\"Bearer\"\u{1b}[0m\n}}"
                ),
            ),
        ];
        for (form, sample) in &masked_forms {
            assert!(masked(sample), "{form}: the redactor must mask the value");
        }
        let secret_yaml = format!(
            "apiVersion: v1\ndata:\n  config.json: {PLANTED}\n  DATABASE_URL: {PLANTED}\nkind: Secret\nmetadata:\n  name: app\n"
        );
        let secret_json = format!(
            "{{\n    \"apiVersion\": \"v1\",\n    \"data\": {{\n        \"api\": \"{PLANTED}\"\n    }},\n    \"kind\": \"Secret\"\n}}"
        );
        for (form, sample) in [
            ("kubectl get secret -o yaml", &secret_yaml),
            ("kubectl get secret -o json", &secret_json),
        ] {
            assert!(
                !masked(sample),
                "{form}: unmasked, so the block stays (update the guard if this changes)"
            );
        }
        for command in [
            "aws secretsmanager get-secret-value --secret-id x --output yaml",
            "az account get-access-token -o jsonc",
        ] {
            assert_eq!(
                judge(command).map(|f| f.exposure),
                Some(Exposure::Exposed),
                "{command}"
            );
        }
        for command in [
            "kubectl get secret app -o yaml",
            "kubectl get secret app -o json",
        ] {
            assert_eq!(
                judge(command).map(|f| f.exposure),
                Some(Exposure::Printed),
                "{command}"
            );
        }
    }

    /// Review round 1: a producer form keeps main's ask only where the
    /// redactor masks its value; the forms it does not mask keep the block.
    /// Each sample is representative default output with a made-up value.
    #[test]
    fn default_json_values_the_redactor_masks() {
        let az_token = format!(
            "{{\n  \"accessToken\": \"{PLANTED}\",\n  \"expiresOn\": \"2026-11-19 22:00:00.000000\",\n  \"tokenType\": \"Bearer\"\n}}"
        );
        let secretsmanager = format!(
            "{{\n    \"ARN\": \"arn:aws:secretsmanager:us-east-1:123456789012:secret:x-AbCdEf\",\n    \"Name\": \"x\",\n    \"SecretString\": \"{PLANTED}\",\n    \"VersionStages\": [\n        \"AWSCURRENT\"\n    ]\n}}"
        );
        let secretsmanager_object = format!(
            "{{\n    \"Name\": \"x\",\n    \"SecretString\": \"{{\\\"password\\\":\\\"{PLANTED}\\\"}}\"\n}}"
        );
        // `| jq .` re-indents by two spaces and `| jq -c .` puts it on one
        // line; both keep every key name, which [`keeps_names`] relies on.
        let secretsmanager_jq = format!(
            "{{\n  \"ARN\": \"arn:aws:x\",\n  \"Name\": \"x\",\n  \"SecretString\": \"{PLANTED}\"\n}}"
        );
        let secretsmanager_compact =
            format!("{{\"ARN\":\"arn:aws:x\",\"Name\":\"x\",\"SecretString\":\"{PLANTED}\"}}");
        let az_compact = format!("{{\"accessToken\":\"{PLANTED}\",\"tokenType\":\"Bearer\"}}");
        // `jq -C .` (jq 1.7 colours), `--tab`, `-S` (keys sorted) and
        // `--indent 4`: each pair still sits on one line (review round 4).
        let secretsmanager_color = format!(
            "\u{1b}[1;39m{{\n  \u{1b}[0m\u{1b}[34;1m\"ARN\"\u{1b}[0m\u{1b}[1;39m:\u{1b}[0m\u{1b}[0;32m\"arn:aws:x\"\u{1b}[0m\u{1b}[1;39m,\n  \u{1b}[0m\u{1b}[34;1m\"SecretString\"\u{1b}[0m\u{1b}[1;39m:\u{1b}[0m\u{1b}[0;32m\"{PLANTED}\"\u{1b}[0m\u{1b}[1;39m\n\u{1b}[1;39m}}\u{1b}[0m"
        );
        let secretsmanager_tab_sorted = format!(
            "{{\n\t\"ARN\": \"arn:aws:x\",\n\t\"Name\": \"x\",\n\t\"SecretString\": \"{PLANTED}\"\n}}"
        );
        let az_indent4 =
            format!("{{\n    \"accessToken\": \"{PLANTED}\",\n    \"tokenType\": \"Bearer\"\n}}");
        for (form, sample) in [
            ("az account get-access-token", &az_token),
            ("aws secretsmanager get-secret-value", &secretsmanager),
            (
                "aws secretsmanager get-secret-value (JSON string)",
                &secretsmanager_object,
            ),
            (
                "aws secretsmanager get-secret-value | jq .",
                &secretsmanager_jq,
            ),
            (
                "aws secretsmanager get-secret-value | jq -c .",
                &secretsmanager_compact,
            ),
            ("az account get-access-token | jq -c .", &az_compact),
            (
                "aws secretsmanager get-secret-value | jq -C .",
                &secretsmanager_color,
            ),
            (
                "aws secretsmanager get-secret-value | jq --tab -S .",
                &secretsmanager_tab_sorted,
            ),
            ("az account get-access-token | jq --indent 4 .", &az_indent4),
        ] {
            assert!(masked(sample), "{form}: the redactor must mask the value");
        }
        let ssm = format!(
            "{{\n    \"Parameter\": {{\n        \"Name\": \"/x\",\n        \"Type\": \"SecureString\",\n        \"Value\": \"{PLANTED}\"\n    }}\n}}"
        );
        let keyvault = format!(
            "{{\n  \"id\": \"https://v.vault.azure.net/secrets/x/1\",\n  \"name\": \"x\",\n  \"value\": \"{PLANTED}\"\n}}"
        );
        // `op item get --reveal`: a `password:` label is masked, but any other
        // label a person gave a field may not be, so the form keeps the block.
        let op_item =
            format!("Title:       wifi\nFields:\n  network name:    home\n  pin:    {PLANTED}\n");
        for (form, sample) in [
            ("aws ssm get-parameter --with-decryption", &ssm),
            ("az keyvault secret show", &keyvault),
            ("op item get --reveal", &op_item),
        ] {
            assert!(
                !masked(sample),
                "{form}: unmasked, so the block stays (update the guard if this changes)"
            );
        }
        // And the guard agrees: the masked forms ask, the others block.
        for command in [
            "az account get-access-token",
            "aws secretsmanager get-secret-value --secret-id x",
        ] {
            assert_eq!(
                judge(command).map(|f| f.exposure),
                Some(Exposure::Exposed),
                "{command}"
            );
        }
        for command in [
            "aws ssm get-parameter --name /x --with-decryption",
            "az keyvault secret show --vault-name v -n x",
            "op item get db --reveal",
        ] {
            assert_eq!(
                judge(command).map(|f| f.exposure),
                Some(Exposure::Printed),
                "{command}"
            );
        }
    }

    #[test]
    fn producers_are_found() {
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
                "kubectl get secret -o json|yaml",
            ),
            (
                "kubectl get secret s -o yaml | yq .data.p",
                "kubectl get secret -o json|yaml",
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
            // Round 6: no stdin-sink or counter exemptions at all.
            (
                "docker login --password-stdin <<< \"$(op read op://v/i/f)\"",
                "op read",
            ),
            (
                "gh auth login --with-token <<< \"$(op read op://v/i/t)\"",
                "op read",
            ),
            (
                "gh auth login --with-token < <(op read op://v/i/f)",
                "op read",
            ),
            (
                "security find-generic-password -s svc -w | docker login -u me --password-stdin",
                "security find-*-password -w",
            ),
            (
                "op read op://v/i/token | gh auth login --with-token",
                "op read",
            ),
            ("op read op://v/i/f | grep -q expected", "op read"),
            ("op read op://v/i/f | openssl dgst -sha256", "op read"),
            (
                "kubectl get secret app -o jsonpath='{.data.token}' | wc -c",
                "kubectl get secret -o jsonpath",
            ),
            ("op read op://v/i/f | sha256sum | cat", "op read"),
            (
                "docker run -i --rm alpine sh -c cat login --password-stdin <<< \"$(op read op://v/i/p)\"",
                "op read",
            ),
            (
                "docker run -i --rm alpine sh -c cat login --password-stdin < <(op read op://v/i/p)",
                "op read",
            ),
            (
                "docker run -i --rm --name login alpine tee /dev/stderr --password-stdin <<< \"$(op read op://v/i/p)\"",
                "op read",
            ),
            (
                "podman run -i --rm alpine sh -c cat login --password-stdin <<< \"$(op read op://v/i/p)\"",
                "op read",
            ),
            (
                "docker exec -i c sh -c cat login --password-stdin <<< \"$(op read op://v/i/p)\"",
                "op read",
            ),
            (
                "docker --config <(op read op://v/i/q) login --password-stdin r <<< x",
                "op read",
            ),
            (
                "docker login -u \"$(op read p)\" --password-stdin r <<< \"$(op read p)\"",
                "op read",
            ),
            (
                "gh auth login --with-token --hostname \"$(op read p)\" <<< \"$(op read p)\"",
                "op read",
            ),
            // Round 5 fake stdin sinks (still ask with no exemption at all).
            (
                "echo \"$(op read op://v/i/p)\" --password-stdin <<< x",
                "op read",
            ),
            ("cat --with-token <<< \"$(op read op://v/i/p)\"", "op read"),
            (
                "tee /dev/stderr --password-stdin <<< \"$(op read op://v/i/p)\"",
                "op read",
            ),
            ("cat <(op read op://v/i/p) --with-token", "op read"),
            (
                "docker login -u \"$(op read op://v/i/u)\" --password-stdin r <<< \"$(op read op://v/i/p)\"",
                "op read",
            ),
            // Round 5 producers.
            (
                "gcloud auth print-access-token",
                "gcloud auth print-access-token",
            ),
            (
                "gcloud auth application-default print-access-token",
                "gcloud auth print-access-token",
            ),
            ("heroku auth:token", "heroku auth:token"),
            (
                "aws configure get aws_secret_access_key",
                "aws configure get <secret>",
            ),
            (
                "aws ecr get-login-password --region x",
                "aws ecr get-login-password",
            ),
            (
                "aws ssm get-parameter --name /x --with-decryption",
                "aws ssm get-parameter --with-decryption",
            ),
            (
                "az keyvault secret show --vault-name v -n x",
                "az keyvault secret show",
            ),
            ("az account get-access-token", "az account get-access-token"),
            ("pass db", "pass show"),
            ("gopass show db", "gopass show"),
            ("bw get password item", "bw get password"),
            ("lpass show --password item", "lpass show --password"),
            ("printf \"%s\\n\" \"$(op read x)\"", "op read"),
            ("docker run -e T=\"$(op read x)\" alpine env", "op read"),
            // Round 4: every nested producer asks, whatever consumes it.
            ("TOKEN=$(op read op://v/i/f) gh api user", "op read"),
            (
                "curl -H \"Authorization: Bearer $(op read op://v/i/f)\" https://x",
                "op read",
            ),
            ("psql \"postgres://u:$(pass show db)@h/db\"", "pass show"),
            ("sudo echo \"$(op read op://v/i/f)\"", "op read"),
            ("env T=\"$(op read op://v/i/f)\" printenv T", "op read"),
            ("ssh h \"echo $(op read op://v/i/f)\"", "op read"),
            ("python3 -c 'print(1)' \"$(pass show x)\"", "pass show"),
            ("set -x; mysql -p\"$(pass show db)\"", "pass show"),
            (
                "curl -v -H \"X-Api-Key: $(pass show k)\" https://api",
                "pass show",
            ),
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
            "security find-generic-password -s svc -w | sha256sum",
            "security find-generic-password -s svc -w > /tmp/pw",
            "security find-generic-password -s svc -w >/dev/null",
            "security find-generic-password -s svc -w &>/dev/null",
            "op read --out-file /tmp/f op://v/i/f",
            "op read -o /tmp/f op://v/i/f",
            "op read op://v/i/f > token.txt",
            "op run -- gh api user",
            "op run --env-file app.env -- npm test",
            // Review round 1: `op inject` and the perl runner count only when
            // they print, so these keep main's silence.
            "op inject -i config.tpl -o config.yml",
            "op inject -i config.tpl --out-file=config.yml",
            "op inject -i config.tpl > config.yml",
            "op inject -i config.tpl | kubectl apply -f -",
            "op inject --help",
            "op inject -h",
            "perl -e 'alarm 9; exec @ARGV' op read op://v/i/f | pbcopy",
            "perl -e 'alarm 9; exec @ARGV' curl -fsS https://x",
            "op read op://v/i/f | base64 -d > key.bin",
            "aws configure get region",
            "aws ssm get-parameter --name /x",
            "pass ls",
            "pass",
            "kubectl get secret s -o json | jq -r .data.p | base64 -d | sha256sum",
            "vault kv get secret/x",
            // Review round 2: a Secret's json or yaml that feeds a consumer
            // or a file keeps main's silence; `describe` shows sizes.
            "kubectl get secret app -o yaml | kubectl apply -f -",
            "kubectl get secret app -o yaml > secret.yaml",
            "kubectl get secret app -o json | grep -c token",
            "kubectl describe secret app",
            "kubectl get secret --help",
            "op inject --version",
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

    /// Shapes whose value lands in the command's own output
    /// (cameronsjo/cadence-hooks#1662): each one blocks.
    #[test]
    fn printed_values_block() {
        let cases: &[(&str, &str)] = &[
            ("op read op://vault/item/password", "op read"),
            ("op read 'op://vault/item/password' >&2", "op read"),
            ("op read op://v/i/f > /dev/stdout", "op read"),
            ("op read op://v/i/f -o /dev/stdout", "op read"),
            ("op read op://v/i/f 2>/dev/null", "op read"),
            ("op read op://v/i/f &", "op read"),
            (
                "op item get db --fields password --reveal",
                "op item get --reveal",
            ),
            (
                "security find-generic-password -s svc -a me -w",
                "security find-*-password -w",
            ),
            (
                "sudo security find-generic-password -ws svc",
                "security find-*-password -w",
            ),
            (
                "echo start; security find-generic-password -s x -w && echo done",
                "security find-*-password -w",
            ),
            ("echo x | shasum; op read op://v/i/f", "op read"),
            ("cd /repo && op read op://v/i/f", "op read"),
            (
                "kubectl get secret app -o jsonpath='{.data.token}'",
                "kubectl get secret -o jsonpath",
            ),
            (
                "kubectl -n prod get secrets/app -ojsonpath={.data.k}",
                "kubectl get secret -o jsonpath",
            ),
            ("vault kv get -field=password secret/x", "vault read -field"),
            (
                "aws secretsmanager get-secret-value --secret-id x --query SecretString --output text",
                "aws secretsmanager get-secret-value",
            ),
            (
                "gcloud auth print-access-token",
                "gcloud auth print-access-token",
            ),
            ("pass show x", "pass show"),
            ("pass db", "pass show"),
            // A substitution an argument printer prints.
            ("echo $(op read op://v/i/f)", "op read"),
            ("echo \"$(op read op://v/i/f)\"", "op read"),
            ("echo -n \"token: $(op read op://v/i/f)\"", "op read"),
            ("printf \"%s\\n\" \"$(op read x)\"", "op read"),
            ("printf '%s\\n' \"$(pass show x)\"", "pass show"),
            ("eval 'pass show x'", "pass show"),
            ("echo `pass show x`", "pass show"),
            ("sudo echo \"$(op read op://v/i/f)\"", "op read"),
            ("echo \"$(op read op://v/i/f)\" >&2", "op read"),
            // A substitution in command position: the shell reports the value.
            ("\"$(op read op://v/i/f)\"", "op read"),
            ("$(pass show x)", "pass show"),
            ("X=1 \"$(op read op://v/i/f)\"", "op read"),
            // A here-string is not a heredoc: command position still reads.
            ("\"$(op read op://v/i/f)\" <<< x", "op read"),
            (
                "echo \"$(op read op://v/i/f)\"; cat <<EOF\nhi\nEOF",
                "op read",
            ),
            ("printf '%s\\n' -v \"$(op read op://v/i/f)\"", "op read"),
            // A `-c`/`eval` script writes to the command's output.
            ("sh -c 'pass show x'", "pass show"),
            ("bash -c 'op read op://v/i/f'", "op read"),
            ("eval 'vault kv get -field=p secret/x'", "vault read -field"),
            ("bash -c 'echo \"$(op read op://v/i/f)\"'", "op read"),
            // Review round 1: a pipeline whose later stages all pass the value
            // through to the output prints it.
            ("op read op://v/i/f | cat", "op read"),
            ("op read op://v/i/f | tee", "op read"),
            ("op read op://v/i/f | tee .env", "op read"),
            ("op read op://v/i/f | head -c 10", "op read"),
            ("op read op://v/i/f | tail -c 4", "op read"),
            ("op read op://v/i/f | jq .", "op read"),
            ("op read op://v/i/f | tr -d '\\n'", "op read"),
            ("op read op://v/i/f | xxd | head", "op read"),
            ("op read op://v/i/f 2>&1 | cat", "op read"),
            (
                "kubectl get secret app -o jsonpath='{.data.token}' | base64 -d",
                "kubectl get secret -o jsonpath",
            ),
            (
                "kubectl get secret app -o jsonpath='{.data.token}' | base64 --decode",
                "kubectl get secret -o jsonpath",
            ),
            (
                "kubectl get secret s -o json | jq -r .data.p | base64 -d",
                "kubectl get secret -o json|yaml",
            ),
            ("echo \"$(op read op://v/i/f)\" | cat", "op read"),
            ("bash -c 'op read op://v/i/f' | cat", "op read"),
            ("cat <<< \"$(op read op://v/i/f)\"", "op read"),
            ("base64 <<< \"$(op read op://v/i/f)\"", "op read"),
            ("cat <(pass show x)", "pass show"),
            ("cat < <(pass show x)", "pass show"),
            ("cat <<EOF\n$(op read op://v/i/f)\nEOF", "op read"),
            ("cat <<EOF | base64\n$(op read op://v/i/f)\nEOF", "op read"),
            // Review round 1: forms main passed silently.
            ("op inject -i config.tpl", "op inject"),
            ("op inject -i config.tpl -o /dev/stdout", "op inject"),
            (
                "perl -e 'alarm 9; exec @ARGV' op read op://v/i/f",
                "op read",
            ),
            (
                "perl -e 'alarm 30; exec @ARGV' security find-generic-password -s s -w",
                "security find-*-password -w",
            ),
            // zsh `print` prints its arguments.
            ("print -r -- \"$(op read op://v/i/f)\"", "op read"),
            // Bare forms of producers the redactor masks by default.
            (
                "az account get-access-token --query accessToken -o tsv",
                "az account get-access-token",
            ),
            (
                "az account get-access-token -o tsv",
                "az account get-access-token",
            ),
            (
                "aws secretsmanager get-secret-value --secret-id x --output text",
                "aws secretsmanager get-secret-value",
            ),
            // Not masked by the redactor: the block stays.
            (
                "aws ssm get-parameter --name /x --with-decryption",
                "aws ssm get-parameter --with-decryption",
            ),
            (
                "az keyvault secret show --vault-name v -n x",
                "az keyvault secret show",
            ),
            ("op item get db --reveal", "op item get --reveal"),
            ("pass show db", "pass show"),
            // Code review of round 1: nested double quotes inside the
            // substitution, a quoted blank included.
            ("echo \"$(op read \"op://v/i/f\")\"", "op read"),
            (
                "printf '%s' \"$(op read \"op://v/i name/credential\")\"",
                "op read",
            ),
            (
                "echo \"$(security find-generic-password -s \"my svc\" -w)\"",
                "security find-*-password -w",
            ),
            ("cat <<< \"$(op read \"op://v/i/f\")\"", "op read"),
            // A filter that strips the key names the redactor masks by.
            (
                "aws secretsmanager get-secret-value --secret-id x | jq -r .SecretString",
                "aws secretsmanager get-secret-value",
            ),
            (
                "az account get-access-token | jq -r .accessToken",
                "az account get-access-token",
            ),
            (
                "aws secretsmanager get-secret-value --secret-id x | jq -r '.SecretString | fromjson | .password'",
                "aws secretsmanager get-secret-value",
            ),
            (
                "az account get-access-token -otsv",
                "az account get-access-token",
            ),
            // Stages that do pass the value through.
            ("op read op://v/i/f | jq -r .password", "op read"),
            ("op read op://v/i/f | sed 's/a/b/'", "op read"),
            ("op read op://v/i/f | cat -", "op read"),
            ("op read op://v/i/f | head -n 1", "op read"),
            ("op read op://v/i/f | xxd -", "op read"),
            ("op read op://v/i/f | cut -c1-4", "op read"),
            // A filter that walks under a Secret's `.data` prints its value.
            (
                "kubectl get secret s -o json | jq -r '.data.token' | base64 -d",
                "kubectl get secret -o json|yaml",
            ),
            (
                "kubectl get secret s -o yaml | yq '.data.token'",
                "kubectl get secret -o json|yaml",
            ),
            // Review round 2: a Secret's json or yaml that reaches the output,
            // whole or through any filter.
            (
                "kubectl get secret app -o json",
                "kubectl get secret -o json|yaml",
            ),
            (
                "kubectl get secrets -o yaml",
                "kubectl get secret -o json|yaml",
            ),
            (
                "kubectl get secret app -o yaml | cat",
                "kubectl get secret -o json|yaml",
            ),
            (
                "kubectl get secret s -o json | jq .",
                "kubectl get secret -o json|yaml",
            ),
            (
                "kubectl get secret app -o json | jq -r '.data | map_values(@base64d)'",
                "kubectl get secret -o json|yaml",
            ),
            (
                "kubectl get secret app -o json | jq -r '.data | to_entries[] | \"\\(.key)=\\(.value | @base64d)\"'",
                "kubectl get secret -o json|yaml",
            ),
            (
                "kubectl get secret app -o json | jq -r '.data | .token' | base64 -d",
                "kubectl get secret -o json|yaml",
            ),
            (
                "kubectl get secret app -o json | jq -r '.[\"data\"][\"token\"]' | base64 -d",
                "kubectl get secret -o json|yaml",
            ),
            (
                "kubectl get secret app -o json | jq -r '.data'",
                "kubectl get secret -o json|yaml",
            ),
            (
                "kubectl get secret app -o yaml | yq '.data'",
                "kubectl get secret -o json|yaml",
            ),
            // A selector that reaches data, or the whole object.
            (
                "kubectl get secret app -o jsonpath='{.data}'",
                "kubectl get secret -o jsonpath",
            ),
            (
                "kubectl get secret app -o go-template='{{range $k, $v := .data}}{{$k}}={{$v}}{{end}}'",
                "kubectl get secret -o jsonpath",
            ),
            (
                "kubectl get secret app -o jsonpath='{@}'",
                "kubectl get secret -o jsonpath",
            ),
            (
                "kubectl get secrets -o custom-columns=NAME:.metadata.name,DATA:.data",
                "kubectl get secret -o jsonpath",
            ),
            // An output-format variable selects the unmasked form, as the flag.
            (
                "AWS_DEFAULT_OUTPUT=text aws secretsmanager get-secret-value --secret-id x",
                "aws secretsmanager get-secret-value",
            ),
            (
                "AZURE_CORE_OUTPUT=tsv az account get-access-token",
                "az account get-access-token",
            ),
            // `tail -c` can cut the key name off.
            (
                "aws secretsmanager get-secret-value --secret-id x | tail -c 60",
                "aws secretsmanager get-secret-value",
            ),
            // A query for the value field, in any format but `none`.
            (
                "aws secretsmanager get-secret-value --secret-id x --query SecretString --output json",
                "aws secretsmanager get-secret-value",
            ),
            (
                "az keyvault secret show --vault-name v --name n --query value -o tsv",
                "az keyvault secret show",
            ),
            (
                "aws ssm get-parameter --name /x --with-decryption --query Parameter",
                "aws ssm get-parameter --with-decryption",
            ),
            // Code review of round 2: a whole parameter by index, a value
            // filter after a cloud read, recursive descent, an indexed item.
            (
                "aws ssm get-parameters --names x --with-decryption --query 'Parameters[0]'",
                "aws ssm get-parameter --with-decryption",
            ),
            (
                "aws ssm get-parameter --name /x --with-decryption | jq -r .Parameter",
                "aws ssm get-parameter --with-decryption",
            ),
            (
                "aws secretsmanager get-secret-value --secret-id x | jq -r .SecretString",
                "aws secretsmanager get-secret-value",
            ),
            (
                "op item get x --reveal --format json | jq -r '.fields[] | .value'",
                "op item get --reveal",
            ),
            (
                "kubectl get secret s -o jsonpath='{..password}'",
                "kubectl get secret -o jsonpath",
            ),
            (
                "kubectl get secrets -o jsonpath='{.items[0]}'",
                "kubectl get secret -o jsonpath",
            ),
            // Security review of round 2: data inside an interpolation, and
            // the metadata and annotations that can hold the applied
            // manifest.
            (
                "kubectl get secret app -o json | jq -r '.metadata.name + \"=\\(.data.token)\"'",
                "kubectl get secret -o json|yaml",
            ),
            (
                "kubectl get secrets -o json | jq -r '.items[] | .metadata.name + \" \\(.data.token | @base64d)\"'",
                "kubectl get secret -o json|yaml",
            ),
            (
                "kubectl get secret app -o json | jq '.metadata'",
                "kubectl get secret -o json|yaml",
            ),
            (
                "kubectl get secret app -o json | jq '.metadata.annotations'",
                "kubectl get secret -o json|yaml",
            ),
            (
                "kubectl get secret app -o json | jq 'del(.data)'",
                "kubectl get secret -o json|yaml",
            ),
            (
                "kubectl get secret app -o jsonpath='{.metadata.annotations}'",
                "kubectl get secret -o jsonpath",
            ),
            // A bare `help` or `version` elsewhere is an item name.
            ("pass show version", "pass show"),
            ("bw get password version", "bw get password"),
            ("bw get password help --session s", "bw get password"),
            // Whole-object spellings of a query.
            (
                "aws secretsmanager get-secret-value --secret-id x --query '*'",
                "aws secretsmanager get-secret-value",
            ),
            (
                "aws ssm get-parameter --name /x --with-decryption --query 'Parameter.*'",
                "aws ssm get-parameter --with-decryption",
            ),
            // `--version <id>` picks a secret version; the read prints.
            (
                "az keyvault secret show --vault-name v -n x --version abc123",
                "az keyvault secret show",
            ),
            // `tee` to the terminal prints whatever follows it.
            (
                "op read op://v/i/f | tee /dev/tty | docker login --password-stdin",
                "op read",
            ),
        ];
        for (command, want) in cases {
            assert_eq!(
                judge(command),
                Some(Finding {
                    label: want,
                    exposure: Exposure::Printed
                }),
                "{command}"
            );
        }
    }

    /// Shapes that hand the value to a consumer keep today's ask: the guard
    /// cannot prove the consumer quiet, and must not newly block them.
    #[test]
    fn consumer_values_keep_their_ask() {
        let cases: &[(&str, &str)] = &[
            (
                "op read op://v/i/token | gh auth login --with-token",
                "op read",
            ),
            (
                "security find-generic-password -s svc -w | docker login -u me --password-stdin",
                "security find-*-password -w",
            ),
            (
                "security find-generic-password -s svc -w | pbcopy",
                "security find-*-password -w",
            ),
            ("op read op://v/i/f | grep -i abc", "op read"),
            ("GH_TOKEN=\"$(op read op://v/i/t)\" gh api user", "op read"),
            // A stage outside the pass-through table keeps the ask.
            ("op read op://v/i/f | tr -d '\\n' | pbcopy", "op read"),
            (
                "op read op://v/i/f | base64 | docker login --password-stdin",
                "op read",
            ),
            ("op read op://v/i/f | tee f > /dev/null", "op read"),
            (
                "X=$(security find-generic-password -s svc -w); echo $X",
                "security find-*-password -w",
            ),
            ("export GH_TOKEN=\"$(op read op://v/i/t)\"", "op read"),
            ("TOKEN=$(op read op://v/i/f) gh api user", "op read"),
            ("env T=\"$(op read op://v/i/f)\" printenv T", "op read"),
            (
                "curl -H \"Authorization: Bearer $(op read op://v/i/f)\" https://x",
                "op read",
            ),
            ("psql \"postgres://u:$(pass show db)@h/db\"", "pass show"),
            ("ssh h \"echo $(op read op://v/i/f)\"", "op read"),
            (
                "docker login --password-stdin <<< \"$(op read op://v/i/f)\"",
                "op read",
            ),
            (
                "gh auth login --with-token < <(op read op://v/i/f)",
                "op read",
            ),
            (
                "echo \"$(op read op://v/i/f)\" | docker login --password-stdin",
                "op read",
            ),
            ("echo \"$(op read op://v/i/f)\" > token.txt", "op read"),
            ("echo $(op read op://v/i/f | sha256sum)", "op read"),
            ("{ op read op://v/i/f; } > token.txt", "op read"),
            ("( op read op://v/i/f ) | pbcopy", "op read"),
            ("bash -c 'op read op://v/i/f' | pbcopy", "op read"),
            ("echo $(bash -c 'op read op://v/i/f') > f", "op read"),
            // Code review round 1: a command word that only starts with `$`,
            // `printf -v`, a redirect target and a process substitution.
            (
                "$HOME/bin/tool --token \"$(op read op://v/i/f)\"",
                "op read",
            ),
            ("\"$TOOL\" login -p \"$(op read op://v/i/f)\"", "op read"),
            (
                "${KUBECTL:-kubectl} create secret generic s --from-literal=p=\"$(op read op://v/i/f)\"",
                "op read",
            ),
            ("printf -v TOKEN '%s' \"$(op read op://v/i/f)\"", "op read"),
            ("echo hi 2>\"$(op read op://v/i/f)\"", "op read"),
            ("echo <(op read op://v/i/f)", "op read"),
            // Security review round 1: a heredoc body feeds its command's
            // stdin, a consumer, though the splitter re-appends its
            // substitutions as segments of their own.
            (
                "docker login -u me --password-stdin <<EOF\n$(op read op://v/i/f)\nEOF",
                "op read",
            ),
            (
                "cat <<EOF | docker login --password-stdin\n$(op read op://v/i/f)\nEOF",
                "op read",
            ),
            (
                "kubectl apply -f - <<EOF\nkind: Secret\n  pw: $(op read op://v/i/f)\nEOF",
                "op read",
            ),
            (
                "cat > config.yml <<EOF\npw: $(op read op://v/i/f)\nEOF",
                "op read",
            ),
            (
                "tee config.yml >/dev/null <<EOF\npw: $(op read op://v/i/f)\nEOF",
                "op read",
            ),
            (
                "psql <<-EOF\nALTER ROLE u PASSWORD '$(pass show db)';\nEOF",
                "pass show",
            ),
            (
                "gh secret set K <<EOF\n$(op read op://v/i/f)\nEOF",
                "op read",
            ),
            // Security review round 2: a redirect glued to the word before it.
            ("echo \"T=$(op read op://v/i/f)\">>.env", "op read"),
            ("echo $(op read op://v/i/f)>f", "op read"),
            ("printf '%s' \"$(op read op://v/i/f)\">.env", "op read"),
            ("op read op://v/i/f>/dev/null", "op read"),
            ("op read 'op://v/i/f'>token.txt", "op read"),
            ("op read op://v/i/f 2>&1>/dev/null", "op read"),
            // PR review round 1: a clipboard flag sends the value to the
            // clipboard, not the output.
            ("pass -c db", "pass show"),
            ("pass show -c db", "pass show"),
            ("pass show --clip db", "pass show"),
            ("pass -c2 db", "pass show"),
            ("gopass show -c db", "gopass show"),
            ("lpass show -c --password item", "lpass show --password"),
            // Default JSON whose value field the redactor masks
            // (`default_json_values_the_redactor_masks`).
            ("az account get-access-token", "az account get-access-token"),
            (
                "az account get-access-token -o json",
                "az account get-access-token",
            ),
            (
                "aws secretsmanager get-secret-value --secret-id x",
                "aws secretsmanager get-secret-value",
            ),
            // Stdout closed, or sent after a stderr already in a file.
            ("op read op://v/i/f >&-", "op read"),
            ("op read op://v/i/f 1>&-", "op read"),
            ("op read op://v/i/f 2>/dev/null >&2", "op read"),
            // zsh `print -v` assigns.
            ("print -v T \"$(op read op://v/i/f)\"", "op read"),
            // Code review of round 1: a stage that writes elsewhere or reads
            // a file instead of stdin.
            (
                "op read op://v/i/f | yq --inplace '.a = load_str(\"/dev/stdin\")' f.yml",
                "op read",
            ),
            ("op read op://v/i/f | sed -ni 's/x/y/p' f", "op read"),
            ("op read op://v/i/f | jq . other.json", "op read"),
            ("op read op://v/i/f | base64 -i in.txt", "op read"),
            ("op read op://v/i/f | cat /dev/null", "op read"),
            ("op read op://v/i/f | xxd - out.hex", "op read"),
            // `>&word` sends both streams to the file `word`.
            ("op read op://v/i/f >&out.txt", "op read"),
            // Masked JSON whose later stages keep the key names.
            (
                "aws secretsmanager get-secret-value --secret-id x | head -n 5",
                "aws secretsmanager get-secret-value",
            ),
            (
                "aws secretsmanager get-secret-value --secret-id x | jq .",
                "aws secretsmanager get-secret-value",
            ),
            // Words before the printer are not printed.
            ("T=\"$(op read op://v/i/f)\" echo hi", "op read"),
            // Excluded words matched quote-blind: a redirect target whose
            // substitution holds nested quotes is still not printed.
            ("echo hi 2>\"$(op read \"op://v/i/f\")\"", "op read"),
            ("T=\"$(op read \"op://v/i/f\")\" echo hi", "op read"),
            // `--help` prints usage.
            ("op read --help", "op read"),
            // Review round 2: a kubectl selector that names only metadata,
            // `type` or a count keeps main's ask.
            (
                "kubectl get secrets -o jsonpath='{.items[*].metadata.name}'",
                "kubectl get secret -o jsonpath",
            ),
            (
                "kubectl get secrets -o jsonpath='{range .items[*]}{.metadata.name}{\"\\n\"}{end}'",
                "kubectl get secret -o jsonpath",
            ),
            (
                "kubectl get secret app -o jsonpath='{.type}'",
                "kubectl get secret -o jsonpath",
            ),
            (
                "kubectl get secret app -o jsonpath='{.metadata.labels.database}'",
                "kubectl get secret -o jsonpath",
            ),
            (
                "kubectl get secret app -o jsonpath='{.metadata.creationTimestamp}'",
                "kubectl get secret -o jsonpath",
            ),
            (
                "kubectl get secrets -o custom-columns=NAME:.metadata.name,TYPE:.type",
                "kubectl get secret -o jsonpath",
            ),
            (
                "kubectl get secrets -n prod -o go-template='{{range .items}}{{.metadata.name}}{{\"\\n\"}}{{end}}'",
                "kubectl get secret -o jsonpath",
            ),
            // Help and version on any producer.
            ("az keyvault secret show --help", "az keyvault secret show"),
            ("az keyvault secret show -h", "az keyvault secret show"),
            (
                "gcloud secrets versions access --help",
                "gcloud secrets versions access",
            ),
            (
                "gcloud auth print-access-token --help",
                "gcloud auth print-access-token",
            ),
            ("heroku auth:token --help", "heroku auth:token"),
            ("bw get password --help", "bw get password"),
            ("gopass show --help", "gopass show"),
            ("pass show --help", "pass show"),
            (
                "aws secretsmanager get-secret-value help",
                "aws secretsmanager get-secret-value",
            ),
            // A query for a field that is not the value, and `-o none`.
            (
                "az keyvault secret show --vault-name v --name n --query id -o tsv",
                "az keyvault secret show",
            ),
            (
                "az keyvault secret show --vault-name v --name n --query attributes.expires -o tsv",
                "az keyvault secret show",
            ),
            (
                "aws secretsmanager get-secret-value --secret-id x --query Name --output text",
                "aws secretsmanager get-secret-value",
            ),
            (
                "aws secretsmanager get-secret-value --secret-id x --query VersionId",
                "aws secretsmanager get-secret-value",
            ),
            (
                "aws ssm get-parameter --name /x --with-decryption --query Parameter.Version",
                "aws ssm get-parameter --with-decryption",
            ),
            (
                "az account get-access-token --query expiresOn -o tsv",
                "az account get-access-token",
            ),
            (
                "az account get-access-token -o none",
                "az account get-access-token",
            ),
            // Structured formats the redactor masks
            // (`structured_values_the_redactor_masks`).
            (
                "aws secretsmanager get-secret-value --secret-id x --output yaml",
                "aws secretsmanager get-secret-value",
            ),
            (
                "aws secretsmanager get-secret-value --secret-id x --output yaml-stream",
                "aws secretsmanager get-secret-value",
            ),
            (
                "az account get-access-token -o yaml",
                "az account get-access-token",
            ),
            (
                "az account get-access-token -o jsonc",
                "az account get-access-token",
            ),
            // `>& file` sends both streams to the file.
            ("op read op://v/i/f >& out.txt", "op read"),
            // A cloud read's query that picks a field that is not the value.
            (
                "aws ssm get-parameters-by-path --path /x --with-decryption --query 'Parameters[*].Name'",
                "aws ssm get-parameter --with-decryption",
            ),
            // Letter clusters: `print -rv` assigns, `gopass show -co` copies.
            ("print -rv T \"$(op read op://v/i/f)\"", "op read"),
            ("gopass show -co db", "gopass show"),
        ];
        for (command, want) in cases {
            assert_eq!(
                judge(command),
                Some(Finding {
                    label: want,
                    exposure: Exposure::Exposed
                }),
                "{command}"
            );
        }
    }

    /// The taint rule (review round 3): once a producer form's output carries
    /// a value, every later `jq`/`yq` stage keeps it, whatever its filter
    /// says. A stage that ends the pipeline prints it: a block. The filter is
    /// never read, so a name-listing filter blocks too, on purpose; kubectl's
    /// own selectors are the way to list names.
    #[test]
    fn every_filter_after_a_value_keeps_it() {
        const OP: &str = "op read";
        const ITEM: &str = "op item get --reveal";
        const SM: &str = "aws secretsmanager get-secret-value";
        const KV: &str = "az keyvault secret show";
        const TOKEN: &str = "az account get-access-token";
        const SSM: &str = "aws ssm get-parameter --with-decryption";
        const JSONPATH: &str = "kubectl get secret -o jsonpath";
        let cases: &[(&str, &str)] = &[
            // Finding 1: a field step after the value is already selected.
            (
                "aws secretsmanager get-secret-value --secret-id x --query SecretString --output text | jq -r .password",
                SM,
            ),
            (
                "aws secretsmanager get-secret-value --secret-id x --query SecretString | jq -r 'fromjson | .password'",
                SM,
            ),
            (
                "aws secretsmanager get-secret-value --secret-id x | jq -r .SecretString | jq -r .password",
                SM,
            ),
            (
                "az keyvault secret show --vault-name v -n n --query value -o tsv | jq -r .password",
                KV,
            ),
            (
                "aws secretsmanager get-secret-value --secret-id x | jq -r '.[]'",
                SM,
            ),
            ("az account get-access-token | jq '..'", TOKEN),
            (
                "aws ssm get-parameter --name /x --with-decryption | jq -r '.Parameter | .[]'",
                SSM,
            ),
            (
                "op item get db --reveal --format json | jq -r '.fields[1]'",
                ITEM,
            ),
            (
                "op item get db --reveal --format json | jq -r '.fields[]'",
                ITEM,
            ),
            // A field that is not the value: still the producer's output.
            (
                "aws secretsmanager get-secret-value --secret-id x | jq -r .ARN",
                SM,
            ),
            (
                "aws secretsmanager get-secret-value --secret-id x | jq -r .Name",
                SM,
            ),
            ("az account get-access-token | jq -r .expiresOn", TOKEN),
            (
                "op item get x --reveal --format json | jq -r '.fields[] | .label'",
                ITEM,
            ),
            (
                "op item get db --reveal --format json | jq '.fields | length'",
                ITEM,
            ),
            ("op read op://v/i/notes | jq keys", OP),
            ("op read op://v/i/notes | jq length", OP),
            // `--stream` rewrites each pair as `[["key"], value]`, which
            // the redactor does not mask.
            (
                "aws secretsmanager get-secret-value --secret-id x | jq --stream .",
                SM,
            ),
            // Review round 4: a selection is not read either; a multi-line
            // value's later lines, or the line it picks, are printed.
            ("pass show x | tail -n +2", "pass show"),
            ("pass show x | sed -n 2p", "pass show"),
            ("pass show email/x | sed -n 's/^password: //p'", "pass show"),
            ("pass show email/x | sed --quiet 1p", "pass show"),
            ("op read op://v/key/private-key | tail +2", OP),
            ("op read op://v/key/private-key | sed -n '2,$p'", OP),
            // An option's value is not the filter.
            ("op read op://v/i/f | yq -I 2 '.a'", OP),
            ("op read op://v/i/f | jq -f filter.jq", OP),
            // An unknown option before the type keeps main's rule for a
            // selector that prints data (review round 4).
            (
                "kubectl get --as admin secret app -o jsonpath='{.data.token}'",
                JSONPATH,
            ),
            (
                "kubectl get -s https://k:6443 secret app -o jsonpath='{.data.token}'",
                JSONPATH,
            ),
            // Finding 3: a jsonpath that reaches data, into a decode filter.
            (
                "kubectl get secret app -o jsonpath='{.data}' | jq 'map_values(@base64d)'",
                JSONPATH,
            ),
            (
                "kubectl get secret app -o jsonpath='{.data}' | jq -r 'to_entries[] | \"\\(.key)=\\(.value | @base64d)\"'",
                JSONPATH,
            ),
        ];
        // Finding 2 and every name-listing filter: any filter on a Secret's
        // json or yaml.
        let secret_filters = [
            "kubectl get secrets -o json | jq '.items[] | select(.metadata.name==\"app\")'",
            "kubectl get secrets -o json | jq '.items[] | select(.type==\"kubernetes.io/tls\")'",
            "kubectl get secrets -o json | jq '.items | map(select(.type == \"Opaque\"))'",
            "kubectl get secrets -o json | jq '.items | sort_by(.metadata.creationTimestamp)'",
            "kubectl get secret app -o json | jq '.metadata.name, .'",
            "kubectl get secret app -o json | jq '.metadata.name, getpath([\"data\",\"token\"])'",
            "kubectl get secret app -o json | jq '.metadata.name, (.|tojson)'",
            "kubectl get secret app -o json | jq 'if .type == \"Opaque\" then . else empty end'",
            "kubectl get secrets -o yaml | yq '.items[] | select(.metadata.name == \"app\")'",
            "kubectl get secrets -o json | jq '.items[].metadata.name'",
            "kubectl get secret s -o json | jq -r '.metadata.name'",
            "kubectl get secret s -o yaml | yq '.metadata.name'",
            "kubectl get secret s -o yaml | yq -o json '.metadata.name'",
            "kubectl get secret s -o json | jq -r '.data | keys[]'",
            "kubectl get secret s -o json | jq --arg k v '.data | keys'",
            "kubectl get secret s -o json | jq -r --indent 2 'keys'",
            "kubectl get secret app -o json | jq -r '.data | keys | join(\",\")'",
            "kubectl get secret app -o json | jq -r '.data | to_entries[] | .key'",
            "kubectl get secret app -o json | jq '.data | length'",
            "kubectl get secrets -o json | jq -r '.items[0].metadata.name'",
            "kubectl get secrets -o json | jq -r '.items[] | [.metadata.namespace, .metadata.name] | @tsv'",
            "kubectl get secret app -o json | jq 'del(.data, .metadata.annotations)'",
            "kubectl get secret app -o json | jq --arg n app '.metadata.name == $n'",
            // The resource type comes after options and their values.
            "kubectl get -n prod secrets -o json",
            "kubectl -n prod get secret app -o yaml",
            // An option the reader does not know may be a flag or take the
            // next word, so both readings are followed (review round 4).
            "kubectl get --as admin secret app -o json | jq .",
            "kubectl get -L app secrets -o json | jq .",
            "kubectl get --as-group g secret app -o yaml",
            "kubectl get -w secrets -o yaml",
        ];
        let all = cases
            .iter()
            .copied()
            .chain(secret_filters.iter().map(|c| (*c, STRUCTURED_SECRET)));
        for (command, want) in all {
            assert_eq!(
                judge(command),
                Some(Finding {
                    label: want,
                    exposure: Exposure::Printed
                }),
                "{command}"
            );
        }
        // The same values handed to a consumer, or to a file, keep main's
        // verdict; kubectl's own selectors and `describe` list names.
        for (command, want) in [
            (
                "kubectl get secret s -o json | jq -r '.data.token' | docker login --password-stdin",
                Some("kubectl get secret -o json|yaml | jq"),
            ),
            (
                "aws secretsmanager get-secret-value --secret-id x | jq -r .SecretString | xargs -0 tool",
                Some(SM),
            ),
            ("op read op://v/i/f | jq -r .a > out.json", None),
            // The masked cloud reads through `jq .` with options that keep
            // the key names keep main's ask.
            (
                "aws secretsmanager get-secret-value --secret-id x | jq --arg a b .",
                Some(SM),
            ),
            (
                "az account get-access-token | jq -c --indent 0 .",
                Some(TOKEN),
            ),
            (
                "aws secretsmanager get-secret-value --secret-id x | jq --argjson a 1 .",
                Some(SM),
            ),
            (
                "aws secretsmanager get-secret-value --secret-id x | jq -C --tab -S .",
                Some(SM),
            ),
            (
                "az account get-access-token | jq --indent 4 -M .",
                Some(TOKEN),
            ),
            // An unknown option before the type keeps main's ask on a
            // selector that does not print data.
            (
                "kubectl get --as admin secrets -o jsonpath='{.items[*].metadata.name}'",
                Some(JSONPATH),
            ),
            // jq reads its file operand, not the piped value.
            ("op read op://v/i/f | jq -f filter.jq data.json", Some(OP)),
            // A namespace or object named `secret` is not the Secret type.
            ("kubectl get pods -n secrets -o yaml", None),
            ("kubectl get deploy secret -o json", None),
            // Neither reading of an unknown option reaches a Secret type:
            // no block, and main's verdict (review round 4).
            ("kubectl get --show-labels pods -n secrets -o yaml", None),
            ("kubectl get -w pods -n secrets -o yaml", None),
            ("kubectl get --as admin deploy secret -o yaml", None),
            (
                "kubectl get -L app pods -n secrets -o json | jq .",
                Some("kubectl get secret -o json|yaml | jq"),
            ),
            (
                "kubectl get -n secrets -A configmaps -o jsonpath='{.items[*].data}'",
                Some(JSONPATH),
            ),
            // The positional reading only withholds a block: main asked here,
            // so the ask stays (review round 4).
            (
                "kubectl -n secrets get configmaps -o json | jq .",
                Some("kubectl get secret -o json|yaml | jq"),
            ),
            (
                "kubectl get pods -n secrets -o jsonpath='{.items[*].data}'",
                Some(JSONPATH),
            ),
            (
                "kubectl get secrets -o jsonpath='{.items[*].metadata.name}'",
                Some(JSONPATH),
            ),
            ("kubectl get secrets -o name", None),
            ("kubectl describe secret app", None),
        ] {
            assert_eq!(
                judge(command).map(|f| (f.label, f.exposure)),
                want.map(|l| (l, Exposure::Exposed)),
                "{command}"
            );
        }
    }

    #[test]
    fn check_blocks_a_printed_value_and_asks_for_a_consumer() {
        let input = HookInput::from_json(
            r#"{"tool_name":"Bash","tool_input":{"command":"op read op://v/i/f"}}"#,
        )
        .unwrap();
        let result = SecretDumpGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        let message = result.message.unwrap();
        assert!(message.contains("`op read`"), "{message}");
        assert!(message.contains("pbcopy"), "{message}");
        assert!(message.contains("--password-stdin"), "{message}");
        assert!(message.contains("op run --"), "{message}");
        assert!(
            message.contains("still raise a permission prompt"),
            "{message}"
        );
        assert!(
            !message.contains("op://v/i/f"),
            "never echoes command text: {message}"
        );

        let consumer = HookInput::from_json(
            r#"{"tool_name":"Bash","tool_input":{"command":"op read op://v/i/f | pbcopy"}}"#,
        )
        .unwrap();
        let result = SecretDumpGuard.run(&consumer);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Ask);
        assert!(result.message.unwrap().contains("op read"));

        let quiet =
            HookInput::from_json(r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#).unwrap();
        assert_eq!(
            SecretDumpGuard.run(&quiet).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    /// Round 6: an unclosed `<<<$(` flood (the removed here-string scan was
    /// quadratic on it; a timeout fails open). 1 MB, release bound 0.5 s.
    #[test]
    fn unclosed_here_string_flood_stays_fast() {
        let flood = format!(
            "docker login --password-stdin r {}",
            "<<<$( ".repeat(1_000_000 / 6)
        );
        let bound = if cfg!(debug_assertions) {
            std::time::Duration::from_secs(20)
        } else {
            std::time::Duration::from_millis(500)
        };
        let started = std::time::Instant::now();
        let _ = first_exposed_dump(&flood);
        cadence_hooks_core::test_builders::assert_elapsed_under(
            &format!("took {:?}", started.elapsed()),
            started.elapsed(),
            bound,
        );
    }

    #[test]
    fn adversarial_200kb_command_stays_fast() {
        let long = format!("op read op://v/i/f{}", " | cat".repeat(40_000));
        let started = std::time::Instant::now();
        assert_eq!(first_exposed_dump(&long), Some("op read"));
        cadence_hooks_core::test_builders::assert_elapsed_under(
            "adversarial_200kb_command_stays_fast",
            started.elapsed(),
            std::time::Duration::from_secs(5),
        );
    }
}
