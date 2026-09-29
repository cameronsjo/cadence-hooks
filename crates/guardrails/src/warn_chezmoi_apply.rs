//! Warn when `chezmoi apply` would overwrite a file that has drifted locally
//! (cameronsjo/cadence-hooks#514).
//!
//! `chezmoi apply` writes source over live. When the live file was edited
//! directly since chezmoi last wrote it, apply discards that edit silently;
//! the right move there is `chezmoi re-add` (or `chezmoi merge`). The ruling on
//! #514 settled the detection: ask `chezmoi status` rather than fire on the
//! command text, because only real drift distinguishes the destructive apply
//! from the routine one, and a nudge that fires on both gets tuned out.
//!
//! **Drift** is a `chezmoi status` row whose first column is `M` (the live
//! file changed since chezmoi last wrote it) and whose second column is `M` or
//! `D` (apply will overwrite or remove it). The rows are narrowed to the
//! apply's targets when it names any, and dropped entirely when an
//! `--include`/`--exclude` keeps files out of the apply.
//!
//! **Scoping** (#514's second case) is a clause of the drift nudge, not a
//! nudge of its own: when drift is found and the apply names no targets and no
//! `--include`, the message says so and suggests `chezmoi apply <file>` or
//! `--include=files`. An unscoped apply over a clean tree stays silent.
//!
//! **What is never run.** `chezmoi status` evaluates templates, so running it
//! means running the user's own source-state templates (and anything they
//! shell out to) *before* the user has approved the apply. The hook accepts
//! that only in the default configuration, where those templates are the
//! same ones every `chezmoi` command already runs: an apply carrying a flag
//! that relocates the source, destination, config, or state (`-S`, `-D`,
//! `-c`, `-W`, `--cache`, `--persistent-state`, `--override-data*`), or that
//! changes what status would answer (`--init`, `--source-path`,
//! `-P`/`--parent-dirs`, `--interactive`), or that runs under a `VAR=value`
//! or `env` prefix (`HOME=`, `XDG_CONFIG_HOME=`, `CHEZMOI_*`), is left alone
//! rather than letting command text choose what executes before approval. A
//! dry run (`-n`) writes nothing and is skipped.
//!
//! Advisory only, and fails open (ADR-0001): `chezmoi` absent from `PATH`, a
//! non-zero exit, a timeout, or unreadable output all mean silence — never a
//! block, and never a claim of "no drift". The call is bounded
//! ([`crate::bounded_tool`]).

use cadence_hooks_core::shell::{
    command_segments, command_word, executable_tokens, is_assignment_word,
    skip_transparent_prefixes,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::path::{Path, PathBuf};

/// Flags that take a separate value, globally or on `apply`.
const VALUE_FLAGS: &[&str] = &[
    "-c",
    "--config",
    "--config-format",
    "--cache",
    "-D",
    "--destination",
    "-S",
    "--source",
    "-W",
    "--working-tree",
    "--color",
    "--mode",
    "-o",
    "--output",
    "--persistent-state",
    "--progress",
    "--use-builtin-age",
    "--use-builtin-diff",
    "--use-builtin-git",
    "--override-data",
    "--override-data-file",
    "-i",
    "--include",
    "-x",
    "--exclude",
];

/// Flags that point chezmoi at another source, destination, config, or state.
const RELOCATING_FLAGS: &[&str] = &[
    "-c",
    "--config",
    "--config-format",
    "--cache",
    "-D",
    "--destination",
    "-S",
    "--source",
    "-W",
    "--working-tree",
    "--persistent-state",
    "--override-data",
    "--override-data-file",
    // Not relocating, but each makes the default `chezmoi status` the wrong
    // question: `--init` regenerates the config first, `--source-path` and
    // `-P`/`--parent-dirs` change what the targets mean, and `--interactive`
    // has the user decide per file.
    "--init",
    "--source-path",
    "-P",
    "--parent-dirs",
    "--interactive",
];

/// One `chezmoi apply` as the hook reads it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ApplyCall {
    /// Positional targets, as written.
    pub targets: Vec<String>,
    /// `--include`/`-i` values, split on commas.
    pub include: Vec<String>,
    /// `--exclude`/`-x` values, split on commas.
    pub exclude: Vec<String>,
    /// A relocating flag was present: the default-config status is not the
    /// state this apply acts on.
    pub relocated: bool,
    /// `-n`/`--dry-run`.
    pub dry_run: bool,
}

/// Split a flag token into its name and an attached value (`--x=v`, `-iv`).
fn split_flag(token: &str) -> (&str, Option<&str>) {
    if let Some(long) = token.strip_prefix("--") {
        return match long.split_once('=') {
            Some((name, value)) => (&token[..name.len() + 2], Some(value)),
            None => (token, None),
        };
    }
    if token.len() > 2 && VALUE_FLAGS.contains(&&token[..2]) {
        return (&token[..2], Some(&token[2..]));
    }
    (token, None)
}

/// True for a short boolean cluster carrying `n` (`-n`, `-nv`).
fn is_short_dry_run(token: &str) -> bool {
    token.strip_prefix('-').is_some_and(|c| {
        !c.starts_with('-') && c.contains('n') && c.bytes().all(|b| matches!(b, b'n' | b'v' | b'k'))
    })
}

/// True for a short boolean cluster carrying `P` (`-P`, `-vP`).
fn is_short_parent_dirs(token: &str) -> bool {
    token.strip_prefix('-').is_some_and(|c| {
        !c.starts_with('-')
            && c.contains('P')
            && c.bytes().all(|b| matches!(b, b'n' | b'v' | b'k' | b'P'))
    })
}

/// Read the `chezmoi apply` in one segment's argv (starting at `chezmoi`).
fn read_apply(argv: &[String]) -> Option<ApplyCall> {
    let mut call = ApplyCall::default();
    let mut seen_apply = false;
    let mut i = 1;
    while let Some(token) = argv.get(i) {
        let token = token.as_str();
        if token == "--" {
            if seen_apply {
                call.targets.extend(argv[i + 1..].iter().cloned());
            }
            break;
        }
        if token.starts_with('-') && token.len() > 1 {
            let (name, attached) = split_flag(token);
            if RELOCATING_FLAGS.contains(&name) || is_short_parent_dirs(token) {
                call.relocated = true;
            }
            if name == "--dry-run" || is_short_dry_run(token) {
                call.dry_run = true;
            }
            let value = if VALUE_FLAGS.contains(&name) && attached.is_none() {
                i += 1;
                argv.get(i).map(String::as_str)
            } else {
                attached
            };
            if let Some(value) = value {
                let parts = value.split(',').map(|v| v.trim().to_ascii_lowercase());
                match name {
                    "-i" | "--include" => call.include.extend(parts),
                    "-x" | "--exclude" => call.exclude.extend(parts),
                    _ => {}
                }
            }
            i += 1;
            continue;
        }
        if !seen_apply {
            if token != "apply" {
                return None;
            }
            seen_apply = true;
        } else {
            call.targets.push(token.to_string());
        }
        i += 1;
    }
    seen_apply.then_some(call)
}

/// Every `chezmoi apply` in `command`.
pub fn apply_calls(command: &str) -> Vec<ApplyCall> {
    command_segments(command)
        .iter()
        .filter_map(|segment| {
            let tokens = executable_tokens(segment);
            let argv = skip_transparent_prefixes(&tokens);
            if command_word(argv.first()?).as_ref() != "chezmoi" {
                return None;
            }
            let mut call = read_apply(argv)?;
            // `HOME=… chezmoi apply`, `CHEZMOI_…=…`, `env X=… chezmoi`: the
            // apply runs in an environment the hook's own status would not
            // share, so treat it like a relocating flag.
            let prefix = &tokens[..tokens.len() - argv.len()];
            if prefix
                .iter()
                .any(|t| is_assignment_word(t) || command_word(t).as_ref() == "env")
            {
                call.relocated = true;
            }
            Some(call)
        })
        .collect()
}

/// Drifted paths in `chezmoi status` output, relative to the destination.
pub fn drifted_paths(status: &str) -> Vec<String> {
    status
        .lines()
        .filter_map(|line| {
            let mut chars = line.chars();
            let x = chars.next()?;
            let y = chars.next()?;
            let path = line.get(3..)?.trim();
            (x == 'M' && matches!(y, 'M' | 'D') && !path.is_empty()).then(|| path.to_string())
        })
        .collect()
}

/// A target as a path relative to `home`, or `None` when it cannot be placed
/// there (outside home, or not a literal).
fn target_under_home(target: &str, cwd: &Path, home: &Path) -> Option<String> {
    if target.contains('$') || target.contains('`') {
        return None;
    }
    let path = if target == "~" {
        home.to_path_buf()
    } else if let Some(rest) = target.strip_prefix("~/") {
        home.join(rest)
    } else if Path::new(target).is_absolute() {
        PathBuf::from(target)
    } else {
        cwd.join(target)
    };
    let rel = path.strip_prefix(home).ok()?;
    let mut parts = Vec::new();
    for c in rel.components() {
        match c {
            std::path::Component::Normal(p) => parts.push(p.to_string_lossy().into_owned()),
            std::path::Component::CurDir => {}
            _ => return None,
        }
    }
    Some(parts.join("/"))
}

/// The drift this apply would discard: `drift` narrowed to its targets and
/// include/exclude filters.
fn drift_in_scope(call: &ApplyCall, drift: &[String], cwd: &Path, home: &Path) -> Vec<String> {
    let files_kept_out = (!call.include.is_empty()
        && !call
            .include
            .iter()
            .any(|t| matches!(t.as_str(), "all" | "files" | "templates" | "encrypted")))
        || call
            .exclude
            .iter()
            .any(|t| matches!(t.as_str(), "all" | "files"));
    if files_kept_out {
        return Vec::new();
    }
    if call.targets.is_empty() {
        return drift.to_vec();
    }
    let scopes: Option<Vec<String>> = call
        .targets
        .iter()
        .map(|t| target_under_home(t, cwd, home))
        .collect();
    let Some(scopes) = scopes else {
        // A target the hook cannot place: every drifted file may be in it.
        return drift.to_vec();
    };
    drift
        .iter()
        .filter(|p| {
            scopes
                .iter()
                .any(|s| s.is_empty() || *p == s || p.starts_with(&format!("{s}/")))
        })
        .cloned()
        .collect()
}

/// The most characters of one status path the nudge shows.
const MAX_SHOWN_PATH: usize = 200;

/// A status path made safe for model-facing text: control characters and
/// backticks dropped, clamped to [`MAX_SHOWN_PATH`] characters.
fn clamp_path(path: &str) -> String {
    let clean: String = path
        .chars()
        .filter(|c| !c.is_control() && *c != '`')
        .collect();
    if clean.chars().count() > MAX_SHOWN_PATH {
        let cut: String = clean.chars().take(MAX_SHOWN_PATH).collect();
        format!("{cut}…")
    } else {
        clean
    }
}

/// Core decision, given the apply and a lazy `chezmoi status` probe.
pub fn evaluate(
    call: &ApplyCall,
    cwd: &Path,
    home: &Path,
    status: impl FnOnce() -> Option<String>,
) -> Option<String> {
    if call.relocated || call.dry_run {
        return None;
    }
    let drift = drifted_paths(&status()?);
    let hits = drift_in_scope(call, &drift, cwd, home);
    if hits.is_empty() {
        return None;
    }
    let shown = hits
        .iter()
        .take(5)
        .map(|p| format!("~/{}", clamp_path(p)))
        .collect::<Vec<_>>()
        .join(", ");
    let more = if hits.len() > 5 {
        format!(" (and {} more)", hits.len() - 5)
    } else {
        String::new()
    };
    let mut msg = format!(
        "warn-chezmoi-apply: `chezmoi status` shows local edits that this apply would \
         overwrite: {shown}{more}. Apply writes source over live, so an edit made directly \
         to the live file is discarded. Check with `chezmoi diff <file>` — a removal-only \
         diff means live drifted forward — and keep it with `chezmoi re-add <file>` (or \
         `chezmoi merge <file>`) before applying."
    );
    if call.targets.is_empty() && call.include.is_empty() {
        msg.push_str(
            " This apply is also unscoped, so it touches every managed file; scope it to \
             what you mean to change (`chezmoi apply <file>` or `--include=files`).",
        );
    }
    msg.push_str(" Advisory only.");
    Some(msg)
}

/// Nudges on `chezmoi apply` over drifted files.
pub struct WarnChezmoiApply;

impl Check for WarnChezmoiApply {
    fn name(&self) -> &str {
        "warn-chezmoi-apply"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };
        let calls = apply_calls(command);
        let Some(call) = calls.iter().find(|c| !c.relocated && !c.dry_run) else {
            return CheckResult::allow();
        };
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return CheckResult::allow();
        };
        let cwd = input
            .cwd
            .as_deref()
            .map(PathBuf::from)
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| home.clone());
        let status = || crate::bounded_tool::run_tool("chezmoi", &["status"], &cwd, &[]);
        match evaluate(call, &cwd, &home, status) {
            Some(msg) => CheckResult::nudge(msg),
            None => CheckResult::allow(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DRIFTED: &str =
        " M .zshrc\nMM .gitconfig\nMD .config/app/a.toml\nM  .vimrc\n R .chezmoiscripts/run.sh\n";
    const CLEAN: &str = " M .zshrc\n A .newfile\n";

    fn home() -> PathBuf {
        PathBuf::from("/home/u")
    }

    fn eval(command: &str, status: Option<&str>) -> Option<String> {
        let calls = apply_calls(command);
        let call = calls.first().expect("an apply");
        evaluate(call, Path::new("/home/u/src"), &home(), || {
            status.map(String::from)
        })
    }

    #[test]
    fn drift_rows_are_modified_live_that_apply_would_change() {
        assert_eq!(drifted_paths(DRIFTED), [".gitconfig", ".config/app/a.toml"]);
        assert!(drifted_paths(CLEAN).is_empty());
    }

    // The ruling's control pair: the same command nudges over drift and is
    // silent over a clean tree.
    #[test]
    fn control_pair_drift_nudges_clean_is_silent() {
        let msg = eval("chezmoi apply", Some(DRIFTED)).expect("drift must nudge");
        assert!(msg.contains("~/.gitconfig"), "{msg}");
        assert!(msg.contains("--include=files"), "unscoped clause: {msg}");
        assert_eq!(eval("chezmoi apply", Some(CLEAN)), None);
    }

    #[test]
    fn chezmoi_unavailable_is_silent_not_no_drift() {
        assert_eq!(eval("chezmoi apply", None), None);
        // A tool that cannot be spawned yields no status. Exercised with a
        // binary name that resolves nowhere rather than by emptying `PATH`:
        // `PATH` is process-global, and every concurrent fixture `git` child
        // would inherit the emptied value and fail to spawn (#1112).
        let status = || {
            crate::bounded_tool::run_tool(
                "cadence-hooks-no-such-tool-1112",
                &["status"],
                Path::new("/tmp"),
                &[],
            )
        };
        let call = &apply_calls("chezmoi apply")[0];
        assert_eq!(evaluate(call, Path::new("/tmp"), &home(), status), None);
    }

    #[test]
    fn targets_scope_the_drift() {
        let msg = eval("chezmoi apply ~/.gitconfig", Some(DRIFTED)).expect("nudge");
        assert!(msg.contains("~/.gitconfig"), "{msg}");
        assert!(!msg.contains("a.toml"), "{msg}");
        assert!(!msg.contains("unscoped"), "{msg}");
        assert!(eval("chezmoi apply ~/.zshrc", Some(DRIFTED)).is_none());
        let dir = eval("chezmoi apply /home/u/.config", Some(DRIFTED)).expect("dir target");
        assert!(dir.contains("a.toml"), "{dir}");
        // Relative to the cwd (/home/u/src): ../.gitconfig.
        assert!(eval("chezmoi apply ../.gitconfig", Some(DRIFTED)).is_some());
        // An unplaceable target keeps every drifted file in scope.
        assert!(eval("chezmoi apply \"$F\"", Some(DRIFTED)).is_some());
    }

    #[test]
    fn include_and_exclude_that_keep_files_out_are_silent() {
        assert!(eval("chezmoi apply --include=scripts", Some(DRIFTED)).is_none());
        assert!(eval("chezmoi apply -x files", Some(DRIFTED)).is_none());
        let scoped = eval("chezmoi apply --include=files", Some(DRIFTED)).expect("nudge");
        assert!(!scoped.contains("unscoped"), "{scoped}");
    }

    #[test]
    fn relocated_or_dry_run_applies_never_run_status() {
        for cmd in [
            "chezmoi -S /tmp/evil apply",
            "chezmoi apply --source=/tmp/evil",
            "chezmoi --config /tmp/c.toml apply",
            "chezmoi apply -n",
            "chezmoi apply --dry-run",
            "chezmoi -nv apply",
            "chezmoi apply --init",
            "chezmoi apply --source-path src/dot_zshrc",
            "chezmoi apply -P ~/.config/app/a.toml",
            "chezmoi apply --parent-dirs ~/.config/app/a.toml",
            "chezmoi apply -vP ~/.config/app/a.toml",
            "chezmoi apply --interactive",
            "HOME=/tmp/h chezmoi apply",
            "XDG_CONFIG_HOME=/tmp/x chezmoi apply",
            "CHEZMOI_SOURCE_DIR=/tmp/s chezmoi apply",
            "env HOME=/tmp/h chezmoi apply",
        ] {
            let calls = apply_calls(cmd);
            let call = calls.first().expect(cmd);
            assert_eq!(
                evaluate(call, Path::new("/"), &home(), || panic!(
                    "status ran for {cmd}"
                )),
                None,
                "{cmd}"
            );
        }
    }

    #[test]
    fn shown_paths_are_clamped_and_stripped_of_control_characters() {
        let long = "a".repeat(500);
        let status = format!("MM .x\u{1b}[31m`evil`\nMM {long}\n");
        let msg = eval("chezmoi apply", Some(&status)).expect("nudge");
        assert!(!msg.contains('\u{1b}'), "{msg:?}");
        assert!(!msg.contains("`evil`"), "{msg}");
        assert!(msg.contains(&format!("~/{}…", "a".repeat(200))), "{msg}");
        assert!(!msg.contains(&"a".repeat(201)), "{msg}");
    }

    #[test]
    fn only_apply_is_read() {
        for cmd in [
            "chezmoi status",
            "chezmoi diff",
            "chezmoi re-add ~/.zshrc",
            "echo chezmoi apply",
            "git apply x.patch",
        ] {
            assert!(apply_calls(cmd).is_empty(), "{cmd}");
        }
        assert_eq!(apply_calls("cd ~ && chezmoi -v apply ~/.zshrc").len(), 1);
    }
}
