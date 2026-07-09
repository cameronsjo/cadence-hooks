//! guard-rm — path-aware triage of `rm`-family delete commands.
//!
//! Instead of a blanket permission prompt on every recursive delete, guard-rm
//! inspects each command's deletion targets and returns a graduated decision:
//!
//! - **ALLOW** (silent, exit 0) — a target under a temp root (`/tmp`,
//!   `/private/tmp`, `$TMPDIR`) or strictly under a `.claude/` directory
//!   (worktrees, session dirs, scratchpads). The friction removed.
//! - **BLOCK** (exit 2, disclosed message) — `/`, `$HOME`, a first-level home
//!   child, inside `$OBSIDIAN_VAULT`, or a git repo root / any path with a
//!   `.git` component.
//! - **ASK** ([`Outcome::Ask`], the prompt) — an unexpanded variable, a command
//!   substitution, a `..`-bearing path, or anything else not proven safe. This
//!   is the default, so nothing that prompts today stops prompting unless it is
//!   structurally proven safe.
//!
//! **Charter:** a *discipline guard with an allow-granting edge*, not a security
//! boundary. Fails open (ADR-0001). Deliberately NOT in `PROTECTED_GUARDS`, so
//! `CADENCE_DISABLE=guard-rm` may neuter it. The catastrophic floor (built-in
//! circuit breakers + retained settings `deny` rows) bounds the
//! fail-open-plus-allow window.
//!
//! **v1 scope (deferred, not forgotten):** a fourth ALLOW mechanism — a per-repo
//! declared safe-path config (`.claude/rm-exemptions.json`) — was cut from v1 as
//! a Step-0 trim (YAGNI); it returns on a real trigger. v1 ships the three
//! structural ALLOW/BLOCK edges above plus the ASK default.
//!
//! **Scope, by design (documented misses, not holes):**
//! - The leading command word is basename-matched against `rm`/`unlink`/
//!   `shred`/`truncate` (plus `find … -delete`), after transparent prefixes
//!   (`command`/`env`/`VAR=x`/…). So `git rm`, `npm rm`, and a look-alike like
//!   `charm` are correctly *not* deletions.
//! - `sudo rm …` is out of scope: `sudo` is not a transparent prefix here, and
//!   a settings `allow Bash(rm:*)` rule keys on the leading word too, so `sudo`
//!   is consistently outside both. Adding `sudo`-flag parsing would risk a
//!   misread; the miss is intentional.
//! - A `..`-bearing target resolves ambiguously (symlinks, escapes), so it
//!   downgrades to ASK rather than a guessed BLOCK/ALLOW.
//!
//! **Segment-aware parsing:** targets are collected by mirroring
//! `enforce_worktree::collect_commit_targets` — walking `split_segments_with_ops`
//! while tracking the effective cwd through `cd` chains, and recursing into each
//! segment's `child_scripts` (`sh -c '…'` wrappers, `$(…)`/backtick bodies) with
//! a *fresh* cwd scope. It deliberately does **not** flatten via
//! `command_segments`, which would splice a `$(cd /x)` into the parent stream
//! and misjudge a target the shell still deletes in the parent's cwd (issue
//! #228). Rolling no new recursion keeps the adversarially-reviewed primitives
//! the single source of truth.

use crate::enforce_worktree::{skip_transparent_prefixes, strip_group_wrappers};
use cadence_hooks_core::shell::{
    MAX_WRAPPER_DEPTH, basename, child_scripts, resolve_cd_target, split_segments_with_ops,
    tokenize,
};
use cadence_hooks_core::worktree::path_under_temp_root;
use cadence_hooks_core::{Check, CheckResult, HookInput, Outcome, normalize_path};
use std::path::Path;

/// Delete verbs whose leading command word marks a filesystem deletion.
/// Deliberately duplicates `obsidian::trash_guard`'s destructive-verb set (per
/// the plan's reuse ledger: promote when cheap, else duplicate with
/// attribution) — the two guards judge different things (vault membership vs
/// path class), so a shared const would couple them without real reuse.
const DELETE_VERBS: &[&str] = &["rm", "unlink", "shred", "truncate"];

/// Does `flag` (in separate-token form) consume the following token as a value
/// for `verb`? Prevents a `shred -n 3` iteration count or a `truncate -s 0`
/// size from being misread as a path operand (which would resolve to a bogus
/// relative path and force a needless ASK). Glued (`-s0`) and `=`-joined
/// (`--size=0`) forms carry their value in one `-`-prefixed token and are
/// skipped as flags without this table. `rm`/`unlink` have no value flags.
fn takes_value(verb: &str, flag: &str) -> bool {
    match verb {
        "shred" => matches!(
            flag,
            "-n" | "--iterations" | "-s" | "--size" | "--random-source"
        ),
        "truncate" => matches!(flag, "-s" | "--size" | "-r" | "--reference"),
        _ => false,
    }
}

/// Classification of a single resolved deletion target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetClass {
    /// Under a temp root. ALLOW.
    Temp,
    /// Strictly *under* a `.claude/` directory. ALLOW. The `.claude` dir itself
    /// is NOT here — deleting it whole is not the transient-scratch case this
    /// ALLOW exists for, so it falls through to the block/ask rules.
    ClaudeManaged,
    /// The filesystem root `/`. BLOCK.
    Root,
    /// The user's home directory itself. BLOCK.
    Home,
    /// A first-level entry directly under home (`~/Documents`, `~/.zshrc`). BLOCK.
    HomeChild,
    /// Inside the Obsidian vault. BLOCK.
    Vault,
    /// A git repo root (has a `.git` child), or any path with a `.git`
    /// component. BLOCK.
    GitRepo,
    /// Unexpanded variable, command substitution, or a `..`-bearing path that
    /// cannot be confidently resolved. ASK.
    Unresolvable,
    /// The genuine ambiguous middle. ASK (default).
    Unknown,
}

impl TargetClass {
    fn outcome(self) -> Outcome {
        match self {
            TargetClass::Temp | TargetClass::ClaudeManaged => Outcome::Allow,
            TargetClass::Root
            | TargetClass::Home
            | TargetClass::HomeChild
            | TargetClass::Vault
            | TargetClass::GitRepo => Outcome::Block,
            TargetClass::Unresolvable | TargetClass::Unknown => Outcome::Ask,
        }
    }
}

/// Resolved environment context, injected so the decision core stays pure and
/// table-testable (no env reads, no I/O beyond the injected git-root probe and
/// `path_under_temp_root`'s tmpdir canonicalization).
struct RmContext<'a> {
    /// Home directory, normalized (no trailing slash).
    home: &'a str,
    /// Obsidian vault root, normalized, when `OBSIDIAN_VAULT` is set non-empty.
    vault: Option<&'a str>,
    /// `$TMPDIR`, for the temp-root check.
    tmpdir: Option<&'a str>,
}

/// A deletion target extracted from the command, before classification.
enum TargetToken {
    /// A path resolved against the effective cwd (a shell path string).
    Path(String),
    /// An operand that could not be resolved (unexpanded var / substitution /
    /// `..`-bearing). Always ASK.
    Unresolvable,
}

/// Walk one script's segments, collecting every rm-family deletion target,
/// tracking the effective cwd across `cd`s and recursing into child scripts —
/// a direct mirror of `enforce_worktree::collect_commit_targets` (issue #228).
fn collect_targets(script: &str, cwd: &str, depth: usize, out: &mut Vec<TargetToken>) {
    let mut effective_dir = cwd.to_string();

    for (segment, _next_op) in split_segments_with_ops(script) {
        let segment = strip_group_wrappers(&segment);
        let tokens = tokenize(segment);
        let argv = skip_transparent_prefixes(&tokens);

        // Child scripts execute with the directory in effect HERE, in their own
        // scope: a wrapper inherits the accumulated cwd, a substitution runs
        // before its own segment. Recurse rather than flatten so a child's `cd`
        // never leaks back into this script's tracking.
        if depth < MAX_WRAPPER_DEPTH {
            for child in child_scripts(argv, segment) {
                collect_targets(&child, &effective_dir, depth + 1, out);
            }
        }

        // `cd` tracking — assume success (equal-precedence `&&`/`||`,
        // left-assoc), skip cd's own flags, and treat a bare `-`, a `$VAR`, or a
        // missing target as unresolvable (keep the pre-cd dir). Mirrors
        // `collect_commit_targets`.
        if tokens.first().map(String::as_str) == Some("cd") {
            let mut idx = 1;
            while tokens
                .get(idx)
                .is_some_and(|t| t == "--" || (t.starts_with('-') && t != "-"))
            {
                idx += 1;
            }
            if let Some(target) = tokens.get(idx)
                && target != "-"
                && !target.starts_with('$')
            {
                effective_dir = resolve_cd_target(target, &effective_dir);
            }
            continue;
        }

        let Some(first) = argv.first() else { continue };
        // basename so `/bin/rm` matches; strip a leading `\` so the alias-bypass
        // form `\rm` is still seen as `rm`. (Deliberate misses: `xargs rm` —
        // the targets arrive on stdin, unclassifiable, and treating it as an rm
        // with no operand would ALLOW, worse than deferring; and `RM` on a
        // case-insensitive volume — matching case-insensitively would be wrong
        // on Linux. Both are mitigated: a settings `allow Bash(rm:*)` rule keys
        // on the leading word too, so they defer, never silently auto-approve.)
        let verb = basename(first).trim_start_matches('\\');
        if DELETE_VERBS.contains(&verb) {
            for operand in delete_operands(argv, verb) {
                out.push(resolve_target(&operand, &effective_dir));
            }
        } else if verb == "find" && find_is_destructive(argv) {
            // A `find` that deletes — via `-delete`/`-exec`/`-ok` running a
            // delete verb — targets its search roots. When the roots can't be
            // confidently identified (no explicit path, or an unrecognized
            // leading option that might have dropped one), one Unresolvable
            // target → ASK, rather than a silent cwd default.
            match find_roots(argv) {
                FindTargets::Paths(roots) => {
                    for root in roots {
                        out.push(resolve_target(&root, &effective_dir));
                    }
                }
                FindTargets::Unresolvable => out.push(TargetToken::Unresolvable),
            }
        }
    }
}

/// A `find` invocation that deletes: it carries `-delete`, or an
/// `-exec`/`-execdir`/`-ok`/`-okdir` whose command is a delete verb
/// (`find … -exec rm …`). The command word is scanned up to its `;`/`+`
/// terminator, so `-exec /bin/rm …`, `-exec env rm …`, and `-exec \rm …` are
/// caught. `-exec sh -c '…'` hides the delete inside the wrapper script — a
/// documented miss.
fn find_is_destructive(argv: &[String]) -> bool {
    if argv.iter().any(|t| t == "-delete") {
        return true;
    }
    let mut after_exec = false;
    for tok in argv.iter().skip(1) {
        match tok.as_str() {
            "-exec" | "-execdir" | "-ok" | "-okdir" => after_exec = true,
            ";" | "\\;" | "+" => after_exec = false,
            other
                if after_exec
                    && DELETE_VERBS.contains(&basename(other).trim_start_matches('\\')) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

/// Path operands of an `rm`/`unlink`/`shred`/`truncate` invocation: non-flag
/// tokens after the verb, honoring `--` (everything after is a path) and each
/// verb's value-taking flags.
fn delete_operands(argv: &[String], verb: &str) -> Vec<String> {
    let mut operands = Vec::new();
    let mut i = 1;
    let mut after_dd = false;
    while i < argv.len() {
        let tok = &argv[i];
        if !after_dd {
            if tok == "--" {
                after_dd = true;
                i += 1;
                continue;
            }
            // A flag is `-`-prefixed and longer than a bare `-`.
            if tok.starts_with('-') && tok.len() > 1 {
                i += if takes_value(verb, tok) { 2 } else { 1 };
                continue;
            }
        }
        operands.push(tok.clone());
        i += 1;
    }
    operands
}

/// The search-root resolution of a destructive `find`.
enum FindTargets {
    /// Explicit path arguments to classify.
    Paths(Vec<String>),
    /// The roots can't be confidently identified → ASK. Two cases collapse here:
    /// no explicit path (the target is the implicit cwd, but a leading option we
    /// failed to recognize could equally have dropped a real root), and a
    /// leading `-`-token that isn't a known global option.
    Unresolvable,
}

/// Search roots of a `find` invocation: the path arguments between the global
/// options and the first expression token (`-name`, `-delete`, `(`, `!`, …).
///
/// `find`'s global options precede the paths and also start with `-`, so a
/// naive "break on the first `-`" drops the real root on `find -L <path>
/// -delete` and silently defaults it to the cwd — from a `.claude`/`tmp` cwd
/// that is a silent ALLOW of a protected delete. The known GNU ∪ BSD global
/// options are skipped (`-H`/`-L`/`-P`/`-E`/`-X`/`-d`/`-s`/`-x` boolean; `-D`/
/// `-O` valued, separate or glued). Rather than enumerate every `find` variant
/// (fragile — a missed option re-opens the hole), anything else is treated
/// conservatively: **no explicit path found → `Unresolvable` (ASK)**, never a
/// silent cwd default. `-f <path>` (BSD, *adds* a search root) also routes to
/// `Unresolvable` — its value is a real target this simple pass won't fold in.
fn find_roots(argv: &[String]) -> FindTargets {
    const GLOBAL_BOOL: &[&str] = &["-H", "-L", "-P", "-E", "-X", "-d", "-s", "-x"];
    let mut i = 1;
    while let Some(tok) = argv.get(i) {
        let t = tok.as_str();
        if GLOBAL_BOOL.contains(&t) {
            i += 1;
        } else if t == "-D" || t == "-O" {
            i += 2; // separate-token value
        } else if t.starts_with("-D") || t.starts_with("-O") {
            i += 1; // glued value (`-O2`, `-Dtree`)
        } else {
            break;
        }
    }
    // At the first non-global token. A dash here means no explicit path was
    // given (expression start) OR an unrecognized/`-f` option — either way we
    // can't safely name the root, so ASK.
    match argv.get(i) {
        Some(tok) if !(tok.starts_with('-') || tok == "(" || tok == "!") => {
            let mut roots = Vec::new();
            while let Some(tok) = argv.get(i) {
                if tok.starts_with('-') || tok == "(" || tok == "!" {
                    break;
                }
                roots.push(tok.clone());
                i += 1;
            }
            FindTargets::Paths(roots)
        }
        _ => FindTargets::Unresolvable,
    }
}

/// Resolve one operand against the effective cwd, or mark it unresolvable.
fn resolve_target(operand: &str, effective_dir: &str) -> TargetToken {
    // Unexpanded variable / command substitution — can't prove anything.
    if operand.contains('$') || operand.contains('`') {
        return TargetToken::Unresolvable;
    }
    // Reduce a glob to the literal directory it lives in: `rm -rf /tmp/x/*`
    // classifies `/tmp/x`, `rm -rf *` classifies the cwd, `rm -rf /*`
    // classifies `/`.
    let literal = glob_literal_prefix(operand);
    if has_parent_segment(literal) {
        return TargetToken::Unresolvable;
    }
    // A bare glob-less cwd reference (`*` → "", or a literal `.`) is the
    // effective directory itself.
    let resolved = if literal.is_empty() || literal == "." {
        effective_dir.to_string()
    } else {
        resolve_cd_target(literal, effective_dir)
    };
    // The effective dir itself may carry a `..` from a `cd ..` — still ambiguous.
    if has_parent_segment(&resolved) {
        return TargetToken::Unresolvable;
    }
    TargetToken::Path(resolved)
}

/// The literal directory prefix of a (possibly globbed) operand: everything up
/// to the last `/` before the first glob metachar. A glob in the first segment
/// yields `""` (the cwd); a leading-`/` glob (`/*`) yields `/` (the root).
///
/// `[` is treated as a glob metachar unconditionally, though it is also a legal
/// filename character — so a literal `~/Documents/file[1].txt` reduces to
/// `~/Documents` and classifies as the exact home child (Block) rather than the
/// deeper ambiguous path (Ask). The error direction is always *more* restrictive
/// (Block/Ask, never a silent Allow), so it is safe, if occasionally strict.
fn glob_literal_prefix(operand: &str) -> &str {
    let Some(pos) = operand.find(['*', '?', '[']) else {
        return operand;
    };
    match operand[..pos].rfind('/') {
        Some(0) => "/",
        Some(slash) => &operand[..slash],
        None => "",
    }
}

/// True when any `/`-separated segment of `path` is exactly `..`.
fn has_parent_segment(path: &str) -> bool {
    path.split('/').any(|seg| seg == "..")
}

/// Drop bare `.` segments from an already-`normalize_path`'d string, so a
/// non-canonical form like `~/./Documents` still matches the exact classifiers
/// (`HomeChild`, `Vault`, `has_git_component`) rather than slipping to the
/// ambiguous default. `..` never reaches here — `resolve_target` routes it to
/// `Unresolvable` upstream.
fn drop_dot_segments(path: &str) -> String {
    if !path.split('/').any(|s| s == ".") {
        return path.to_string();
    }
    let leading = path.starts_with('/');
    let joined = path
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect::<Vec<_>>()
        .join("/");
    if leading {
        format!("/{joined}")
    } else {
        joined
    }
}

/// Classify a resolved target path. `is_git_root` is injected (the wrapper
/// stats `<target>/.git`; tests stub it) so this stays pure.
///
/// Order is load-bearing: ALLOW rules run **before** BLOCK rules, so a scratch
/// target under a protected ancestor — a git worktree under `.claude`, a repo
/// checked out in `/tmp` — is ALLOW, not blocked as a git repo.
fn classify_path(path: &str, ctx: &RmContext, is_git_root: &dyn Fn(&str) -> bool) -> TargetClass {
    let norm = drop_dot_segments(&normalize_path(path));

    // ALLOW rules first.
    if path_under_temp_root(Path::new(&norm), ctx.tmpdir) {
        return TargetClass::Temp;
    }
    if is_under_claude_managed(&norm) {
        return TargetClass::ClaudeManaged;
    }

    // BLOCK rules. `normalize_path("/")` == "" (trailing slash trimmed), so an
    // empty norm IS the root.
    if norm.is_empty() || norm == "/" {
        return TargetClass::Root;
    }
    if norm == ctx.home {
        return TargetClass::Home;
    }
    if is_first_level_home_child(&norm, ctx.home) {
        return TargetClass::HomeChild;
    }
    if let Some(vault) = ctx.vault
        && (norm == vault || norm.starts_with(&format!("{vault}/")))
    {
        return TargetClass::Vault;
    }
    if has_git_component(&norm) || is_git_root(&norm) {
        return TargetClass::GitRepo;
    }

    TargetClass::Unknown
}

/// `.claude` appears as a path component AND is not the final one — the target
/// lives *under* a `.claude` dir, rather than being it.
fn is_under_claude_managed(path: &str) -> bool {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match segs.iter().position(|s| *s == ".claude") {
        Some(pos) => pos + 1 < segs.len(),
        None => false,
    }
}

/// `path` is a first-level entry directly under `home` (one component below).
fn is_first_level_home_child(path: &str, home: &str) -> bool {
    if home.is_empty() {
        return false;
    }
    let prefix = format!("{home}/");
    path.strip_prefix(&prefix)
        .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
}

/// Any `/`-separated segment of `path` is exactly `.git`.
fn has_git_component(path: &str) -> bool {
    path.split('/').any(|seg| seg == ".git")
}

/// The decision core: collect targets, classify each, and keep the most severe
/// verdict (Block > Ask > Allow). Pure — env and the git-root probe are
/// injected.
fn judge_rm(
    command: &str,
    cwd: &str,
    ctx: &RmContext,
    is_git_root: &dyn Fn(&str) -> bool,
) -> CheckResult {
    let mut targets = Vec::new();
    collect_targets(command, cwd, 0, &mut targets);
    if targets.is_empty() {
        // Not an rm-family deletion, or an rm with no operands — not ours.
        return CheckResult::allow();
    }

    let mut worst = Outcome::Allow;
    let mut block_class: Option<TargetClass> = None;
    for target in &targets {
        let class = match target {
            TargetToken::Unresolvable => TargetClass::Unresolvable,
            TargetToken::Path(p) => classify_path(p, ctx, is_git_root),
        };
        let outcome = class.outcome();
        // Remember the FIRST block-classified target only for message wording.
        // The choice is arbitrary, not an ordering — every BLOCK `TargetClass`
        // shares one `Outcome::Block`, so which one names the message doesn't
        // change the verdict.
        if outcome == Outcome::Block && block_class.is_none() {
            block_class = Some(class);
        }
        worst = worst.merge(outcome);
    }

    match worst {
        Outcome::Block => {
            CheckResult::block(block_message(block_class.unwrap_or(TargetClass::Unknown)))
        }
        Outcome::Ask => CheckResult::ask(ASK_MESSAGE),
        // Allow (and the impossible Nudge/LoopBlock) → defer to normal flow.
        _ => CheckResult::allow(),
    }
}

/// The ASK reason shown in the permission prompt.
const ASK_MESSAGE: &str = "guard-rm: this delete target could not be proven safe (an unexpanded variable, \
     a command substitution, or a path outside recognized temp/scratch roots). \
     Confirm the deletion, or opt out with CADENCE_DISABLE=guard-rm.";

/// The BLOCK message: names the protected location and every escape hatch.
fn block_message(class: TargetClass) -> String {
    let what = match class {
        TargetClass::Root => "the filesystem root `/`",
        TargetClass::Home => "your home directory",
        TargetClass::HomeChild => "a top-level entry in your home directory",
        TargetClass::Vault => "your Obsidian vault",
        TargetClass::GitRepo => "a git repository (a `.git` lives here)",
        _ => "a protected location",
    };
    format!(
        "🚫 guard-rm: this deletes {what}, which is almost never intended.\n   \
         If you're certain, run it in a terminal yourself, or:\n   \
         • CADENCE_DISABLE=guard-rm — opt this guard out (persists in settings)\n   \
         • CADENCE_BYPASS=1 — bypass all cadence enforcement for one session"
    )
}

/// Path-aware triage of `rm`-family delete commands.
pub struct GuardRm;

impl Check for GuardRm {
    fn name(&self) -> &str {
        "guard-rm"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };
        let home = normalize_path(&cadence_hooks_core::paths::user_home_lossy_or_default());
        let vault = std::env::var("OBSIDIAN_VAULT")
            .ok()
            .filter(|v| !v.is_empty())
            .map(|v| normalize_path(&v));
        let tmpdir = std::env::var("TMPDIR").ok();
        let cwd = input.cwd.as_deref().unwrap_or("/");
        let ctx = RmContext {
            home: &home,
            vault: vault.as_deref(),
            tmpdir: tmpdir.as_deref(),
        };
        judge_rm(command, cwd, &ctx, &is_git_root_on_disk)
    }
}

/// Real git-root probe: `<target>/.git` exists (a repo root, or a linked
/// worktree whose `.git` is a *file*). One `stat` per target — no subprocess.
fn is_git_root_on_disk(target: &str) -> bool {
    !target.is_empty() && Path::new(target).join(".git").exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::test_builders::make_bash;

    /// The process home — the SAME value `resolve_cd_target` expands `~` to, so
    /// injected context and `~`-expansion agree (as they do in production, where
    /// both read `user_home_lossy_or_default`). Home-relative test cases use `~`
    /// rather than a hard-coded path so they hold whatever the runner's HOME is.
    fn home() -> String {
        normalize_path(&cadence_hooks_core::paths::user_home_lossy_or_default())
    }

    /// A vault root independent of home and temp (so no ALLOW rule pre-empts it).
    const VAULT: &str = "/vaults/main";

    /// Judge with the real home, a fixed vault, no tmpdir, and a git-root probe
    /// that returns true only for the exact paths in `git_roots`.
    fn judge_with(command: &str, cwd: &str, git_roots: &[&str]) -> Outcome {
        let home = home();
        let ctx = RmContext {
            home: &home,
            vault: Some(VAULT),
            tmpdir: None,
        };
        let probe = |p: &str| git_roots.contains(&p);
        judge_rm(command, cwd, &ctx, &probe).outcome
    }

    /// Common case: no git roots on disk.
    fn judge(command: &str, cwd: &str) -> Outcome {
        judge_with(command, cwd, &[])
    }

    // --- ALLOW: temp roots ---

    #[test]
    fn temp_absolute_allows() {
        assert_eq!(judge("rm -rf /tmp/scratch", "/anywhere"), Outcome::Allow);
        assert_eq!(judge("rm -rf /private/tmp/x", "/anywhere"), Outcome::Allow);
    }

    #[test]
    fn temp_via_cd_chain_allows() {
        assert_eq!(judge("cd /tmp && rm -rf build", "/home"), Outcome::Allow);
    }

    #[test]
    fn temp_glob_allows() {
        assert_eq!(judge("rm -rf /tmp/scratch/*", "/home"), Outcome::Allow);
    }

    #[test]
    fn tmp_lookalike_is_not_temp() {
        // Path::starts_with is component-wise, so `/tmpfoo` is NOT under `/tmp`.
        // Not temp, not protected → the ambiguous middle.
        assert_eq!(judge("rm -rf /tmpfoo/x", "/home"), Outcome::Ask);
    }

    // --- ALLOW: .claude-managed (strictly under) ---

    #[test]
    fn under_claude_worktree_allows() {
        assert_eq!(
            judge("rm -rf /srv/repo/.claude/worktrees/x", "/home"),
            Outcome::Allow
        );
    }

    #[test]
    fn claude_worktree_allows_even_if_git_root() {
        // A worktree's `.git` is a file, so the git-root probe would fire — but
        // the .claude ALLOW is checked first, so worktree cleanup is allowed.
        // Probe returns true for ALL paths to prove the ordering.
        let home = home();
        let ctx = RmContext {
            home: &home,
            vault: Some(VAULT),
            tmpdir: None,
        };
        let out = judge_rm(
            "rm -rf /srv/repo/.claude/worktrees/x",
            "/home",
            &ctx,
            &|_| true,
        )
        .outcome;
        assert_eq!(out, Outcome::Allow);
    }

    #[test]
    fn claude_dir_itself_is_not_allowed() {
        // Deleting `~/.claude` whole is not the transient-scratch case — it is a
        // first-level home child → BLOCK, never a silent ALLOW.
        assert_eq!(judge("rm -rf ~/.claude", "/home"), Outcome::Block);
    }

    // --- BLOCK: root / home / home-child ---

    #[test]
    fn root_blocks() {
        assert_eq!(judge("rm -rf /", "/home"), Outcome::Block);
    }

    #[test]
    fn root_glob_blocks() {
        // `/*` reduces to `/` — must block, not be misread as the cwd.
        assert_eq!(judge("rm -rf /*", "/home"), Outcome::Block);
    }

    #[test]
    fn home_itself_blocks() {
        assert_eq!(judge("rm -rf ~", "/home"), Outcome::Block);
        assert_eq!(
            judge(&format!("rm -rf {}", home()), "/home"),
            Outcome::Block
        );
    }

    #[test]
    fn home_child_blocks() {
        assert_eq!(judge("rm -rf ~/Documents", "/home"), Outcome::Block);
        assert_eq!(judge("rm -rf ~/.zshrc", "/home"), Outcome::Block);
        assert_eq!(judge("rm -rf ~/Desktop", "/home"), Outcome::Block);
    }

    #[test]
    fn deep_home_path_is_not_child() {
        // Only first-level home entries block; deeper paths fall to the middle.
        assert_eq!(judge("rm -rf ~/Documents/notes", "/home"), Outcome::Ask);
    }

    // --- BLOCK: vault ---

    #[test]
    fn vault_root_and_inside_block() {
        assert_eq!(judge("rm -rf /vaults/main", "/home"), Outcome::Block);
        assert_eq!(
            judge("rm -rf /vaults/main/notes/x.md", "/home"),
            Outcome::Block
        );
    }

    #[test]
    fn vault_lookalike_does_not_block() {
        // `/vaults/main-backup` is not the vault.
        assert_eq!(judge("rm -rf /vaults/main-backup/x", "/home"), Outcome::Ask);
    }

    #[test]
    fn no_vault_env_skips_vault_rule() {
        let home = home();
        let ctx = RmContext {
            home: &home,
            vault: None,
            tmpdir: None,
        };
        // The same path is just an unknown middle path with no vault configured.
        let out = judge_rm("rm -rf /vaults/main/x", "/home", &ctx, &|_| false).outcome;
        assert_eq!(out, Outcome::Ask);
    }

    // --- BLOCK: git repos ---

    #[test]
    fn dot_git_component_blocks() {
        assert_eq!(
            judge("rm -rf /Users/cam/proj/repo/.git", "/home"),
            Outcome::Block
        );
        assert_eq!(
            judge("rm -rf /Users/cam/proj/repo/.git/hooks", "/home"),
            Outcome::Block
        );
    }

    #[test]
    fn git_repo_root_via_probe_blocks() {
        assert_eq!(
            judge_with(
                "rm -rf /Users/cam/proj/myrepo",
                "/home",
                &["/Users/cam/proj/myrepo"],
            ),
            Outcome::Block
        );
    }

    // --- ASK: unresolvable ---

    #[test]
    fn unexpanded_var_asks() {
        assert_eq!(judge("rm -rf $BUILD_DIR", "/home"), Outcome::Ask);
        assert_eq!(judge("rm -rf ${OUT}/dist", "/home"), Outcome::Ask);
    }

    #[test]
    fn command_substitution_target_asks() {
        assert_eq!(judge("rm -rf $(mktemp -d)", "/home"), Outcome::Ask);
    }

    #[test]
    fn parent_escaping_path_asks() {
        assert_eq!(judge("rm -rf ../../etc", "/home/user/proj"), Outcome::Ask);
        assert_eq!(judge("rm -rf /tmp/../etc", "/home"), Outcome::Ask);
    }

    #[test]
    fn cd_with_parent_makes_target_ambiguous() {
        assert_eq!(judge("cd ../sibling && rm -rf x", "/a/b/c"), Outcome::Ask);
    }

    // --- ASK: default middle ---

    #[test]
    fn arbitrary_project_path_asks() {
        assert_eq!(judge("rm -rf /opt/app/cache", "/home"), Outcome::Ask);
        assert_eq!(judge("rm -rf build", "/srv/project"), Outcome::Ask);
    }

    // --- most-severe wins across multiple targets ---

    #[test]
    fn mixed_targets_take_most_severe() {
        // temp (ALLOW) + home-child (BLOCK) → BLOCK.
        assert_eq!(judge("rm -rf /tmp/x ~/Documents", "/home"), Outcome::Block);
        // temp (ALLOW) + unresolvable (ASK) → ASK.
        assert_eq!(judge("rm -rf /tmp/x $VAR", "/home"), Outcome::Ask);
        // unresolvable (ASK) + root (BLOCK) → BLOCK.
        assert_eq!(judge("rm -rf $VAR /", "/home"), Outcome::Block);
    }

    // --- non-deletions & look-alikes → ALLOW (nothing to judge) ---

    #[test]
    fn non_rm_commands_allow() {
        assert_eq!(judge("charm install foo", "/home"), Outcome::Allow);
        assert_eq!(
            judge("git rm --cached ~/Documents/x", "/home"),
            Outcome::Allow
        );
        assert_eq!(judge("npm rm left-pad", "/home"), Outcome::Allow);
        assert_eq!(judge("ls -la /", "/home"), Outcome::Allow);
    }

    #[test]
    fn rm_with_no_operands_allows() {
        assert_eq!(judge("rm -rf", "/home"), Outcome::Allow);
        assert_eq!(judge("rm --help", "/home"), Outcome::Allow);
    }

    #[test]
    fn find_without_delete_allows() {
        assert_eq!(
            judge("find /Users/cam/Documents -name '*.tmp'", "/home"),
            Outcome::Allow
        );
    }

    // --- adversarial shapes: wrappers, substitutions, groups, prefixes ---

    #[test]
    fn bash_c_wrapper_sees_inner_rm() {
        assert_eq!(judge("bash -lc 'rm -rf /'", "/home"), Outcome::Block);
        assert_eq!(judge("sh -c 'rm -rf /tmp/x'", "/home"), Outcome::Allow);
    }

    #[test]
    fn substitution_body_sees_inner_rm() {
        assert_eq!(judge("echo $(rm -rf ~)", "/home"), Outcome::Block);
    }

    #[test]
    fn group_wrapper_sees_rm() {
        assert_eq!(judge("(rm -rf /)", "/home"), Outcome::Block);
        assert_eq!(judge("{ rm -rf ~/Desktop; }", "/home"), Outcome::Block);
    }

    #[test]
    fn transparent_prefix_sees_rm() {
        assert_eq!(judge("env FOO=1 rm -rf /", "/home"), Outcome::Block);
        assert_eq!(judge("command rm -rf ~", "/home"), Outcome::Block);
    }

    #[test]
    fn path_qualified_verb_detected() {
        assert_eq!(judge("/bin/rm -rf /", "/home"), Outcome::Block);
        assert_eq!(judge("/usr/bin/unlink ~/.zshrc", "/home"), Outcome::Block);
    }

    #[test]
    fn double_dash_terminator_paths_after_it() {
        // Everything after `--` is a path even if it starts with `-`.
        assert_eq!(judge("rm -rf -- ~/Documents", "/home"), Outcome::Block);
    }

    #[test]
    fn quoted_path_with_spaces_resolved() {
        assert_eq!(
            judge("rm -rf \"/vaults/main/Field Reports\"", "/home"),
            Outcome::Block
        );
    }

    // --- value-flag handling (shred/truncate) ---

    #[test]
    fn shred_value_flag_not_misread_as_target() {
        // `-n 3` must not be read as a path `3`; only /tmp/x is the target.
        assert_eq!(judge("shred -n 3 /tmp/x", "/home"), Outcome::Allow);
    }

    #[test]
    fn truncate_size_flag_not_misread() {
        assert_eq!(judge("truncate -s 0 /tmp/log", "/home"), Outcome::Allow);
        assert_eq!(judge("truncate -s 0 ~/Documents", "/home"), Outcome::Block);
    }

    // --- find -delete targets the search roots ---

    #[test]
    fn find_delete_blocks_protected_root() {
        assert_eq!(
            judge("find ~/Documents -name '*.md' -delete", "/home"),
            Outcome::Block
        );
    }

    #[test]
    fn find_delete_allows_temp_root() {
        assert_eq!(judge("find /tmp/x -delete", "/home"), Outcome::Allow);
    }

    #[test]
    fn find_delete_no_explicit_path_asks() {
        // No explicit path before the expression: the target is the implicit
        // cwd, but a leading option we failed to recognize could equally have
        // dropped a real root — can't tell safely, so ASK (never a silent cwd
        // default that a `.claude`/`tmp` cwd would turn into ALLOW).
        assert_eq!(judge("find -name '*.md' -delete", "/home"), Outcome::Ask);
        assert_eq!(judge("find -delete", "/home"), Outcome::Ask);
    }

    #[test]
    fn find_bsd_global_options_keep_the_root() {
        // macOS ships BSD find: -x/-s/-E/-d/-X are global options too.
        assert_eq!(
            judge("find -x ~/Documents -delete", "/home"),
            Outcome::Block
        );
        assert_eq!(
            judge("find -s ~/Documents -delete", "/home"),
            Outcome::Block
        );
        assert_eq!(
            judge("find -E ~/Documents -delete", "/home"),
            Outcome::Block
        );
    }

    #[test]
    fn find_unknown_leading_option_asks() {
        // An option outside the known GNU∪BSD global set might have dropped the
        // real root → ASK, not a silent cwd default.
        assert_eq!(
            judge("find -zzz ~/Documents -delete", "/home"),
            Outcome::Ask
        );
        // `-f <path>` (BSD, adds a search root) also routes to ASK.
        assert_eq!(judge("find -f ~/Documents -delete", "/home"), Outcome::Ask);
    }

    #[test]
    fn find_ok_and_backslash_exec_detected() {
        // `-ok`/`-okdir` are interactive `-exec`; a `\rm` behind -exec is still rm.
        assert_eq!(
            judge("find ~/Documents -ok rm {} +", "/home"),
            Outcome::Block
        );
        assert_eq!(
            judge("find ~/Documents -exec \\rm -rf {} +", "/home"),
            Outcome::Block
        );
    }

    // --- security-review fixes: find global options, -exec, \rm, dots ---

    #[test]
    fn find_leading_global_option_keeps_the_root() {
        // Sec #1: a leading -L/-H/-P (or -D/-O) must not drop the real root and
        // default to cwd. `find -L ~/Documents -delete` blocks, not allows.
        assert_eq!(
            judge("find -L ~/Documents -name '*.md' -delete", "/home"),
            Outcome::Block
        );
        assert_eq!(
            judge("find -P ~/Documents -delete", "/home"),
            Outcome::Block
        );
        assert_eq!(
            judge("find -O2 ~/Documents -delete", "/home"),
            Outcome::Block
        );
        assert_eq!(
            judge("find -D tree ~/Documents -delete", "/home"),
            Outcome::Block
        );
    }

    #[test]
    fn find_exec_delete_targets_the_root() {
        // Sec #2: `find … -exec rm …` deletes, so the search roots are targets.
        assert_eq!(
            judge("find ~/Documents -name '*.md' -exec rm -rf {} +", "/home"),
            Outcome::Block
        );
        assert_eq!(
            judge("find ~/Documents -execdir /bin/rm {} ;", "/home"),
            Outcome::Block
        );
        assert_eq!(judge("find /tmp/x -exec rm {} +", "/home"), Outcome::Allow);
    }

    #[test]
    fn find_without_exec_delete_still_read_only() {
        // A find whose -exec runs a non-delete command is read-only → Allow.
        assert_eq!(
            judge("find ~/Documents -exec cat {} +", "/home"),
            Outcome::Allow
        );
    }

    #[test]
    fn backslash_rm_alias_bypass_detected() {
        // Sec #3: `\rm` (bypasses a shell alias) is still `rm`.
        assert_eq!(judge("\\rm -rf /", "/home"), Outcome::Block);
    }

    #[test]
    fn dot_segments_do_not_downgrade_block() {
        // Sec #4: a `.` segment must not slip a home child past the exact match.
        assert_eq!(judge("rm -rf ~/./Documents", "/home"), Outcome::Block);
        assert_eq!(judge("rm -rf /vaults/./main/x", "/home"), Outcome::Block);
    }

    #[test]
    fn more_value_flags_not_misread() {
        // Cover the rest of the takes_value table + glued / =-joined forms.
        assert_eq!(
            judge("shred --iterations 3 /tmp/x", "/home"),
            Outcome::Allow
        );
        assert_eq!(
            judge("shred --random-source /dev/urandom /tmp/x", "/home"),
            Outcome::Allow
        );
        assert_eq!(
            judge("truncate -r /tmp/ref /tmp/x", "/home"),
            Outcome::Allow
        );
        // Glued (`-s0`) and =-joined (`--size=0`) carry their own value — the
        // only operand is /tmp/x.
        assert_eq!(judge("truncate -s0 /tmp/x", "/home"), Outcome::Allow);
        assert_eq!(judge("truncate --size=0 /tmp/x", "/home"), Outcome::Allow);
    }

    // --- message content ---

    #[test]
    fn block_message_names_target_and_hatches() {
        let home = home();
        let ctx = RmContext {
            home: &home,
            vault: Some(VAULT),
            tmpdir: None,
        };
        let r = judge_rm("rm -rf /", "/home", &ctx, &|_| false);
        let msg = r.message.expect("block carries a message");
        assert!(msg.contains("filesystem root"));
        assert!(msg.contains("CADENCE_DISABLE=guard-rm"));
        assert!(msg.contains("CADENCE_BYPASS=1"));
    }

    #[test]
    fn ask_carries_reason() {
        let home = home();
        let ctx = RmContext {
            home: &home,
            vault: None,
            tmpdir: None,
        };
        let r = judge_rm("rm -rf $VAR", "/home", &ctx, &|_| false);
        assert_eq!(r.outcome, Outcome::Ask);
        assert!(
            r.message
                .expect("ask carries a reason")
                .contains("guard-rm")
        );
    }

    // --- Check::run plumbing (env-independent assertions) ---

    #[test]
    fn run_allows_non_command_payload() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        assert_eq!(GuardRm.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn run_allows_temp_delete() {
        // `/tmp` is env-independent (the fixed temp-root branch), so this holds
        // regardless of the test runner's HOME/TMPDIR.
        let input = make_bash("rm -rf /tmp/guard-rm-test-scratch");
        assert_eq!(GuardRm.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn run_allows_non_rm() {
        let input = make_bash("charm install something");
        assert_eq!(GuardRm.run(&input).outcome, Outcome::Allow);
    }
}
