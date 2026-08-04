//! AST-based loop analysis for shell commands.
//!
//! Parses shell commands using `brush-parser` and walks the AST to determine
//! whether loops containing `gh` or `git push` commands are safe (all targets
//! explicitly specified and owned) or need blocking.

use brush_parser::ast::{
    Command, CommandPrefixOrSuffixItem, CompoundCommand, CompoundList, CompoundListItem, Pipeline,
    SimpleCommand,
};
use brush_parser::{Parser, ParserOptions, SourceInfo};

/// A command found inside a loop body with its resolved target information.
#[derive(Debug)]
pub struct LoopedCommand {
    /// The command name (e.g., "gh", "git")
    pub name: String,
    /// The explicit repo target, if one was specified via -R/--repo flag
    pub explicit_repo: Option<String>,
    /// Suffix arguments (subcommands, flags) — enables downstream consumers to
    /// distinguish reads from writes without coupling analysis to action lists.
    pub args: Vec<String>,
}

/// Result of analyzing loops in a shell command.
#[derive(Debug)]
pub enum LoopAnalysis {
    /// No loops found in the command.
    NoLoops,
    /// Loops found, all targeted commands have explicit owned targets.
    AllTargetsExplicit(Vec<LoopedCommand>),
    /// Loops found with commands that lack explicit targets.
    MissingTargets(Vec<LoopedCommand>),
    /// Parser failed — caller should fall back to regex detection.
    ParseFailed,
}

/// Parse a shell command and analyze any loops for `gh` commands.
///
/// Returns a `LoopAnalysis` indicating whether loops are safe (all `gh` commands
/// have explicit `-R`/`--repo` flags) or need blocking.
pub fn analyze_gh_loops(command: &str) -> LoopAnalysis {
    let program = match parse_command(command) {
        Some(p) => p,
        None => return LoopAnalysis::ParseFailed,
    };

    let mut looped_commands = Vec::new();
    for complete_cmd in &program.complete_commands {
        collect_gh_in_loops_from_list(complete_cmd, &mut looped_commands);
    }

    if looped_commands.is_empty() {
        return LoopAnalysis::NoLoops;
    }

    if looped_commands.iter().all(|c| c.explicit_repo.is_some()) {
        LoopAnalysis::AllTargetsExplicit(looped_commands)
    } else {
        LoopAnalysis::MissingTargets(looped_commands)
    }
}

/// Result of analyzing chained (non-loop) push commands.
#[derive(Debug)]
pub enum ChainAnalysis {
    /// Zero or one push command — no chain to analyze.
    SingleOrNone,
    /// Multiple pushes, all with the same explicit remote.
    SameRemote(String),
    /// Multiple pushes targeting different remotes.
    DifferentRemotes(Vec<LoopedCommand>),
    /// Multiple pushes but some lack explicit remotes.
    MissingRemotes(Vec<LoopedCommand>),
    /// Parser failed — caller should fall back to counting.
    ParseFailed,
}

/// Parse a shell command and analyze chained `git push` commands outside loops.
///
/// Extracts all top-level (non-looped) `git push` commands from `&&`/`;` chains
/// and determines if they all target the same remote.
pub fn analyze_push_chain(command: &str) -> ChainAnalysis {
    let program = match parse_command(command) {
        Some(p) => p,
        None => return ChainAnalysis::ParseFailed,
    };

    let mut push_commands = Vec::new();
    for complete_cmd in &program.complete_commands {
        collect_top_level_pushes(complete_cmd, &mut push_commands);
    }

    if push_commands.len() <= 1 {
        return ChainAnalysis::SingleOrNone;
    }

    if push_commands.iter().any(|c| c.explicit_repo.is_none()) {
        return ChainAnalysis::MissingRemotes(push_commands);
    }

    let remotes: Vec<&str> = push_commands
        .iter()
        .filter_map(|c| c.explicit_repo.as_deref())
        .collect();

    if remotes.windows(2).all(|w| w[0] == w[1]) {
        ChainAnalysis::SameRemote(remotes[0].to_string())
    } else {
        ChainAnalysis::DifferentRemotes(push_commands)
    }
}

/// Collect `git push` commands from top-level (non-loop) positions in a compound list.
fn collect_top_level_pushes(list: &CompoundList, out: &mut Vec<LoopedCommand>) {
    for item in &list.0 {
        let and_or = &item.0;
        collect_top_level_pushes_from_pipeline(&and_or.first, out);
        for additional in &and_or.additional {
            let pipeline = match additional {
                brush_parser::ast::AndOr::And(p) | brush_parser::ast::AndOr::Or(p) => p,
            };
            collect_top_level_pushes_from_pipeline(pipeline, out);
        }
    }
}

/// Collect `git push` from pipelines, but do NOT recurse into loop bodies.
fn collect_top_level_pushes_from_pipeline(pipeline: &Pipeline, out: &mut Vec<LoopedCommand>) {
    for cmd in &pipeline.seq {
        match cmd {
            Command::Simple(simple) if is_git_push_command(simple) => {
                out.push(LoopedCommand {
                    name: "git push".to_string(),
                    explicit_repo: extract_push_remote(simple),
                    args: suffix_words(simple),
                });
            }
            Command::Compound(compound, _) => {
                // Recurse into brace groups and subshells but NOT loops
                match compound {
                    CompoundCommand::BraceGroup(bg) => {
                        collect_top_level_pushes(&bg.list, out);
                    }
                    CompoundCommand::Subshell(sub) => {
                        collect_top_level_pushes(&sub.list, out);
                    }
                    CompoundCommand::IfClause(if_cmd) => {
                        collect_top_level_pushes(&if_cmd.condition, out);
                        collect_top_level_pushes(&if_cmd.then, out);
                        if let Some(elses) = &if_cmd.elses {
                            for else_clause in elses {
                                if let Some(cond) = &else_clause.condition {
                                    collect_top_level_pushes(cond, out);
                                }
                                collect_top_level_pushes(&else_clause.body, out);
                            }
                        }
                    }
                    // Skip loops — those are handled by analyze_push_loops
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

/// Parse a shell command and analyze any loops for `git push` commands.
pub fn analyze_push_loops(command: &str) -> LoopAnalysis {
    let program = match parse_command(command) {
        Some(p) => p,
        None => return LoopAnalysis::ParseFailed,
    };

    let mut looped_commands = Vec::new();
    for complete_cmd in &program.complete_commands {
        collect_push_in_loops_from_list(complete_cmd, &mut looped_commands);
    }

    if looped_commands.is_empty() {
        return LoopAnalysis::NoLoops;
    }

    if looped_commands.iter().all(|c| c.explicit_repo.is_some()) {
        LoopAnalysis::AllTargetsExplicit(looped_commands)
    } else {
        LoopAnalysis::MissingTargets(looped_commands)
    }
}

/// Check whether any loop body in the command contains a command that could
/// change the shell's working directory.
///
/// Returns `None` when the command cannot be parsed, `Some(true)` when any
/// loop body contains a cwd mutator (`cd`, `pushd`, `popd`) or a construct
/// that could hide one (`eval`, `source`, `.`, `command`, `builtin`,
/// unrecognized compound commands), and `Some(false)` otherwise.
///
/// Guards use this to decide whether commands inside a loop provably execute
/// in the directory the hook resolved — the precondition for trusting
/// cwd-based git resolution for looped writes.
pub fn loop_bodies_mutate_cwd(command: &str) -> Option<bool> {
    let program = parse_command(command)?;
    let mut found = false;
    for complete_cmd in &program.complete_commands {
        find_loops_in_list(complete_cmd, &mut found);
    }
    Some(found)
}

/// Walk a compound list looking for loops; check each loop body for cwd mutators.
fn find_loops_in_list(list: &CompoundList, found: &mut bool) {
    for item in &list.0 {
        let and_or = &item.0;
        find_loops_in_pipeline(&and_or.first, found);
        for additional in &and_or.additional {
            let pipeline = match additional {
                brush_parser::ast::AndOr::And(p) | brush_parser::ast::AndOr::Or(p) => p,
            };
            find_loops_in_pipeline(pipeline, found);
        }
    }
}

fn find_loops_in_pipeline(pipeline: &Pipeline, found: &mut bool) {
    for cmd in &pipeline.seq {
        if let Command::Compound(compound, _) = cmd {
            match compound {
                CompoundCommand::ForClause(for_cmd) => {
                    body_walk(&for_cmd.body.list, found);
                }
                CompoundCommand::WhileClause(while_cmd) => {
                    body_walk(&while_cmd.1.list, found);
                }
                CompoundCommand::UntilClause(until_cmd) => {
                    body_walk(&until_cmd.1.list, found);
                }
                // Not loop bodies — keep looking for loops inside them
                CompoundCommand::BraceGroup(bg) => find_loops_in_list(&bg.list, found),
                CompoundCommand::Subshell(sub) => find_loops_in_list(&sub.list, found),
                CompoundCommand::IfClause(if_cmd) => {
                    find_loops_in_list(&if_cmd.condition, found);
                    find_loops_in_list(&if_cmd.then, found);
                    if let Some(elses) = &if_cmd.elses {
                        for else_clause in elses {
                            if let Some(cond) = &else_clause.condition {
                                find_loops_in_list(cond, found);
                            }
                            find_loops_in_list(&else_clause.body, found);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Names of commands that change — or can hide a change of — the shell's cwd.
fn is_cwd_mutator(cmd: &SimpleCommand) -> bool {
    const MUTATORS: &[&str] = &[
        "cd", "pushd", "popd", "eval", "source", ".", "command", "builtin",
    ];
    cmd.word_or_name
        .as_ref()
        .is_some_and(|w| MUTATORS.contains(&w.value.as_str()))
}

/// Recursively check every command inside a loop body for cwd mutators.
///
/// Unlike the gh/push collectors, this walk is **conservative**: constructs it
/// cannot see inside (case clauses, function definitions, arithmetic
/// commands) flag as mutating, because a missed `cd` would wrongly extend
/// cwd-based trust to a loop whose iterations run elsewhere.
fn body_walk(list: &CompoundList, found: &mut bool) {
    for item in &list.0 {
        let and_or = &item.0;
        body_walk_pipeline(&and_or.first, found);
        for additional in &and_or.additional {
            let pipeline = match additional {
                brush_parser::ast::AndOr::And(p) | brush_parser::ast::AndOr::Or(p) => p,
            };
            body_walk_pipeline(pipeline, found);
        }
    }
}

fn body_walk_pipeline(pipeline: &Pipeline, found: &mut bool) {
    for cmd in &pipeline.seq {
        match cmd {
            Command::Simple(simple) => {
                if is_cwd_mutator(simple) {
                    *found = true;
                }
            }
            Command::Compound(compound, _) => match compound {
                CompoundCommand::ForClause(fc) => body_walk(&fc.body.list, found),
                CompoundCommand::WhileClause(wc) => body_walk(&wc.1.list, found),
                CompoundCommand::UntilClause(uc) => body_walk(&uc.1.list, found),
                CompoundCommand::BraceGroup(bg) => body_walk(&bg.list, found),
                CompoundCommand::Subshell(sub) => body_walk(&sub.list, found),
                CompoundCommand::IfClause(if_cmd) => {
                    body_walk(&if_cmd.condition, found);
                    body_walk(&if_cmd.then, found);
                    if let Some(elses) = &if_cmd.elses {
                        for else_clause in elses {
                            if let Some(cond) = &else_clause.condition {
                                body_walk(cond, found);
                            }
                            body_walk(&else_clause.body, found);
                        }
                    }
                }
                // Constructs we can't see inside — conservative
                _ => *found = true,
            },
            // Function definitions and other command forms — conservative
            _ => *found = true,
        }
    }
}

fn parse_command(command: &str) -> Option<brush_parser::ast::Program> {
    let reader = std::io::Cursor::new(command);
    let options = ParserOptions::default();
    let source_info = SourceInfo::default();
    let mut parser = Parser::new(reader, &options, &source_info);
    parser.parse_program().ok()
}

// --- gh loop analysis ---

fn collect_gh_in_loops_from_list(list: &CompoundList, out: &mut Vec<LoopedCommand>) {
    for item in &list.0 {
        collect_gh_in_loops_from_item(item, out);
    }
}

fn collect_gh_in_loops_from_item(item: &CompoundListItem, out: &mut Vec<LoopedCommand>) {
    let and_or = &item.0;
    collect_gh_in_loops_from_pipeline(&and_or.first, out);
    for additional in &and_or.additional {
        let pipeline = match additional {
            brush_parser::ast::AndOr::And(p) | brush_parser::ast::AndOr::Or(p) => p,
        };
        collect_gh_in_loops_from_pipeline(pipeline, out);
    }
}

fn collect_gh_in_loops_from_pipeline(pipeline: &Pipeline, out: &mut Vec<LoopedCommand>) {
    for cmd in &pipeline.seq {
        if let Command::Compound(compound, _) = cmd {
            match compound {
                CompoundCommand::ForClause(for_cmd) => {
                    collect_gh_from_body(&for_cmd.body.list, out);
                }
                CompoundCommand::WhileClause(while_cmd) => {
                    collect_gh_from_body(&while_cmd.1.list, out);
                }
                CompoundCommand::UntilClause(until_cmd) => {
                    collect_gh_from_body(&until_cmd.1.list, out);
                }
                // Recurse into brace groups and subshells
                CompoundCommand::BraceGroup(bg) => {
                    collect_gh_in_loops_from_list(&bg.list, out);
                }
                CompoundCommand::Subshell(sub) => {
                    collect_gh_in_loops_from_list(&sub.list, out);
                }
                CompoundCommand::IfClause(if_cmd) => {
                    collect_gh_in_loops_from_list(&if_cmd.condition, out);
                    collect_gh_in_loops_from_list(&if_cmd.then, out);
                    if let Some(elses) = &if_cmd.elses {
                        for else_clause in elses {
                            if let Some(cond) = &else_clause.condition {
                                collect_gh_in_loops_from_list(cond, out);
                            }
                            collect_gh_in_loops_from_list(&else_clause.body, out);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Collect all `gh` commands from a loop body.
fn collect_gh_from_body(body: &CompoundList, out: &mut Vec<LoopedCommand>) {
    for item in &body.0 {
        collect_gh_from_and_or_item(item, out);
    }
}

fn collect_gh_from_and_or_item(item: &CompoundListItem, out: &mut Vec<LoopedCommand>) {
    let and_or = &item.0;
    collect_gh_from_pipeline(&and_or.first, out);
    for additional in &and_or.additional {
        let pipeline = match additional {
            brush_parser::ast::AndOr::And(p) | brush_parser::ast::AndOr::Or(p) => p,
        };
        collect_gh_from_pipeline(pipeline, out);
    }
}

fn collect_gh_from_pipeline(pipeline: &Pipeline, out: &mut Vec<LoopedCommand>) {
    for cmd in &pipeline.seq {
        match cmd {
            Command::Simple(simple) if is_gh_command(simple) => {
                out.push(LoopedCommand {
                    name: "gh".to_string(),
                    explicit_repo: extract_repo_flag(simple),
                    args: suffix_words(simple),
                });
            }
            Command::Compound(compound, _) => {
                // Recurse into nested compounds (nested loops, brace groups, etc.)
                match compound {
                    CompoundCommand::ForClause(for_cmd) => {
                        collect_gh_from_body(&for_cmd.body.list, out);
                    }
                    CompoundCommand::WhileClause(while_cmd) => {
                        collect_gh_from_body(&while_cmd.1.list, out);
                    }
                    CompoundCommand::UntilClause(until_cmd) => {
                        collect_gh_from_body(&until_cmd.1.list, out);
                    }
                    CompoundCommand::BraceGroup(bg) => {
                        collect_gh_from_body(&bg.list, out);
                    }
                    CompoundCommand::Subshell(sub) => {
                        collect_gh_from_body(&sub.list, out);
                    }
                    CompoundCommand::IfClause(if_cmd) => {
                        collect_gh_from_body(&if_cmd.condition, out);
                        collect_gh_from_body(&if_cmd.then, out);
                        if let Some(elses) = &if_cmd.elses {
                            for else_clause in elses {
                                if let Some(cond) = &else_clause.condition {
                                    collect_gh_from_body(cond, out);
                                }
                                collect_gh_from_body(&else_clause.body, out);
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

// --- git push loop analysis ---

fn collect_push_in_loops_from_list(list: &CompoundList, out: &mut Vec<LoopedCommand>) {
    for item in &list.0 {
        let and_or = &item.0;
        collect_push_in_loops_from_pipeline(&and_or.first, out);
        for additional in &and_or.additional {
            let pipeline = match additional {
                brush_parser::ast::AndOr::And(p) | brush_parser::ast::AndOr::Or(p) => p,
            };
            collect_push_in_loops_from_pipeline(pipeline, out);
        }
    }
}

fn collect_push_in_loops_from_pipeline(pipeline: &Pipeline, out: &mut Vec<LoopedCommand>) {
    for cmd in &pipeline.seq {
        if let Command::Compound(compound, _) = cmd {
            match compound {
                CompoundCommand::ForClause(for_cmd) => {
                    collect_push_from_body(&for_cmd.body.list, out);
                }
                CompoundCommand::WhileClause(while_cmd) => {
                    collect_push_from_body(&while_cmd.1.list, out);
                }
                CompoundCommand::UntilClause(until_cmd) => {
                    collect_push_from_body(&until_cmd.1.list, out);
                }
                CompoundCommand::BraceGroup(bg) => {
                    collect_push_in_loops_from_list(&bg.list, out);
                }
                CompoundCommand::Subshell(sub) => {
                    collect_push_in_loops_from_list(&sub.list, out);
                }
                CompoundCommand::IfClause(if_cmd) => {
                    collect_push_in_loops_from_list(&if_cmd.condition, out);
                    collect_push_in_loops_from_list(&if_cmd.then, out);
                    if let Some(elses) = &if_cmd.elses {
                        for else_clause in elses {
                            if let Some(cond) = &else_clause.condition {
                                collect_push_in_loops_from_list(cond, out);
                            }
                            collect_push_in_loops_from_list(&else_clause.body, out);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

fn collect_push_from_body(body: &CompoundList, out: &mut Vec<LoopedCommand>) {
    for item in &body.0 {
        let and_or = &item.0;
        collect_push_from_pipeline(&and_or.first, out);
        for additional in &and_or.additional {
            let pipeline = match additional {
                brush_parser::ast::AndOr::And(p) | brush_parser::ast::AndOr::Or(p) => p,
            };
            collect_push_from_pipeline(pipeline, out);
        }
    }
}

fn collect_push_from_pipeline(pipeline: &Pipeline, out: &mut Vec<LoopedCommand>) {
    for cmd in &pipeline.seq {
        match cmd {
            Command::Simple(simple) if is_git_push_command(simple) => {
                out.push(LoopedCommand {
                    name: "git push".to_string(),
                    explicit_repo: extract_push_remote(simple),
                    args: suffix_words(simple),
                });
            }
            Command::Compound(compound, _) => match compound {
                CompoundCommand::ForClause(for_cmd) => {
                    collect_push_from_body(&for_cmd.body.list, out);
                }
                CompoundCommand::WhileClause(while_cmd) => {
                    collect_push_from_body(&while_cmd.1.list, out);
                }
                CompoundCommand::UntilClause(until_cmd) => {
                    collect_push_from_body(&until_cmd.1.list, out);
                }
                CompoundCommand::BraceGroup(bg) => {
                    collect_push_from_body(&bg.list, out);
                }
                CompoundCommand::Subshell(sub) => {
                    collect_push_from_body(&sub.list, out);
                }
                CompoundCommand::IfClause(if_cmd) => {
                    collect_push_from_body(&if_cmd.condition, out);
                    collect_push_from_body(&if_cmd.then, out);
                    if let Some(elses) = &if_cmd.elses {
                        for else_clause in elses {
                            if let Some(cond) = &else_clause.condition {
                                collect_push_from_body(cond, out);
                            }
                            collect_push_from_body(&else_clause.body, out);
                        }
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
}

// --- Command identification helpers ---

fn is_gh_command(cmd: &SimpleCommand) -> bool {
    cmd.word_or_name.as_ref().is_some_and(|w| w.value == "gh")
}

fn is_git_push_command(cmd: &SimpleCommand) -> bool {
    let Some(name) = &cmd.word_or_name else {
        return false;
    };
    if name.value != "git" {
        return false;
    }
    // Check first suffix word is "push"
    suffix_words(cmd).first().is_some_and(|w| w == "push")
}

/// Extract `-R` or `--repo` flag value from a `gh` command's arguments.
///
/// Later readings win, which is what pflag does. The scan stops at `--`:
/// cobra stops parsing flags there and treats every later token as positional,
/// so a `-R` after it is an argument gh never reads as a repo. Scanning past it
/// made this resolve a repository gh will not act on — and in the
/// `-R evil/b -- -R owned/a` orientation that error points at ALLOW, leaving
/// the block to `guard_gh_write::repo_flag`'s fail-closed backstop.
fn extract_repo_flag(cmd: &SimpleCommand) -> Option<String> {
    let words = suffix_words(cmd);
    let mut result = None;
    let mut index = 0;
    while index < words.len() {
        let word = &words[index];
        if word == "--" {
            break;
        }
        if (word == "-R" || word == "--repo")
            && let Some(value) = words.get(index + 1)
        {
            result = Some(value.clone());
            index += 2;
            continue;
        }
        // Handle -Rowner/repo (no space)
        if let Some(repo) = word.strip_prefix("-R").filter(|r| !r.is_empty()) {
            result = Some(repo.to_string());
        }
        if let Some(repo) = word.strip_prefix("--repo=") {
            result = Some(repo.to_string());
        }
        index += 1;
    }
    result
}

/// Extract the explicit remote name from `git push <remote>` arguments.
///
/// The option grammar itself lives in [`crate::shell::push_repository_argument`]
/// — the single model shared with `guard_push_remote::extract_push_target`.
/// Keeping a second copy here is what let the two functions disagree about what
/// a remote is: this one modelled the short-option cluster walk and missed the
/// three separate-value long options, while the other modelled no grammar at all
/// (cadence-hooks#550).
///
/// Consuming option values rather than returning them matters because a value is
/// often assignment-shaped (Gerrit's `-o topic=…`, `-o r=…`), which the parser
/// hands back as an `AssignmentWord`; left unconsumed it poses as the positional
/// remote, and the caller then judges a remote git never pushes to. This has no
/// backstop — `guard-push-remote` consumes the answer directly on both its chain
/// gate and its loop gate.
fn extract_push_remote(cmd: &SimpleCommand) -> Option<String> {
    let words = suffix_words(cmd);
    let start = words.iter().position(|word| word == "push")? + 1;
    // **Positional only — deliberately NOT `--repo`.** These structural gates
    // ask "did this command name a remote explicitly", and answering yes for a
    // `--repo`-only push turned a hard block into a silent allow: it promoted
    // `MissingTargets`/`MissingRemotes` (which block before any owner logic)
    // into `AllTargetsExplicit`, whose per-iteration check looks the value up as
    // a remote NAME, fails, and skips fail-open. Two independent reviews caught
    // the same transition. `--repo`'s value is still ownership-validated — by
    // `guard_push_remote`'s own destination arm, where the URL/name distinction
    // is actually made.
    crate::shell::push_repository_argument(&words[start..]).positional
}

/// Extract word values from a command's suffix.
fn suffix_words(cmd: &SimpleCommand) -> Vec<String> {
    let Some(suffix) = &cmd.suffix else {
        return Vec::new();
    };
    suffix
        .0
        .iter()
        .filter_map(|item| match item {
            CommandPrefixOrSuffixItem::Word(w) => Some(w.value.clone()),
            CommandPrefixOrSuffixItem::AssignmentWord(_, w) => Some(w.value.clone()),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- analyze_gh_loops ---

    #[test]
    fn no_loop_returns_no_loops() {
        let result = analyze_gh_loops("gh pr create --title test");
        assert!(matches!(result, LoopAnalysis::NoLoops));
    }

    #[test]
    fn for_loop_with_explicit_repo_is_safe() {
        let result = analyze_gh_loops(
            "for label in bug feat; do gh label create $label -R cameronsjo/repo; done",
        );
        match result {
            LoopAnalysis::AllTargetsExplicit(cmds) => {
                assert_eq!(cmds.len(), 1);
                assert_eq!(cmds[0].explicit_repo.as_deref(), Some("cameronsjo/repo"));
            }
            other => panic!("expected AllTargetsExplicit, got {other:?}"),
        }
    }

    #[test]
    fn for_loop_without_repo_flag_is_unsafe() {
        let result = analyze_gh_loops("for repo in a b; do gh pr create; done");
        assert!(matches!(result, LoopAnalysis::MissingTargets(_)));
    }

    #[test]
    fn while_loop_with_gh_is_detected() {
        let result =
            analyze_gh_loops("while read -r issue; do gh issue close $issue; done < issues.txt");
        assert!(matches!(result, LoopAnalysis::MissingTargets(_)));
    }

    #[test]
    fn pipe_to_python_loop_not_a_gh_loop() {
        // The "for" is inside python, not a shell loop containing gh
        let result = analyze_gh_loops(
            "gh api repos/owner/repo/issues | python3 -c \"import json,sys; [print(i['number']) for i in json.load(sys.stdin)]\"",
        );
        assert!(matches!(result, LoopAnalysis::NoLoops));
    }

    #[test]
    fn for_loop_with_repo_flag_long_form() {
        let result = analyze_gh_loops(
            "for i in 1 2 3; do gh issue comment $i --repo cameronsjo/test --body 'done'; done",
        );
        match result {
            LoopAnalysis::AllTargetsExplicit(cmds) => {
                assert_eq!(cmds[0].explicit_repo.as_deref(), Some("cameronsjo/test"));
            }
            other => panic!("expected AllTargetsExplicit, got {other:?}"),
        }
    }

    #[test]
    fn mixed_loop_some_with_some_without_repo() {
        // Two gh commands in one loop body — one with -R, one without
        let result = analyze_gh_loops(
            "for i in 1 2; do gh issue close $i -R cameronsjo/repo && gh pr create; done",
        );
        assert!(matches!(result, LoopAnalysis::MissingTargets(_)));
    }

    #[test]
    fn no_gh_in_loop_body() {
        let result = analyze_gh_loops("for f in *.txt; do echo $f; done");
        assert!(matches!(result, LoopAnalysis::NoLoops));
    }

    #[test]
    fn nested_loop_detects_gh() {
        let result = analyze_gh_loops(
            "for repo in a b; do for label in bug feat; do gh label create $label; done; done",
        );
        assert!(matches!(result, LoopAnalysis::MissingTargets(_)));
    }

    // --- loop_bodies_mutate_cwd ---

    #[test]
    fn plain_loop_body_does_not_mutate_cwd() {
        assert_eq!(
            loop_bodies_mutate_cwd("for i in 1 2 3; do gh issue close $i; done"),
            Some(false)
        );
    }

    #[test]
    fn cd_before_loop_does_not_count() {
        // cd outside the loop body is handled by parse_work_dir — only
        // per-iteration mutation matters here.
        assert_eq!(
            loop_bodies_mutate_cwd("cd /repo && for i in 1 2; do gh issue close $i; done"),
            Some(false)
        );
    }

    #[test]
    fn cd_in_loop_body_mutates() {
        assert_eq!(
            loop_bodies_mutate_cwd("for d in a b; do cd $d && gh pr create; done"),
            Some(true)
        );
    }

    #[test]
    fn subshell_cd_in_loop_body_mutates() {
        assert_eq!(
            loop_bodies_mutate_cwd("for d in a b; do (cd $d && gh pr create); done"),
            Some(true)
        );
    }

    #[test]
    fn pushd_in_loop_body_mutates() {
        assert_eq!(
            loop_bodies_mutate_cwd("for d in a b; do pushd $d; gh pr create; popd; done"),
            Some(true)
        );
    }

    #[test]
    fn eval_in_loop_body_mutates_conservatively() {
        assert_eq!(
            loop_bodies_mutate_cwd("for i in 1 2; do eval \"$CMD\" && gh pr create; done"),
            Some(true)
        );
    }

    #[test]
    fn while_loop_with_cd_mutates() {
        assert_eq!(
            loop_bodies_mutate_cwd("while read -r d; do cd $d && gh pr create; done < dirs.txt"),
            Some(true)
        );
    }

    #[test]
    fn nested_loop_inner_cd_mutates() {
        assert_eq!(
            loop_bodies_mutate_cwd(
                "for a in 1; do for b in 2; do cd /tmp && gh pr create; done; done"
            ),
            Some(true)
        );
    }

    #[test]
    fn no_loops_returns_false() {
        assert_eq!(loop_bodies_mutate_cwd("gh pr create"), Some(false));
    }

    #[test]
    fn echo_and_gh_in_loop_body_does_not_mutate() {
        assert_eq!(
            loop_bodies_mutate_cwd("for i in 1 2; do echo start && gh issue close $i; done"),
            Some(false)
        );
    }

    // --- analyze_push_loops ---

    #[test]
    fn no_loop_push_returns_no_loops() {
        let result = analyze_push_loops("git push origin main");
        assert!(matches!(result, LoopAnalysis::NoLoops));
    }

    #[test]
    fn for_loop_push_with_explicit_remote() {
        let result =
            analyze_push_loops("for branch in feat1 feat2; do git push origin $branch; done");
        match result {
            LoopAnalysis::AllTargetsExplicit(cmds) => {
                assert_eq!(cmds[0].explicit_repo.as_deref(), Some("origin"));
            }
            other => panic!("expected AllTargetsExplicit, got {other:?}"),
        }
    }

    #[test]
    fn for_loop_push_without_remote() {
        let result = analyze_push_loops("for branch in feat1 feat2; do git push; done");
        assert!(matches!(result, LoopAnalysis::MissingTargets(_)));
    }

    // --- repo flag extraction ---

    #[test]
    fn repo_flag_no_space() {
        let result =
            analyze_gh_loops("for i in 1 2; do gh label create bug -Rcameronsjo/repo; done");
        match result {
            LoopAnalysis::AllTargetsExplicit(cmds) => {
                assert_eq!(cmds[0].explicit_repo.as_deref(), Some("cameronsjo/repo"));
            }
            other => panic!("expected AllTargetsExplicit, got {other:?}"),
        }
    }

    #[test]
    fn repo_flag_equals_form() {
        let result =
            analyze_gh_loops("for i in 1 2; do gh issue close $i --repo=cameronsjo/repo; done");
        match result {
            LoopAnalysis::AllTargetsExplicit(cmds) => {
                assert_eq!(cmds[0].explicit_repo.as_deref(), Some("cameronsjo/repo"));
            }
            other => panic!("expected AllTargetsExplicit, got {other:?}"),
        }
    }

    // --- adversarial: nested and complex structures ---

    #[test]
    fn nested_for_loops_with_inner_target() {
        let result = analyze_gh_loops(
            "for repo in a b; do for label in bug feat; do gh label create $label -R $repo; done; done",
        );
        match result {
            LoopAnalysis::AllTargetsExplicit(cmds) => {
                assert_eq!(cmds.len(), 1);
            }
            other => panic!("expected AllTargetsExplicit, got {other:?}"),
        }
    }

    #[test]
    fn last_repo_flag_wins_across_all_four_spellings() {
        for (flags, expected) in [
            ("-R first/a --repo second/b", "second/b"),
            ("--repo first/a -Rsecond/b", "second/b"),
            ("--repo=first/a -R second/b", "second/b"),
            ("-Rfirst/a --repo=second/b", "second/b"),
        ] {
            let command = format!("for i in 1 2; do gh issue close $i {flags}; done");
            match analyze_gh_loops(&command) {
                LoopAnalysis::AllTargetsExplicit(cmds) => {
                    assert_eq!(cmds[0].explicit_repo.as_deref(), Some(expected), "{flags}");
                }
                other => panic!("expected AllTargetsExplicit for {flags}, got {other:?}"),
            }
        }
    }

    #[test]
    fn repo_flag_value_is_not_reparsed_as_another_flag() {
        let result = analyze_gh_loops(
            "for i in 1 2; do gh issue close $i -R --repo=first/value -Rfinal/target; done",
        );
        match result {
            LoopAnalysis::AllTargetsExplicit(cmds) => {
                assert_eq!(cmds[0].explicit_repo.as_deref(), Some("final/target"));
            }
            other => panic!("expected AllTargetsExplicit, got {other:?}"),
        }
    }

    #[test]
    fn loop_suffix_preserves_assignment_shaped_api_fields() {
        let result = analyze_gh_loops("for i in 1 2; do gh api graphql -f query=mutation{x}; done");
        match result {
            LoopAnalysis::MissingTargets(cmds) => {
                assert!(
                    cmds[0].args.contains(&"query=mutation{x}".to_string()),
                    "assignment-shaped field was dropped: {:?}",
                    cmds[0].args
                );
            }
            other => panic!("expected MissingTargets, got {other:?}"),
        }

        let result = analyze_gh_loops("for i in 1 2; do gh api orgs/acme/repos -f name=x; done");
        match result {
            LoopAnalysis::MissingTargets(cmds) => {
                assert!(cmds[0].args.contains(&"name=x".to_string()));
            }
            other => panic!("expected MissingTargets, got {other:?}"),
        }
    }

    #[test]
    fn until_loop_with_gh() {
        let result = analyze_gh_loops("until false; do gh issue list; done");
        assert!(matches!(result, LoopAnalysis::MissingTargets(_)));
    }

    #[test]
    fn subshell_inside_loop() {
        let result = analyze_gh_loops("for i in 1 2; do (gh pr create --title test); done");
        assert!(matches!(result, LoopAnalysis::MissingTargets(_)));
    }

    #[test]
    fn brace_group_inside_loop() {
        let result = analyze_gh_loops("for i in 1 2; do { gh pr create --title test; }; done");
        assert!(matches!(result, LoopAnalysis::MissingTargets(_)));
    }

    #[test]
    fn mixed_explicit_implicit_targets() {
        let result = analyze_gh_loops(
            "for i in 1 2; do gh issue close $i -R cameronsjo/repo && gh pr create; done",
        );
        assert!(matches!(result, LoopAnalysis::MissingTargets(_)));
    }

    #[test]
    fn empty_command_no_loops() {
        let result = analyze_gh_loops("");
        assert!(matches!(result, LoopAnalysis::NoLoops));
    }

    #[test]
    fn three_deep_nesting() {
        let result = analyze_gh_loops(
            "for a in 1; do for b in 2; do for c in 3; do gh issue comment $c; done; done; done",
        );
        assert!(matches!(result, LoopAnalysis::MissingTargets(_)));
    }

    #[test]
    fn pipe_chain_in_loop() {
        let result = analyze_gh_loops("for r in a b; do gh issue list -R $r | head -5; done");
        // gh issue list is not a write but is detected inside loop
        match result {
            LoopAnalysis::AllTargetsExplicit(cmds) => {
                assert_eq!(cmds.len(), 1);
            }
            other => panic!("expected AllTargetsExplicit, got {other:?}"),
        }
    }

    #[test]
    fn and_chain_in_loop() {
        let result = analyze_gh_loops("for i in 1 2; do echo start && gh pr close $i; done");
        assert!(matches!(result, LoopAnalysis::MissingTargets(_)));
    }

    #[test]
    fn or_chain_in_loop() {
        let result = analyze_gh_loops("for i in 1 2; do gh pr close $i || echo failed; done");
        assert!(matches!(result, LoopAnalysis::MissingTargets(_)));
    }

    // --- adversarial: push loop variants ---

    #[test]
    fn push_with_flags_in_loop() {
        let result =
            analyze_push_loops("for b in feat1 feat2; do git push --force origin $b; done");
        match result {
            LoopAnalysis::AllTargetsExplicit(cmds) => {
                assert_eq!(cmds[0].explicit_repo.as_deref(), Some("origin"));
            }
            other => panic!("expected AllTargetsExplicit, got {other:?}"),
        }
    }

    #[test]
    fn push_option_value_cannot_pose_as_remote() {
        for option in [
            "-o ci.skip=1",
            "-oci.skip=1",
            "--push-option ci.skip=1",
            "--push-option=ci.skip=1",
        ] {
            let command = format!("for b in feat1 feat2; do git push {option} origin $b; done");
            match analyze_push_loops(&command) {
                LoopAnalysis::AllTargetsExplicit(cmds) => {
                    assert_eq!(cmds[0].explicit_repo.as_deref(), Some("origin"), "{option}");
                }
                other => panic!("expected AllTargetsExplicit for {option}, got {other:?}"),
            }
        }

        assert!(matches!(
            analyze_push_loops("for b in feat1 feat2; do git push -o ci.skip=1; done"),
            LoopAnalysis::MissingTargets(_)
        ));
    }

    /// git walks a single-dash token letter by letter, so `-o` clustered behind
    /// a boolean still takes the next word as its push-option value. All
    /// spellings verified against git 2.55.0.
    #[test]
    fn clustered_push_option_value_cannot_pose_as_remote() {
        for option in [
            "-qo topic=x",   // `o` last: value is the next word
            "-fo topic=x",   //
            "-uo topic=x",   //
            "-qov",          // `o` mid-cluster: value is the rest of the token
            "-4o topic=x",   // a non-alphabetic boolean shorthand
            "-qo ci.skip=1", // a non-assignment-shaped value, clustered
        ] {
            let command = format!("for b in feat1 feat2; do git push {option} origin $b; done");
            match analyze_push_loops(&command) {
                LoopAnalysis::AllTargetsExplicit(cmds) => {
                    assert_eq!(cmds[0].explicit_repo.as_deref(), Some("origin"), "{option}");
                }
                other => panic!("expected AllTargetsExplicit for {option}, got {other:?}"),
            }
        }
    }

    /// When `o` is NOT the last letter of the cluster it consumes the REST of
    /// the token, so the following word really is the positional remote.
    /// `git push -oq topic=x /nonexistent/repo main` reports an invalid refspec
    /// `/nonexistent/repo` on git 2.55.0 — proving `topic=x` was the repository.
    #[test]
    fn push_option_glued_into_cluster_leaves_next_word_as_remote() {
        for option in ["-oq", "-oo", "-ooq"] {
            let command = format!("for b in feat1 feat2; do git push {option} origin $b; done");
            match analyze_push_loops(&command) {
                LoopAnalysis::AllTargetsExplicit(cmds) => {
                    assert_eq!(cmds[0].explicit_repo.as_deref(), Some("origin"), "{option}");
                }
                other => panic!("expected AllTargetsExplicit for {option}, got {other:?}"),
            }
        }
    }

    /// The three Block-to-Allow flips a cluster-blind scan opened: a clustered
    /// `-o` value posing as the remote made two different remotes read as one,
    /// and made a bare looped push look like it named a target.
    #[test]
    fn clustered_push_option_does_not_mask_a_missing_or_second_remote() {
        match analyze_push_loops("for b in feat1 feat2; do git push -qo topic=x; done") {
            LoopAnalysis::MissingTargets(cmds) => {
                assert_eq!(cmds[0].explicit_repo, None);
            }
            other => panic!("expected MissingTargets, got {other:?}"),
        }

        for (command, second) in [
            (
                "git push -qo topic=x origin main && git push -qo topic=x evilremote main",
                "evilremote",
            ),
            (
                "git push -qo r=someone origin main && git push -qo r=someone https://github.com/evil/x.git main",
                "https://github.com/evil/x.git",
            ),
        ] {
            match analyze_push_chain(command) {
                ChainAnalysis::DifferentRemotes(cmds) => {
                    let remotes: Vec<&str> = cmds
                        .iter()
                        .filter_map(|c| c.explicit_repo.as_deref())
                        .collect();
                    assert_eq!(remotes, vec!["origin", second], "{command}");
                }
                other => panic!("expected DifferentRemotes for {command}, got {other:?}"),
            }
        }
    }

    /// cobra stops parsing flags at `--`, so a later `-R` is positional and gh
    /// never reads it as a repo. Scanning past it resolved a repository gh will
    /// not act on — and in the second orientation it resolved an OWNED one for
    /// a command targeting an unowned repo.
    #[test]
    fn repo_flag_scan_stops_at_double_dash() {
        for (flags, expected) in [
            ("-R cameronsjo/a -- -R evil/b", "cameronsjo/a"),
            ("-R evil/b -- -R cameronsjo/a", "evil/b"),
            ("-R cameronsjo/a -- --repo=evil/b", "cameronsjo/a"),
        ] {
            let command = format!("for i in 1 2; do gh issue close $i {flags}; done");
            match analyze_gh_loops(&command) {
                LoopAnalysis::AllTargetsExplicit(cmds) => {
                    assert_eq!(cmds[0].explicit_repo.as_deref(), Some(expected), "{flags}");
                }
                other => panic!("expected AllTargetsExplicit for {flags}, got {other:?}"),
            }
        }
    }

    #[test]
    fn push_bare_in_until_loop() {
        let result = analyze_push_loops("until false; do git push; done");
        assert!(matches!(result, LoopAnalysis::MissingTargets(_)));
    }

    #[test]
    fn push_empty_command() {
        let result = analyze_push_loops("");
        assert!(matches!(result, LoopAnalysis::NoLoops));
    }

    #[test]
    fn push_three_deep_nesting() {
        let result = analyze_push_loops(
            "for a in 1; do for b in 2; do for c in 3; do git push; done; done; done",
        );
        assert!(matches!(result, LoopAnalysis::MissingTargets(_)));
    }

    // --- analyze_push_chain ---

    #[test]
    fn chain_single_push_returns_single() {
        let result = analyze_push_chain("git push origin main");
        assert!(matches!(result, ChainAnalysis::SingleOrNone));
    }

    #[test]
    fn chain_no_push_returns_single() {
        let result = analyze_push_chain("git status && git log");
        assert!(matches!(result, ChainAnalysis::SingleOrNone));
    }

    #[test]
    fn chain_same_remote_detected() {
        let result = analyze_push_chain("git push origin main && git push origin v1.0.0");
        match result {
            ChainAnalysis::SameRemote(remote) => assert_eq!(remote, "origin"),
            other => panic!("expected SameRemote, got {other:?}"),
        }
    }

    #[test]
    fn chain_different_remotes_detected() {
        let result = analyze_push_chain("git push origin main && git push upstream main");
        assert!(matches!(result, ChainAnalysis::DifferentRemotes(_)));
    }

    #[test]
    fn chain_missing_remote_detected() {
        let result = analyze_push_chain("git push && git push origin main");
        assert!(matches!(result, ChainAnalysis::MissingRemotes(_)));
    }

    #[test]
    fn chain_semicolon_same_remote() {
        let result = analyze_push_chain("git push origin main; git push origin v2.0.0");
        match result {
            ChainAnalysis::SameRemote(remote) => assert_eq!(remote, "origin"),
            other => panic!("expected SameRemote, got {other:?}"),
        }
    }

    #[test]
    fn chain_three_pushes_same_remote() {
        let result = analyze_push_chain(
            "git push origin main && git push origin v1.0.0 && git push origin --tags",
        );
        match result {
            ChainAnalysis::SameRemote(remote) => assert_eq!(remote, "origin"),
            other => panic!("expected SameRemote, got {other:?}"),
        }
    }

    #[test]
    fn chain_does_not_count_pushes_inside_loops() {
        // The loop push should be handled by analyze_push_loops, not chain analysis
        let result = analyze_push_chain("git push origin main && for b in a b; do git push; done");
        // Only the top-level push is counted — loop body is excluded
        assert!(matches!(result, ChainAnalysis::SingleOrNone));
    }

    #[test]
    fn chain_with_non_push_commands_interleaved() {
        let result =
            analyze_push_chain("git tag v1.0.0 && git push origin main && git push origin v1.0.0");
        match result {
            ChainAnalysis::SameRemote(remote) => assert_eq!(remote, "origin"),
            other => panic!("expected SameRemote, got {other:?}"),
        }
    }

    // --- adversarial: chain analysis bypass attempts ---

    #[test]
    fn chain_push_hidden_in_subshell() {
        // Push to different remote inside ( ) should be caught
        let result = analyze_push_chain("git push origin main && (git push upstream main)");
        assert!(matches!(result, ChainAnalysis::DifferentRemotes(_)));
    }

    #[test]
    fn chain_push_hidden_in_brace_group() {
        // Push to different remote inside { } should be caught
        let result = analyze_push_chain("git push origin main && { git push upstream main; }");
        assert!(matches!(result, ChainAnalysis::DifferentRemotes(_)));
    }

    #[test]
    fn chain_or_operator_different_remotes() {
        // || chain — fallback push to different remote should block
        let result = analyze_push_chain("git push origin main || git push upstream main");
        assert!(matches!(result, ChainAnalysis::DifferentRemotes(_)));
    }

    #[test]
    fn chain_or_operator_same_remote() {
        // || chain — retry to same remote should be allowed
        let result = analyze_push_chain("git push origin main || git push origin main");
        match result {
            ChainAnalysis::SameRemote(remote) => assert_eq!(remote, "origin"),
            other => panic!("expected SameRemote, got {other:?}"),
        }
    }

    #[test]
    fn chain_variable_as_remote_treated_as_missing() {
        // $REMOTE is not a literal remote name — should be caught as missing
        let result = analyze_push_chain("git push $REMOTE main && git push origin main");
        // $REMOTE won't match any known remote in extract_push_remote,
        // but at the chain level it's a non-flag positional arg
        // The key question: does brush-parser preserve $REMOTE as a word?
        // If so, it becomes explicit_repo = Some("$REMOTE") which differs from "origin"
        assert!(!matches!(result, ChainAnalysis::SameRemote(_)));
    }

    #[test]
    fn chain_empty_string() {
        let result = analyze_push_chain("");
        assert!(matches!(result, ChainAnalysis::SingleOrNone));
    }

    #[test]
    fn chain_push_in_if_then_else() {
        // Pushes in different branches of an if statement to different remotes
        let result = analyze_push_chain(
            "if true; then git push origin main; else git push upstream main; fi",
        );
        assert!(matches!(result, ChainAnalysis::DifferentRemotes(_)));
    }

    #[test]
    fn chain_push_in_if_same_remote() {
        let result =
            analyze_push_chain("if true; then git push origin main; else git push origin feat; fi");
        match result {
            ChainAnalysis::SameRemote(remote) => assert_eq!(remote, "origin"),
            other => panic!("expected SameRemote, got {other:?}"),
        }
    }

    #[test]
    fn chain_mixed_with_loop_only_counts_top_level() {
        // The loop push should be ignored by chain analysis (handled by loop analysis)
        // Only the top-level push counts
        let result = analyze_push_chain(
            "git push origin main && for b in a b; do git push upstream $b; done",
        );
        // Only one top-level push — loop body excluded
        assert!(matches!(result, ChainAnalysis::SingleOrNone));
    }

    #[test]
    fn chain_command_substitution_in_remote() {
        // $(echo upstream) — parser should still produce a word node
        // but it won't be a simple literal remote name
        let result = analyze_push_chain("git push origin main && git push $(echo upstream) main");
        // Command substitution as remote — should not match "origin"
        assert!(!matches!(result, ChainAnalysis::SameRemote(ref r) if r == "origin"));
    }

    #[test]
    fn chain_quoted_git_push_not_counted() {
        // "git push" inside echo string should not be treated as a push command
        let result = analyze_push_chain(r#"echo "running git push" && git push origin main"#);
        assert!(matches!(result, ChainAnalysis::SingleOrNone));
    }

    #[test]
    fn chain_force_push_same_remote_still_same() {
        // Force push is a separate concern (not chain analysis's job) — same remote is same remote
        let result = analyze_push_chain("git push origin main && git push --force origin feat");
        match result {
            ChainAnalysis::SameRemote(remote) => assert_eq!(remote, "origin"),
            other => panic!("expected SameRemote, got {other:?}"),
        }
    }

    #[test]
    fn chain_push_tags_same_remote() {
        // Common pattern: push branch then push tags
        let result = analyze_push_chain("git push origin main && git push origin --tags");
        match result {
            ChainAnalysis::SameRemote(remote) => assert_eq!(remote, "origin"),
            other => panic!("expected SameRemote, got {other:?}"),
        }
    }

    #[test]
    fn chain_three_different_remotes() {
        let result = analyze_push_chain(
            "git push origin main && git push upstream main && git push backup main",
        );
        assert!(matches!(result, ChainAnalysis::DifferentRemotes(_)));
    }

    #[test]
    fn chain_two_same_one_different() {
        let result = analyze_push_chain(
            "git push origin main && git push origin v1.0 && git push upstream main",
        );
        assert!(matches!(result, ChainAnalysis::DifferentRemotes(_)));
    }
}
