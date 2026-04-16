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
fn extract_repo_flag(cmd: &SimpleCommand) -> Option<String> {
    let words = suffix_words(cmd);
    let mut iter = words.iter();
    while let Some(word) = iter.next() {
        if word == "-R" || word == "--repo" {
            return iter.next().cloned();
        }
        // Handle -Rowner/repo (no space)
        if let Some(repo) = word.strip_prefix("-R").filter(|r| !r.is_empty()) {
            return Some(repo.to_string());
        }
        if let Some(repo) = word.strip_prefix("--repo=") {
            return Some(repo.to_string());
        }
    }
    None
}

/// Extract the explicit remote name from `git push <remote>` arguments.
fn extract_push_remote(cmd: &SimpleCommand) -> Option<String> {
    let words = suffix_words(cmd);
    // Skip "push", then skip flags, take first positional arg
    let after_push: Vec<&str> = words
        .iter()
        .skip_while(|w| *w != "push")
        .skip(1) // skip "push" itself
        .filter(|w| !w.starts_with('-'))
        .map(|w| w.as_str())
        .collect();
    after_push.first().map(|s| s.to_string())
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
