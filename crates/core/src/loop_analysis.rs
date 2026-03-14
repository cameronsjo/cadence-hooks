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
        match cmd {
            Command::Compound(compound, _) => {
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
            _ => {}
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
            Command::Simple(simple) => {
                if is_gh_command(simple) {
                    out.push(LoopedCommand {
                        name: "gh".to_string(),
                        explicit_repo: extract_repo_flag(simple),
                    });
                }
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
            Command::Simple(simple) => {
                if is_git_push_command(simple) {
                    out.push(LoopedCommand {
                        name: "git push".to_string(),
                        explicit_repo: extract_push_remote(simple),
                    });
                }
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
        if let Some(repo) = word.strip_prefix("-R") {
            if !repo.is_empty() {
                return Some(repo.to_string());
            }
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
}
