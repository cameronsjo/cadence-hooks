//! Ask "are you sure?" before a Bash command removes a Docker container
//! (cameronsjo/cadence-hooks#1661).
//!
//! A removed container cannot be started again: its writable layer, logs and
//! anything written inside it are gone. `stop`, `restart` and `kill` leave a
//! container that starts again, so they are not judged here; neither are
//! `compose`, `system prune`, or image, volume and network removal.
//!
//! The guard is confirm tier (`cadence_hooks_core::confirm`): the first
//! attempt blocks with a message naming what the command removes, and the
//! identical command again, from the same session and agent within ten
//! minutes, passes once. It replaces a settings ask rule, whose dialog auto
//! mode never answers.
//!
//! Detection is tokenized. Each segment `command_segments` yields (chains,
//! pipes, `bash -c` scripts, substitutions) is read through the same
//! exec-wrapper peel `guard-op-vault-scan` uses (`sudo`, `env`, `timeout`,
//! `xargs`, `perl -e '…exec @ARGV'`, …). The command word must be `docker`;
//! Docker's global options are skipped, value options with their value; the
//! next word must be `rm`, or `container` followed by `rm` or `remove`.
//!
//! The threat model is a cooperative model making an honest mistake
//! (cadence-ecosystem ADR-0046). The guard reads command text only, so a
//! removal the text does not spell out (a script file, the Docker API over
//! its socket, `ssh host 'docker rm …'`, a command word behind a variable set
//! elsewhere) is not seen, and a command it cannot read is allowed.

use crate::guard_op_vault_scan::executed_argv;
use cadence_hooks_core::confirm::{Retry, confirm_block, whole_command_action};
use cadence_hooks_core::shell::{
    command_segments, command_word, executable_tokens, is_redirect_token, redirect_operator_span,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Asks before `docker rm` / `docker container rm`; a deliberate identical
/// retry passes once.
pub struct ContainerRmGuard;

/// The hook's name, which also keys its confirmations.
const NAME: &str = "guard-container-rm";

/// Docker global options that take a value as the next word. Any other
/// option word before the subcommand is a flag (`--debug`, `--tls`).
const VALUE_OPTIONS: &[&str] = &[
    "--config",
    "-c",
    "--context",
    "-H",
    "--host",
    "-l",
    "--log-level",
    "--tlscacert",
    "--tlscert",
    "--tlskey",
];

/// One container removal the guard read in a segment.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Removal {
    /// The containers the segment names literally, in order.
    containers: Vec<String>,
    /// Some names come only at run time: from a substitution
    /// (`$(docker ps -aq)`), a variable, or an `xargs` placeholder (`{}`).
    runtime: bool,
    /// `-f`/`--force`: a running container is stopped first.
    force: bool,
    /// `-v`/`--volumes`: its anonymous volumes go too.
    volumes: bool,
}

impl Removal {
    /// One line for the block message. Pure.
    fn describe(&self) -> String {
        let names: Vec<String> = self.containers.iter().map(|c| format!("`{c}`")).collect();
        let what = match (names.is_empty(), self.runtime) {
            // `xargs docker rm` names nothing literally and still removes.
            (true, _) => "the containers named at run time".to_string(),
            (false, true) => format!("{} and the containers named at run time", names.join(", ")),
            (false, false) => names.join(", "),
        };
        let mut notes = Vec::new();
        if self.force {
            notes.push("-f stops a running container first");
        }
        if self.volumes {
            notes.push("-v also removes its anonymous volumes");
        }
        if notes.is_empty() {
            format!("removes {what}")
        } else {
            format!("removes {what} ({})", notes.join("; "))
        }
    }
}

/// The words after Docker's global options. Pure.
fn skip_global_options(words: &[String]) -> &[String] {
    let mut rest = words;
    while let Some(word) = rest.first() {
        if !word.starts_with('-') || word == "-" {
            break;
        }
        let width = if VALUE_OPTIONS.contains(&word.as_str()) {
            2
        } else {
            1
        };
        rest = rest.get(width..).unwrap_or_default();
    }
    rest
}

/// Read `rm`'s operands: the containers and the flags that change what goes.
/// `None` when the command asks for help and removes nothing. Pure.
fn read_operands(operands: &[String]) -> Option<Removal> {
    let mut removal = Removal {
        containers: Vec::new(),
        runtime: false,
        force: false,
        volumes: false,
    };
    let mut i = 0;
    while let Some(word) = operands.get(i) {
        i += 1;
        if word.contains("$(") || word.contains('`') {
            // The tokenizer splits a substitution's inner command into
            // words; skip them so its flags and words are not read as rm's.
            removal.runtime = true;
            i = substitution_end(operands, i - 1);
            continue;
        }
        if word.starts_with('$') || word == "{}" {
            removal.runtime = true;
            continue;
        }
        if is_redirect_token(word) {
            // A bare operator (`>`, `2>`) takes the next word as its target.
            if redirect_operator_span(word).is_some_and(|(_, bare)| bare) {
                i += 1;
            }
            continue;
        }
        match word.as_str() {
            "--help" | "-h" => return None,
            "--force" => removal.force = true,
            "--volumes" => removal.volumes = true,
            w if w.starts_with("--") => {}
            w if w.starts_with('-') && w.len() > 1 => {
                removal.force |= w.contains('f');
                removal.volumes |= w.contains('v');
            }
            w => removal.containers.push(w.to_string()),
        }
    }
    Some(removal)
}

/// The index just past the substitution that opens in `words[start]`: the
/// first word at which `$(…)` parens balance and backticks pair. A
/// substitution left open runs to the end. Pure.
fn substitution_end(words: &[String], start: usize) -> usize {
    let (mut depth, mut ticks) = (0i64, 0usize);
    for (offset, word) in words.iter().enumerate().skip(start) {
        depth += word.matches('(').count() as i64 - word.matches(')').count() as i64;
        ticks += word.matches('`').count();
        if depth <= 0 && ticks % 2 == 0 {
            return offset + 1;
        }
    }
    words.len()
}

/// The removal a segment's tokens perform, if any. Pure.
fn removal_in(tokens: &[String]) -> Option<Removal> {
    let argv = executed_argv(tokens);
    let (head, rest) = argv.split_first()?;
    if command_word(head).as_ref() != "docker" {
        return None;
    }
    let (sub, rest) = skip_global_options(rest).split_first()?;
    let operands = match sub.as_str() {
        "rm" => rest,
        "container" => {
            let (verb, rest) = rest.split_first()?;
            if !matches!(verb.as_str(), "rm" | "remove") {
                return None;
            }
            rest
        }
        _ => return None,
    };
    read_operands(operands)
}

/// The removals `command` performs (deduplicated, in order) and the
/// confirm-tier action, or `None` when it removes no container.
///
/// The action is the whole command, whitespace-normalized, beside the
/// removals read, as `guard-op-vault-scan` keys its scans: a `--context`, a
/// `DOCKER_HOST=` prefix or an earlier `export` can each choose which daemon
/// the removal reaches, and the whole command carries them all without the
/// guard naming them.
fn removals_and_action(command: &str) -> Option<(Vec<String>, String)> {
    let mut lines: Vec<String> = Vec::new();
    for segment in command_segments(command) {
        if let Some(removal) = removal_in(&executable_tokens(&segment)) {
            let line = removal.describe();
            if !lines.contains(&line) {
                lines.push(line);
            }
        }
    }
    if lines.is_empty() {
        return None;
    }
    let mut key = lines.clone();
    key.sort();
    let action = format!("{}\u{1f}{}", key.join("\n"), whole_command_action(command));
    Some((lines, action))
}

fn block_message(lines: &[String]) -> String {
    let found = lines
        .iter()
        .map(|l| format!("this command {l}"))
        .collect::<Vec<_>>()
        .join("\n   Found: ");
    format!(
        "🚫 {NAME}: this removes a Docker container\n   \
         Found: {found}\n   \
         Fix: a removed container cannot be started again, and its logs and anything written \
         inside it are gone. Check it is the container the operator meant (`docker ps -a`) and \
         that nothing in it needs keeping (`docker logs`, `docker cp`). To pause it instead, \
         `docker stop` leaves a container that starts again."
    )
}

impl Check for ContainerRmGuard {
    fn name(&self) -> &str {
        NAME
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };
        let Some((lines, action)) = removals_and_action(command) else {
            return CheckResult::allow();
        };
        confirm_block(
            input,
            NAME,
            &action,
            &block_message(&lines),
            Retry::SameCommand,
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::test_builders::{make_bash, with_marker_dir};
    use cadence_hooks_core::{BypassKind, Outcome};

    fn attempt(command: &str, session: Option<&str>, agent: Option<&str>, call: &str) -> HookInput {
        let mut input = make_bash(command);
        input.session_id = session.map(String::from);
        input.agent_id = agent.map(String::from);
        input.tool_use_id = Some(call.into());
        input
    }

    /// The outcome of `command` as call `call` in session `s1`.
    fn try_in_s1(command: &str, call: &str) -> CheckResult {
        ContainerRmGuard.run(&attempt(command, Some("s1"), None, call))
    }

    /// Run `command` once in a fresh marker dir, as a first attempt.
    fn first_outcome(command: &str) -> CheckResult {
        let dir = tempfile::tempdir().unwrap();
        with_marker_dir(dir.path(), || try_in_s1(command, "t1"))
    }

    // --- what is a removal ---

    #[test]
    fn container_removals_block() {
        for cmd in [
            "docker rm web",
            "docker rm -f web",
            "docker rm --force web db",
            "docker rm -fv web",
            "docker container rm web",
            "docker container rm -f web",
            "docker container remove web",
            "docker --context prod rm web",
            "docker -H tcp://h:2375 rm web",
            "docker --host=tcp://h:2375 rm web",
            "docker --debug rm web",
            "docker --log-level debug container rm web",
            "/usr/local/bin/docker rm web",
            "DOCKER rm web",
            "sudo docker rm web",
            "env DOCKER_HOST=tcp://h:2375 docker rm web",
            "DOCKER_HOST=tcp://h:2375 docker rm web",
            "timeout 30 docker rm -f web",
            "perl -e 'alarm 60; exec @ARGV' docker rm web",
            "bash -c 'docker rm web'",
            "docker ps -aq | xargs docker rm",
            "docker ps -aq --filter status=exited | xargs -r docker rm",
            "docker rm $(docker ps -aq)",
            "docker stop web && docker rm web",
            "docker rm web 2>/dev/null || true",
            "(docker rm web)",
            // The shared parser reads a literal `eval` string as commands.
            "eval \"docker rm web\"",
            "for c in a b; do docker rm $c; done",
        ] {
            assert_eq!(first_outcome(cmd).outcome, Outcome::Block, "{cmd}");
        }
    }

    #[test]
    fn everything_else_docker_does_passes() {
        for cmd in [
            "docker ps",
            "docker ps -a",
            "docker logs web",
            "docker logs -f --tail 100 web",
            "docker inspect web",
            "docker exec -it web sh",
            "docker run --rm alpine true",
            "docker run --rm -it -v ./src:/src alpine sh",
            "docker run --name rm alpine",
            "docker start web",
            "docker stop web",
            "docker restart web",
            "docker kill web",
            "docker image rm alpine",
            "docker image remove alpine",
            "docker rmi alpine",
            "docker compose down",
            "docker compose rm",
            "docker compose rm -f web",
            "docker system prune",
            "docker system prune -af",
            "docker container prune",
            "docker volume rm v",
            "docker network rm n",
            "docker container ls",
            "docker container stop web",
            "docker --context rm ps",
            "docker build -t app .",
            "docker pull alpine",
            "docker rm --help",
            "docker container rm -h",
            "podman ps",
        ] {
            let result = first_outcome(cmd);
            assert_eq!(result.outcome, Outcome::Allow, "{cmd}");
            assert!(result.message.is_none(), "{cmd}");
        }
    }

    #[test]
    fn prose_and_other_programs_pass() {
        for cmd in [
            "echo 'docker rm web'",
            "git commit -m 'docs: docker rm web'",
            "grep -rn 'docker rm' docs",
            "rm docker",
            "rm -f docker-compose.override.yml",
            "ls",
            "",
        ] {
            assert_eq!(first_outcome(cmd).outcome, Outcome::Allow, "{cmd}");
        }
    }

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            ..Default::default()
        };
        assert_eq!(ContainerRmGuard.run(&input).outcome, Outcome::Allow);
    }

    // --- the stated limit (cadence-ecosystem ADR-0046) ---

    #[test]
    fn what_the_text_does_not_spell_out_is_not_seen() {
        for cmd in [
            // The remote command is one quoted argument to ssh.
            "ssh host 'docker rm web'",
            "ssh host docker rm web",
            // A script file's contents are not in the command.
            "bash ./cleanup.sh",
            // A command word behind a variable set elsewhere.
            "$DOCKER rm web",
            // The API over the socket.
            "curl --unix-socket /var/run/docker.sock -X DELETE http://localhost/containers/web",
        ] {
            assert_eq!(first_outcome(cmd).outcome, Outcome::Allow, "{cmd}");
        }
    }

    // --- the message ---

    #[test]
    fn message_names_the_containers_and_flags() {
        let msg = first_outcome("docker container rm -f web db")
            .message
            .unwrap();
        assert!(msg.contains("guard-container-rm"), "{msg}");
        assert!(msg.contains("removes `web`, `db`"), "{msg}");
        assert!(msg.contains("-f stops a running container first"), "{msg}");
        assert!(!msg.contains("-v also"), "{msg}");
        assert!(msg.contains("Are you sure?"), "{msg}");
        assert!(msg.contains("run the identical command again"), "{msg}");
        let volumes = first_outcome("docker rm -v web").message.unwrap();
        assert!(
            volumes.contains("-v also removes its anonymous volumes"),
            "{volumes}"
        );
        let redirect = first_outcome("docker rm web > out.log").message.unwrap();
        assert!(
            redirect.contains("removes `web`\n") || redirect.contains("removes `web` ("),
            "{redirect}"
        );
        assert!(!redirect.contains("out.log`"), "{redirect}");
    }

    #[test]
    fn message_says_when_names_come_at_run_time() {
        for cmd in [
            "docker ps -aq | xargs docker rm",
            "docker ps -aq | xargs -I{} docker rm {}",
            "docker rm $(docker ps -aq)",
            "docker rm `docker ps -aq`",
            "docker rm $CONTAINER",
        ] {
            let msg = first_outcome(cmd).message.unwrap();
            assert!(
                msg.contains("this command removes the containers named at run time\n"),
                "{cmd}: {msg}"
            );
        }
        // A substitution's own flags and words are not rm's.
        let msg = first_outcome("docker rm -f $(docker ps -aq -f status=exited) web")
            .message
            .unwrap();
        assert!(
            msg.contains(
                "removes `web` and the containers named at run time (-f stops a running \
                 container first)\n"
            ),
            "{msg}"
        );
        assert!(
            !msg.contains("status=exited") && !msg.contains("`ps`"),
            "{msg}"
        );
        let plain = first_outcome("docker rm $(docker ps -aq)").message.unwrap();
        assert!(!plain.contains("-f stops"), "{plain}");
    }

    #[test]
    fn a_wrapped_removal_is_reported_once() {
        let msg = first_outcome("bash -c 'docker rm web'").message.unwrap();
        assert_eq!(msg.matches("Found:").count(), 1, "{msg}");
    }

    // --- confirm tier (cameronsjo/cadence-hooks#1658) ---

    #[test]
    fn first_blocks_identical_retry_passes_once_third_blocks() {
        let dir = tempfile::tempdir().unwrap();
        with_marker_dir(dir.path(), || {
            assert_eq!(try_in_s1("docker rm -f web", "t1").outcome, Outcome::Block);
            let second = try_in_s1("docker rm -f web", "t2");
            assert_eq!(second.outcome, Outcome::Allow);
            assert_eq!(second.bypass.unwrap().kind, BypassKind::Confirmed);
            assert_eq!(try_in_s1("docker rm -f web", "t3").outcome, Outcome::Block);
        });
    }

    #[test]
    fn a_retry_that_differs_only_in_spacing_passes() {
        let dir = tempfile::tempdir().unwrap();
        with_marker_dir(dir.path(), || {
            assert_eq!(try_in_s1("docker rm web", "t1").outcome, Outcome::Block);
            let retry = try_in_s1("  docker   rm\tweb ", "t2");
            assert_eq!(retry.outcome, Outcome::Allow);
        });
    }

    #[test]
    fn a_changed_command_blocks_again() {
        let mut passed: Vec<String> = Vec::new();
        for (plain, variant) in [
            ("docker rm web", "docker rm db"),
            ("docker rm web", "docker rm web db"),
            ("docker rm web", "docker rm -f web"),
            ("docker rm web", "docker rm -v web"),
            ("docker rm web", "docker --context prod rm web"),
            ("docker rm web", "DOCKER_HOST=tcp://h:2375 docker rm web"),
            ("docker rm web", "export DOCKER_CONTEXT=prod; docker rm web"),
            ("docker rm web", "docker container rm web"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            with_marker_dir(dir.path(), || {
                assert_eq!(try_in_s1(plain, "t1").outcome, Outcome::Block, "{plain}");
                let retry = try_in_s1(variant, "t2");
                let rearmed = retry.outcome == Outcome::Block
                    && retry.message.is_some_and(|m| m.contains("Are you sure?"));
                if !rearmed {
                    passed.push(format!("{plain} -> {variant}"));
                }
            });
        }
        assert!(passed.is_empty(), "inherited a confirmation: {passed:#?}");
    }

    #[test]
    fn the_key_holds_no_working_directory() {
        // A container is not in a repository: the same command from another
        // directory is the same action, as for guard-op-vault-scan.
        let dir = tempfile::tempdir().unwrap();
        with_marker_dir(dir.path(), || {
            let mut first = attempt("docker rm web", Some("s1"), None, "t1");
            first.cwd = Some("/srv/a".into());
            assert_eq!(ContainerRmGuard.run(&first).outcome, Outcome::Block);
            let mut retry = attempt("docker rm web", Some("s1"), None, "t2");
            retry.cwd = Some("/srv/b".into());
            assert_eq!(ContainerRmGuard.run(&retry).outcome, Outcome::Allow);
        });
    }

    #[test]
    fn confirm_does_not_reach_another_session_or_agent() {
        let dir = tempfile::tempdir().unwrap();
        with_marker_dir(dir.path(), || {
            let cmd = "docker rm web";
            assert_eq!(try_in_s1(cmd, "t1").outcome, Outcome::Block);
            for (label, input) in [
                ("another session", attempt(cmd, Some("s2"), None, "t2")),
                ("another agent", attempt(cmd, Some("s1"), Some("ag1"), "t3")),
            ] {
                assert_eq!(
                    ContainerRmGuard.run(&input).outcome,
                    Outcome::Block,
                    "{label} must not inherit the pass"
                );
            }
            assert_eq!(try_in_s1(cmd, "t4").outcome, Outcome::Allow);
        });
    }

    #[test]
    fn no_session_id_blocks_every_time() {
        let dir = tempfile::tempdir().unwrap();
        with_marker_dir(dir.path(), || {
            for call in ["t1", "t2"] {
                let r = ContainerRmGuard.run(&attempt("docker rm web", None, None, call));
                assert_eq!(r.outcome, Outcome::Block);
                let msg = r.message.unwrap();
                assert!(
                    msg.contains("A second attempt will be blocked too"),
                    "{msg}"
                );
            }
        });
    }

    #[test]
    fn confirm_expires() {
        let dir = tempfile::tempdir().unwrap();
        with_marker_dir(dir.path(), || {
            let input = attempt("docker rm web", Some("s1"), None, "t1");
            assert_eq!(ContainerRmGuard.run(&input).outcome, Outcome::Block);
            let (_, action) = removals_and_action("docker rm web").unwrap();
            assert!(cadence_hooks_core::confirm::backdate_for_tests(
                &input,
                NAME,
                &action,
                11 * 60
            ));
            assert_eq!(try_in_s1("docker rm web", "t2").outcome, Outcome::Block);
        });
    }
}
