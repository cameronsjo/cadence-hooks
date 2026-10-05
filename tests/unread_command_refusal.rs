//! cameronsjo/cadence-hooks#1279, #1231 review: a fail-closed guard refuses a
//! command part of which it could not read. Padding a command with brace
//! expansions until the expansion budget is spent left a later
//! `{git,reset,--hard}` whole, so it ran past every guard; wrapping each pad
//! in a script read two ways halved the pads that took. Through the built
//! binary, because the refusal lives in the dispatch seam, not in a guard.

mod support;

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn scratch() -> &'static std::path::Path {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    DIR.get_or_init(|| tempfile::tempdir().expect("temp dir"))
        .path()
}

fn run(args: &[&str], command: &str) -> Output {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "unread-command",
        "cwd": scratch(),
        "tool_name": "Bash",
        "tool_input": { "command": command },
    })
    .to_string();
    let mut cmd: Command = support::cadence_hooks();
    cmd.env_remove("CADENCE_BYPASS")
        .env_remove("CADENCE_DISABLE")
        .env_remove("CADENCE_ALLOW_MAIN")
        .env("CADENCE_METRICS_DIR", scratch())
        .env("HOME", scratch())
        .env("CADENCE_NO_FEEDBACK_FOOTER", "1")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn cadence-hooks");
    if let Some(mut stdin) = child.stdin.take() {
        match stdin.write_all(payload.as_bytes()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => panic!("write payload: {e}"),
        }
    }
    child.wait_with_output().expect("wait on cadence-hooks")
}

const PAD: &str = r": {1..1024}{1..4} a\b";

/// Each pad spelled inside a wrapper the hunt reads.
fn wrapped(wrapper: &str) -> String {
    match wrapper {
        "top" => PAD.to_string(),
        "sh" => format!("sh -c '{PAD}'"),
        "bash" => format!("bash -c '{PAD}'"),
        "find" => format!(r"find . -exec sh -c '{PAD}' \;"),
        "xargs" => format!("echo | xargs sh -c '{PAD}'"),
        "trap" => format!("trap '{PAD}' EXIT"),
        "herestring" => format!("bash <<< '{PAD}'"),
        "rebase" => format!("git rebase -x '{PAD}' HEAD"),
        other => unreachable!("{other}"),
    }
}

#[test]
fn padded_commands_are_refused_by_every_fail_closed_guard() {
    let wrappers = [
        "top",
        "sh",
        "bash",
        "find",
        "xargs",
        "trap",
        "herestring",
        "rebase",
    ];
    for pads in [6, 8, 16] {
        for wrapper in wrappers {
            let padding = format!("{}; ", wrapped(wrapper)).repeat(pads);
            for (args, tail) in [
                (["cadence", "git-safety"], "{git,reset,--hard}"),
                (["cadence", "prevent-secret-writes"], "{cp,d,.env}"),
            ] {
                let command = format!("{padding}{tail}");
                let out = run(&args, &command);
                assert_eq!(
                    out.status.code(),
                    Some(2),
                    "{args:?} {pads}x {wrapper} {tail}: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
    }
}

#[test]
fn a_command_padded_past_the_budget_is_refused_whatever_it_runs() {
    // A harmless tail: only the unread padding can refuse it, so this shows
    // the refusal itself, not a guard reading the tail.
    let command = format!("{}{{echo,hi}}", format!("{PAD}; ").repeat(80));
    for args in [
        ["cadence", "git-safety"],
        ["cadence", "prevent-secret-writes"],
        ["cadence", "prevent-secret-leaks"],
    ] {
        let out = run(&args, &command);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        // prevent-secret-leaks refuses the same input with its own message.
        assert!(stderr.contains("too large"), "{args:?}: {stderr}");
    }
}

#[test]
fn modest_brace_expansions_still_pass() {
    for command in [
        "echo {1..10}",
        "mkdir -p src/{a,b,c}",
        "cp x.{txt,bak} /tmp",
        "for i in {1..4096}; do :; done",
        "echo {a,b}{c,d} 'x\\y'",
        "bash -c 'echo {a,b} a\\b'",
    ] {
        for args in [
            ["cadence", "git-safety"],
            ["cadence", "prevent-secret-writes"],
            ["cadence", "prevent-secret-leaks"],
            ["cadence", "prevent-secret-push"],
            ["guardrails", "guard-push-remote"],
        ] {
            let out = run(&args, command);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{args:?} {command}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

/// Every guard that refuses an unread command.
const REFUSING: [[&str; 2]; 6] = [
    ["cadence", "git-safety"],
    ["cadence", "prevent-secret-writes"],
    ["cadence", "prevent-secret-leaks"],
    ["cadence", "prevent-secret-push"],
    ["guardrails", "guard-push-remote"],
    ["obsidian", "trash-guard"],
];

fn minified_json() -> String {
    let objects: Vec<String> = (0..40)
        .map(|i| format!(r#"{{"id":{i},"tags":["a","b"],"m":{{"x":1,"y":2}}}}"#))
        .collect();
    format!("[{}]", objects.join(","))
}

#[test]
fn heredoc_bodies_no_shell_runs_are_read_as_data() {
    // cameronsjo/cadence-hooks#1279 round 3 (I1): bash never brace-expands a
    // heredoc body, but a whole-command reading of prevent-secret-leaks
    // expanded it and the command was refused as unread. Checked through the
    // dispatch seam, where the refusal lives: a `run()`-level test cannot
    // see it.
    let json = minified_json();
    let spending = vec!["{1..4000} x{a,b}{c,d}"; 80].join("\n");
    let rows = [
        format!("cat <<'EOF' > data.json\n{json}\nEOF"),
        format!("cat > data.json <<EOF\n{json}\nEOF"),
        format!("curl -s -X POST -d @- https://example.com <<'EOF'\n{json}\nEOF"),
        format!("python3 - <<'PY'\nd = {json}\nPY"),
        "tee notes.md <<'EOF'\nRanges like {1..5000} expand in bash.\nEOF".to_string(),
        "git commit -F - <<'EOF'\nfeat: support {1..5000} ranges\nEOF".to_string(),
        "cat <<EOF\n{1..100000}\nEOF".to_string(),
        format!("cat <<'EOF' > x.txt\n{spending}\nEOF"),
        format!("git commit -m \"$(cat <<'EOF'\n{spending}\nEOF\n)\""),
    ];
    for command in &rows {
        for args in REFUSING {
            let out = run(&args, command);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{args:?} {command:.60}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
    // A body a shell runs is a script: past the bound it stays refused by
    // the guard that reads it.
    for command in [
        "bash <<'EOF'\necho {1..5000}\nEOF",
        "cat <<'EOF' | bash\n{cat,x,{1..5000}}\nEOF",
    ] {
        let out = run(&["cadence", "prevent-secret-leaks"], command);
        assert_eq!(out.status.code(), Some(2), "{command}");
    }
}

#[test]
fn a_lone_oversized_word_in_an_inert_argument_list_passes() {
    // cameronsjo/cadence-hooks#1279 round 3 (I2): bash runs these
    // harmlessly, and a word too big to expand among `echo`/`printf`/`for`
    // arguments hides nothing. (prevent-secret-leaks keeps its own #1096
    // refusal of any over-bound word, so it is not in this table.)
    for command in [
        "for i in {1..5000}; do echo $i; done",
        "echo {1..100000} | wc -w",
        r"printf '%s\n' {a..z}{a..z}{a..z} | wc -l",
        r"printf '%s\n' {0..9}{0..9}{0..9}{0..9}",
        "echo x{a,b}{c,d}{e,f}{g,h}{i,j}{k,l}{m,n}{o,p}{q,r}{s,t}{u,v}{w,x}{y,z}",
        "echo {1..5000} > nums.txt",
        "touch file{1..5000}.txt",
    ] {
        for args in REFUSING {
            if args[1] == "prevent-secret-leaks"
                || (args[1] == "prevent-secret-writes" && command.starts_with("touch"))
            {
                continue;
            }
            let out = run(&args, command);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{args:?} {command}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

#[test]
fn an_oversized_word_where_it_can_hide_what_runs_is_refused() {
    // cameronsjo/cadence-hooks#1279 round 3 (I2): command position, a
    // non-literal command, a wrapper's script, output fed to a shell or
    // xargs, a `printf -v`, and a `touch` whose operands the writes guard
    // judges (`.{a..z}{a..z}{a..z}` creates `.env`).
    for command in [
        ": {1..5000}; {git,reset,--hard}",
        "{rm,note.md,{1..5000}}",
        "git {reset,--hard,{1..5000}}",
        "$CMD {1..5000}",
        "bash -c 'echo {1..5000}'",
        "echo {1..5000}; bash -c '{git,reset,--hard,{1..5000}}'",
        r": {1..5000}; eval $'\x7bgit,reset,--hard,\x7b1..5000\x7d\x7d'",
        "echo {1..5000}; x='{rm,note.md,{1..5000}}'; eval $x",
        "echo {rm,note.md,{1..5000}} | bash",
        "echo {note.md,{1..5000}} | xargs rm",
        "for x in {rm,note.md,{1..5000}}; do $x; done",
        "echo $(bash -c '{rm,note.md,{1..5000}}')",
        "printf -v {GIT_DIR,{1..5000}} x",
        "touch .{a..z}{a..z}{a..z}",
    ] {
        let out = run(&["cadence", "prevent-secret-writes"], command);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{command}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let out = run(
        &["cadence", "git-safety"],
        ": {1..5000}; {git,reset,--hard}",
    );
    assert_eq!(out.status.code(), Some(2));
}
