//! cameronsjo/cadence-hooks#1442 (cadence-ecosystem ADR-0046, rule 3): a
//! command the parser could not read in full is judged on what it did read,
//! never refused for the rest. Brace padding past the expansion budget, a
//! glued `#`, a loosely read function header and a bash 5.3 funsub were each
//! refused at the dispatch seam (#1279, #1400, #1405); every one is a
//! spelling only a deliberate attacker types, so they pass now, while a
//! literal dangerous command beside them still blocks. Through the built
//! binary, because the seam is in dispatch, not in a guard.

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

/// Every guard that used to refuse an unread command.
const GUARDS: [[&str; 2]; 6] = [
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
        for args in GUARDS {
            let out = run(&args, command);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{args:?} {command:.60}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
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
        for args in GUARDS {
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

/// Everyday substitutions, and a glued `#` outside a double-quoted one
/// (read three ways by the comment pass already), are not refused.
#[test]
fn ordinary_quoted_substitutions_still_pass() {
    for command in [
        "echo \"$(git log -1 --format=%h)\"",
        "echo \"$(a=(x); echo hi)\"",
        "x=\"$( (cd /tmp && ls) )\"",
        "echo \"$(date) #note\"",
        "echo \"$(date)#anchor\"",
        "echo \"$(echo a # (comment)\n)\"",
        "echo \"$(echo '(#)')\"",
        "echo $(a=(x)#; echo hi)",
        "git commit -m \"$(cat <<'EOF'\nfix: tidy (#12)\nEOF\n)\"",
    ] {
        for args in [
            ["cadence", "git-safety"],
            ["cadence", "prevent-secret-leaks"],
        ] {
            let out = run(&args, command);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{args:?} {command:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

/// Everyday function definitions, assignments and parameter expansions near
/// the I1 and I3 shapes are not refused.
#[test]
fn ordinary_functions_and_expansions_still_pass() {
    for command in [
        "arr=()",
        "arr+=(one two)",
        "f() { echo hi; }; f",
        "function build { echo hi; }; build",
        "f.x-y() { echo hi; }; f.x-y",
        "git commit -m \"fix: call Foo::new() and Bar::default()\"",
        "echo \"${HOME}/x ${x:-a} ${#arr[@]}\"",
        "echo \"${{ secrets.TOKEN }}\"",
        "time cargo test",
        "! grep -q foo bar.txt",
    ] {
        for args in [
            ["cadence", "git-safety"],
            ["cadence", "prevent-secret-leaks"],
            ["cadence", "prevent-secret-writes"],
        ] {
            let out = run(&args, command);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{args:?} {command:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

#[test]
fn a_command_read_only_in_part_is_not_refused_for_the_rest() {
    let padded = format!("{}{{echo,hi}}", format!("{PAD}; ").repeat(80));
    let shapes = [
        padded.as_str(),
        "echo \"$(a=(x)#; echo \"a\nb\"\necho hi)\"",
        "@(){ echo hi; }; @",
        "g:x(){ echo hi; }; g:x",
        "echo ${ date; }",
        "git {reset,--hard,{1..5000}}",
    ];
    for command in shapes {
        for args in [
            ["cadence", "git-safety"],
            ["cadence", "prevent-secret-writes"],
            ["cadence", "prevent-secret-leaks"],
        ] {
            let out = run(&args, command);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{args:?} {command:.60}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

#[test]
fn a_literal_dangerous_command_beside_an_unread_shape_still_blocks() {
    for (args, command) in [
        (
            ["cadence", "git-safety"],
            "echo \"$(a=(x)#; echo hi)\"; git reset --hard",
        ),
        (
            ["cadence", "prevent-secret-leaks"],
            "echo ${ date; }; cat .env",
        ),
        (
            ["cadence", "prevent-secret-writes"],
            "@(){ echo hi; }; echo A=1 > .env",
        ),
    ] {
        let out = run(&args, command);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?} {command}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
