//! Opt-in differential coverage for the shell parser's built-binary path.
//!
//! Real `bash` decides whether each row executes an inert `touch` canary. The
//! built `cadence-hooks` binary receives a confined secret-read twin through
//! `prevent-secret-leaks`; it must block exactly when bash executed the canary.
//! This keeps pre-filters, hook decoding, parser behavior, and dispatch in scope.
//!
//! `CADENCE_SHELL_DIFFERENTIAL_BIN` is mandatory and must name the exact built
//! binary under test. Run the current differential with:
//! `CADENCE_SHELL_DIFFERENTIAL_BIN=target/debug/cadence-hooks cargo test
//! --test shell_differential built_guard_visibility_matches_real_bash --
//! --ignored --exact`.
//!
//! The known-different bootstrap is reproducible from PR #511's durable first
//! cut, commit `7c084dfdcdf4b305437210bf9aa5c63449758a83`. Build that revision, point
//! the same environment variable at its executable, then run
//! `cargo test --test shell_differential
//! oracle_reports_all_five_pre_fix_binary_misses -- --ignored --exact`.

#![cfg(unix)]

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const BASH: &str = "/bin/bash";
const BASH_PAYLOAD: &str = "touch ./canary";
const GUARDED_PAYLOAD: &str = "cat .env";

#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    template: &'static str,
    bootstrap_490_miss: bool,
    bash_executes: bool,
}

impl Case {
    const fn bootstrap_490(name: &'static str, template: &'static str) -> Self {
        Self {
            name,
            template,
            bootstrap_490_miss: true,
            bash_executes: true,
        }
    }

    const fn executes(name: &'static str, template: &'static str) -> Self {
        Self {
            name,
            template,
            bootstrap_490_miss: false,
            bash_executes: true,
        }
    }

    const fn does_not_execute(name: &'static str, template: &'static str) -> Self {
        Self {
            name,
            template,
            bootstrap_490_miss: false,
            bash_executes: false,
        }
    }
}

const CASES: &[Case] = &[
    // The first four of the five #490 bootstrap rows preserved in `run1.py`.
    // The unterminated-heredoc fifth row is marked in its earned group below;
    // all five were Allow against the first-cut binary while bash executed.
    Case::bootstrap_490("#490 parameter-default hash", "echo ${x:- # } ; PAYLOAD"),
    Case::bootstrap_490("#490 backtick comment", "echo `date # x`; PAYLOAD"),
    Case::bootstrap_490("#490 escaped-space hash", r"echo a\ #x && PAYLOAD"),
    Case::bootstrap_490(
        "#490 parameter-default text after hash",
        "echo ${B:-a # b} && PAYLOAD",
    ),
    Case::executes(
        "#490 multiline substitution comment",
        "echo $(echo a # x\n) ; PAYLOAD",
    ),
    // #497: an inert sudo shim peels only the spellings represented here, so
    // neither the test runner nor a developer's machine ever invokes sudo.
    Case::executes("#497 sudo short flag", "sudo -E bash -c 'PAYLOAD'"),
    Case::executes("#497 sudo home flag", "sudo -H bash -c 'PAYLOAD'"),
    Case::executes("#497 sudo noninteractive flag", "sudo -n bash -c 'PAYLOAD'"),
    Case::executes("#497 sudo login flag", "sudo -i bash -c 'PAYLOAD'"),
    Case::executes(
        "#497 sudo clustered short flags",
        "sudo -EH bash -c 'PAYLOAD'",
    ),
    Case::executes(
        "#497 sudo long flag",
        "sudo --preserve-env bash -c 'PAYLOAD'",
    ),
    Case::executes(
        "#497 sudo long flag with value",
        "sudo --preserve-env=PATH bash -c 'PAYLOAD'",
    ),
    Case::executes("#497 sudo bare end of options", "sudo -- bash -c 'PAYLOAD'"),
    Case::executes("#497 sudo end of options", "sudo -E -- bash -c 'PAYLOAD'"),
    // #496: `--` terminates shell option parsing; the next token is the script.
    Case::executes("#496 bash -c end of options", "bash -c -- 'PAYLOAD'"),
    Case::executes("#496 sh -c end of options", "sh -c -- 'PAYLOAD'"),
    Case::executes(
        "#496 sudo and end-of-options compose",
        "sudo -E bash -c -- 'PAYLOAD'",
    ),
    // #491: odd parity leaves a real pipe; even parity leaves a clobber
    // redirect and must not manufacture an executable payload.
    Case::executes("#491 odd escaped clobber is a pipe", r"echo hi \>| PAYLOAD"),
    Case::does_not_execute(
        "#491 even escaped clobber is a redirect",
        r"echo hi \\>| PAYLOAD",
    ),
    // Heredoc carry rows from the #490/#511 parser work.
    Case::executes(
        "#511 heredoc carry after commented introducer line",
        "cat <<EOF # note\nprose $(PAYLOAD)\nEOF",
    ),
    Case::bootstrap_490(
        "#511 heredoc carry from unterminated body",
        "cat <<EOF\nprose # $(PAYLOAD)",
    ),
    Case::executes(
        "#511 commented-out heredoc introducer",
        "echo hi # cat <<EOF\nPAYLOAD\nEOF",
    ),
];

struct BashObservation {
    output: Output,
    executed: bool,
    scratch: tempfile::TempDir,
}

struct Observation {
    bash: Output,
    bash_executed: bool,
    guard: Output,
    guard_blocked: bool,
    scratch: tempfile::TempDir,
}

fn install_sudo_shim(dir: &Path) {
    let shim = dir.join("sudo");
    fs::write(
        &shim,
        r#"#!/bin/bash
while (($#)); do
    case "$1" in
        --) shift; break ;;
        --preserve-env|--preserve-env=*) shift ;;
        -E|-H|-n|-i|-EH) shift ;;
        *) break ;;
    esac
done
exec "$@"
"#,
    )
    .expect("write inert sudo shim");
    let mut permissions = fs::metadata(&shim).expect("stat sudo shim").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(shim, permissions).expect("make sudo shim executable");
}

fn oracle_path(shim_dir: &Path) -> OsString {
    std::env::join_paths([shim_dir, Path::new("/usr/bin"), Path::new("/bin")])
        .expect("construct isolated oracle PATH")
}

fn observe_bash(case: Case) -> BashObservation {
    let scratch = tempfile::tempdir().expect("create isolated oracle directory");
    install_sudo_shim(scratch.path());
    let source = case.template.replace("PAYLOAD", BASH_PAYLOAD);
    let output = Command::new(BASH)
        .args(["--noprofile", "--norc", "-c", &source])
        .current_dir(scratch.path())
        .env_clear()
        .env("PATH", oracle_path(scratch.path()))
        .env("LC_ALL", "C")
        .output()
        .expect("run real bash oracle");
    let executed = scratch.path().join("canary").is_file();
    assert_eq!(
        executed,
        case.bash_executes,
        "{}: real bash changed the recorded canary result: status={:?}, stderr={}",
        case.name,
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );

    BashObservation {
        output,
        executed,
        scratch,
    }
}

fn cadence_hooks_binary() -> PathBuf {
    // Keep Cargo's integration-test binary artifact wired even though the
    // caller must explicitly select it (or a historical build) below.
    let _cargo_built_current_binary = env!("CARGO_BIN_EXE_cadence-hooks");
    let path = PathBuf::from(
        std::env::var_os("CADENCE_SHELL_DIFFERENTIAL_BIN").unwrap_or_else(|| {
            panic!(
                "CADENCE_SHELL_DIFFERENTIAL_BIN must name the exact cadence-hooks binary under test"
            )
        }),
    );
    let path = fs::canonicalize(&path)
        .unwrap_or_else(|error| panic!("resolve cadence-hooks binary {}: {error}", path.display()));
    let metadata = fs::metadata(&path)
        .unwrap_or_else(|error| panic!("stat cadence-hooks binary {}: {error}", path.display()));
    assert!(
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        "CADENCE_SHELL_DIFFERENTIAL_BIN is not an executable file: {}",
        path.display(),
    );

    let version = Command::new(&path)
        .arg("--version")
        .env_clear()
        .output()
        .unwrap_or_else(|error| panic!("probe cadence-hooks binary {}: {error}", path.display()));
    assert!(
        version.status.success()
            && String::from_utf8_lossy(&version.stdout).starts_with("cadence-hooks "),
        "CADENCE_SHELL_DIFFERENTIAL_BIN is not cadence-hooks: {} (status={:?}, stdout={}, stderr={})",
        path.display(),
        version.status.code(),
        String::from_utf8_lossy(&version.stdout),
        String::from_utf8_lossy(&version.stderr),
    );
    path
}

fn run_guard(binary: &Path, case: Case, scratch: &Path) -> Output {
    // The guard twin is data only: it is written directly to cadence-hooks'
    // stdin and is never passed to a shell. Its `.env` is a dummy inside the
    // disposable row directory; only the inert `touch` twin can execute.
    fs::write(scratch.join(".env"), "DUMMY=1\n").expect("write confined guard fixture");
    let source = case.template.replace("PAYLOAD", GUARDED_PAYLOAD);
    let payload = serde_json::json!({
        "session_id": "shell-differential",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": source },
        "cwd": scratch,
    })
    .to_string();

    let mut child = Command::new(binary)
        .args(["cadence", "prevent-secret-leaks"])
        .current_dir(scratch)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", scratch)
        .env("TMPDIR", scratch)
        .env("CADENCE_METRICS_DIR", scratch.join("metrics"))
        .env("CADENCE_MARKER_DIR", scratch.join("markers"))
        .env("CADENCE_NO_FEEDBACK_FOOTER", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run built cadence-hooks parser consumer");
    child
        .stdin
        .as_mut()
        .expect("guard stdin")
        .write_all(payload.as_bytes())
        .expect("write guard payload");
    child.wait_with_output().expect("wait for guard oracle")
}

fn observe(binary: &Path, case: Case) -> Observation {
    let bash = observe_bash(case);
    let guard = run_guard(binary, case, bash.scratch.path());
    let guard_blocked = match guard.status.code() {
        Some(0) => {
            assert!(
                guard.stdout.is_empty() && guard.stderr.is_empty(),
                "{}: exit 0 was not a silent Allow: stdout={}, stderr={}",
                case.name,
                String::from_utf8_lossy(&guard.stdout),
                String::from_utf8_lossy(&guard.stderr),
            );
            false
        }
        Some(2) => {
            assert!(
                String::from_utf8_lossy(&guard.stderr)
                    .contains("prevent-secret-leaks: command would expose secret file contents"),
                "{}: exit 2 came from the wrong failure: stderr={}",
                case.name,
                String::from_utf8_lossy(&guard.stderr),
            );
            true
        }
        code => panic!(
            "{}: built guard failed instead of returning Allow or Block: status={code:?}, stderr={}",
            case.name,
            String::from_utf8_lossy(&guard.stderr),
        ),
    };

    Observation {
        bash: bash.output,
        bash_executed: bash.executed,
        guard,
        guard_blocked,
        scratch: bash.scratch,
    }
}

fn diagnostic(case: Case, observation: &Observation) -> String {
    format!(
        "{}: bash_executed={}, bash_status={:?}, bash_stderr={}; guard_blocked={}, guard_status={:?}, guard_stderr={}; scratch={}",
        case.name,
        observation.bash_executed,
        observation.bash.status.code(),
        String::from_utf8_lossy(&observation.bash.stderr),
        observation.guard_blocked,
        observation.guard.status.code(),
        String::from_utf8_lossy(&observation.guard.stderr),
        observation.scratch.path().display(),
    )
}

fn disagrees(bash_executed: bool, guard_blocked: bool) -> bool {
    bash_executed != guard_blocked
}

#[test]
#[ignore = "opt-in bootstrap: invokes real bash for the five #490 seeds"]
fn oracle_reports_all_five_pre_fix_binary_misses() {
    let binary = cadence_hooks_binary();
    let mut misses = Vec::new();
    for &case in CASES.iter().filter(|case| case.bootstrap_490_miss) {
        let observation = observe(&binary, case);
        if disagrees(observation.bash_executed, observation.guard_blocked) {
            misses.push(diagnostic(case, &observation));
        }
    }

    assert_eq!(
        misses.len(),
        5,
        "known-different bootstrap must report every pre-fix #490 miss; reported {misses:#?}"
    );
}

#[test]
#[ignore = "opt-in differential: invokes real bash and the built binary per earned row"]
fn built_guard_visibility_matches_real_bash() {
    let binary = cadence_hooks_binary();
    let mut disagreements = Vec::new();
    for &case in CASES {
        let observation = observe(&binary, case);
        if disagrees(observation.bash_executed, observation.guard_blocked) {
            disagreements.push(diagnostic(case, &observation));
        }
    }

    assert!(
        disagreements.is_empty(),
        "bash/guard differential found {} disagreement(s):\n{}",
        disagreements.len(),
        disagreements.join("\n"),
    );
}
