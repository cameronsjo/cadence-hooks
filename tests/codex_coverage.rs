use cadence_hooks_core::{HookInput, MetricsInput};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn report() -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    serde_json::from_slice(
        &fs::read(root.join("docs/codex-compatibility-report.json"))
            .expect("read checked-in compatibility report"),
    )
    .expect("report json")
}

/// Spawn the built binary with its metrics root pinned to a throwaway dir.
///
/// Every spawned subcommand may append telemetry, and an unpinned run resolves
/// `metrics_dir()` to the *operator's real* ledger — creating it and writing
/// production-shaped rows there just for running the suite. Every other
/// integration test in this directory pins it; these must too.
fn isolated_cadence_hooks(metrics_dir: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    cmd.env("CADENCE_METRICS_DIR", metrics_dir);
    cmd
}

/// Spawn one hook subcommand with a payload on stdin, in a throwaway metrics
/// dir, and return `(exit code, stderr)`.
///
/// `env` is applied on top; `CADENCE_NO_FEEDBACK_FOOTER` is always set so
/// assertions read the guard's own text rather than the feedback footer.
fn run_hook(args: &[&str], env: &[(&str, &str)], payload: &str) -> (Option<i32>, String) {
    use std::io::Write;
    let metrics = tempfile::tempdir().expect("temp metrics dir");
    let markers = tempfile::tempdir().expect("temp marker dir");
    let mut cmd = isolated_cadence_hooks(metrics.path());
    cmd.args(args)
        .env("CADENCE_MARKER_DIR", markers.path())
        .env("CADENCE_NO_FEEDBACK_FOOTER", "1");
    for (key, value) in env {
        cmd.env(key, value);
    }
    let output = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(payload.as_bytes())?;
            child.wait_with_output()
        })
        .expect("run hook");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn live_manifest() -> Value {
    let metrics = tempfile::tempdir().expect("temp metrics dir");
    let output = isolated_cadence_hooks(metrics.path())
        .args(["manifest", "--format", "json"])
        .output()
        .expect("generate live hook manifest");
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).expect("manifest json")
}

#[test]
fn every_registered_hook_has_explicit_compatibility_and_evidence() {
    let value = report();
    let hooks = value["hooks"].as_array().expect("hooks");
    assert!(hooks.len() > 40);
    let report_names = hooks
        .iter()
        .map(|hook| hook["name"].as_str().expect("report hook name").to_string())
        .collect::<BTreeSet<_>>();
    let manifest_names = live_manifest()["hooks"]
        .as_array()
        .expect("manifest hooks")
        .iter()
        .map(|hook| {
            hook["name"]
                .as_str()
                .expect("manifest hook name")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        report_names, manifest_names,
        "checked-in compatibility report must match the live registry"
    );
    for hook in hooks {
        assert!(matches!(
            hook["status"].as_str(),
            Some("native" | "adapted" | "degraded" | "unavailable")
        ));
        assert!(
            hook["evidence"]
                .as_str()
                .is_some_and(|text| !text.is_empty())
        );
        if hook["status"] == "degraded" {
            assert_ne!(hook["criticality"], "security-critical");
        }
        if hook["applicable"] != false {
            assert!(
                hook["wiring"]
                    .as_array()
                    .is_some_and(|entries| !entries.is_empty()),
                "applicable hook lacks plugin wiring: {}",
                hook["name"]
            );
        }
        if hook["criticality"] == "security-critical" && hook["applicable"] != false {
            assert!(matches!(
                hook["status"].as_str(),
                Some("native" | "adapted")
            ));
        }
    }
}

#[test]
fn every_security_route_has_native_hook_or_sandbox_control() {
    let value = report();
    for capability in value["capabilities"].as_array().expect("capabilities") {
        if capability["criticality"] != "security-critical" || capability["applicable"] == false {
            continue;
        }
        assert!(matches!(
            capability["status"].as_str(),
            Some("native" | "adapted")
        ));
        assert!(
            capability["evidence"]
                .as_str()
                .is_some_and(|text| !text.is_empty())
        );
    }
}

/// Assert `evidence` is a `path::test_name` reference to a test that exists.
///
/// The pre-existing status assertions were tautological: the report is generated
/// from a hand-authored config, so checking that a status is `"adapted"` asserts
/// a checked-in JSON agrees with itself, and `evidence` was free text with no
/// referential integrity — `guard-rm`'s read `"crates/core/src/lib.rs"`, a bare
/// path naming no test and no function, and passed while the guard did not in
/// fact handle Codex deletion at all.
///
/// A status is a claim. This is the smallest constraint that makes a
/// security-critical `adapted` claim *checkable*: it must point at a named test,
/// in a file in this repo, that actually exists.
fn assert_evidence_names_a_real_test(label: &str, evidence: &str) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some((path, test)) = evidence.split_once("::") else {
        panic!(
            "{label}: security-critical `adapted` evidence must be `path::test_name`, \
             got {evidence:?} — a bare path names nothing a reader can verify"
        );
    };
    assert!(
        !test.is_empty() && test.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "{label}: evidence must end in a bare test-function name, got {test:?} \
         (prose after `::` reads as a reference and is not one)"
    );
    let source = fs::read_to_string(root.join(path)).unwrap_or_else(|error| {
        panic!("{label}: evidence names {path:?}, which does not exist here ({error})")
    });
    assert!(
        source_declares_test(&source, test),
        "{label}: evidence names {test}, which is not a #[test] in {path}"
    );
}

/// True when `source` declares `#[test] fn <name>`. Walks back from the `fn`
/// line over attributes, doc comments, and blanks so an intervening
/// `#[cfg(unix)]` or doc block does not hide the `#[test]`.
fn source_declares_test(source: &str, name: &str) -> bool {
    let lines: Vec<&str> = source.lines().collect();
    let signature = format!("fn {name}(");
    for (index, line) in lines.iter().enumerate() {
        if !line.trim_start().starts_with(&signature) {
            continue;
        }
        for above in lines[..index].iter().rev() {
            let above = above.trim();
            if above == "#[test]" {
                return true;
            }
            if above.is_empty() || above.starts_with("#[") || above.starts_with("//") {
                continue;
            }
            break;
        }
    }
    false
}

/// Every security-critical row claiming `adapted` must name a test that exists.
///
/// Covers both halves of the report: `hooks` (where the `guard-rm` false claim
/// lived) and `capabilities`. `native` rows are exempt — "the Claude path works
/// unchanged" is carried by that hook's own suite, not by a Codex-specific test
/// — and so are `applicable: false` rows, which claim no coverage at all.
#[test]
fn security_critical_adapted_rows_name_a_test_that_exists() {
    let value = report();
    let mut checked = 0;
    for (kind, key) in [("hook", "hooks"), ("capability", "capabilities")] {
        for row in value[key].as_array().expect(key) {
            if row["criticality"] != "security-critical"
                || row["status"] != "adapted"
                || row["applicable"] == false
            {
                continue;
            }
            let name = row["name"]
                .as_str()
                .or_else(|| row["id"].as_str())
                .expect("every row carries a name or an id");
            let evidence = row["evidence"].as_str().expect("evidence");
            assert_evidence_names_a_real_test(&format!("{kind} {name}"), evidence);
            checked += 1;
        }
    }
    assert!(
        checked >= 8,
        "expected the security-critical adapted set to be non-trivial, checked {checked}"
    );
}

/// The checker itself, in both directions — otherwise a bug that made
/// `source_declares_test` always return true would disarm the gate above
/// silently, which is the exact failure mode this whole test exists to close.
#[test]
fn evidence_checker_rejects_what_it_should() {
    let source = "#[test]\nfn real_one() {}\n\nfn not_a_test() {}\n";
    assert!(source_declares_test(source, "real_one"));
    assert!(!source_declares_test(source, "not_a_test"));
    assert!(!source_declares_test(source, "absent"));

    // An attribute or doc block between `#[test]` and `fn` must not hide it.
    let decorated = "#[test]\n#[cfg(unix)]\n/// doc\nfn guarded() {}\n";
    assert!(source_declares_test(decorated, "guarded"));

    // A bare path — the shape that let the `guard-rm` false claim ship.
    let bare = std::panic::catch_unwind(|| {
        assert_evidence_names_a_real_test("hook guard-rm", "crates/core/src/lib.rs")
    });
    assert!(bare.is_err(), "a bare path must be rejected");

    // Prose after `::` reads as a reference but is not one.
    let prose = std::panic::catch_unwind(|| {
        assert_evidence_names_a_real_test(
            "capability ask-outcomes",
            "crates/core/src/lib.rs::emit_and_exit converts Codex Ask to block",
        )
    });
    assert!(prose.is_err(), "prose after `::` must be rejected");

    // A well-formed reference to a test that does not exist.
    let missing = std::panic::catch_unwind(|| {
        assert_evidence_names_a_real_test(
            "hook fake",
            "crates/core/src/lib.rs::no_such_test_exists_anywhere",
        )
    });
    assert!(missing.is_err(), "a dangling test name must be rejected");
}

#[test]
fn security_critical_malformed_patch_blocks_without_echoing_patch() {
    let payload = r#"{"tool_name":"apply_patch","tool_input":"*** Begin Patch\nSECRET_VALUE\n*** End Patch"}"#;
    let metrics = tempfile::tempdir().expect("temp metrics dir");
    let output = isolated_cadence_hooks(metrics.path())
        .args(["cadence", "prevent-secret-writes"])
        .env("CADENCE_HARNESS", "codex")
        .env("CADENCE_NO_FEEDBACK_FOOTER", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(payload.as_bytes())?;
            child.wait_with_output()
        })
        .expect("run guard");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("targets could not be enumerated"));
    assert!(!stderr.contains("SECRET_VALUE"));
}

/// The `Ask` → `Block` conversion, spawned end to end.
///
/// This is one of the two behaviours that exist to stop Codex failing open, and
/// it had no coverage at all: `emit_and_exit`'s Ask check is reachable only
/// through the binary, and the one `CADENCE_HARNESS=codex` test in this file
/// exercised the *other* branch (`dispatch::codex_fail_closed`). Codex has no
/// interactive Ask channel, so an `Ask` that exits 0 lets the operation proceed
/// unconfirmed — a silent fail-open in the guard tier built to ask.
///
/// `guard-rm` is the only `Ask` producer; an unexpanded variable in the target
/// is its canonical unresolvable case.
#[test]
fn codex_ask_outcome_converts_to_a_block() {
    let payload = r#"{"tool_name":"Bash","cwd":"/private/tmp","tool_input":{"command":"rm -rf $UNKNOWN/data"}}"#;

    let (code, stderr) = run_hook(
        &["guardrails", "guard-rm"],
        &[("CADENCE_HARNESS", "codex")],
        payload,
    );
    assert_eq!(code, Some(2), "an Ask under Codex must exit 2");
    assert!(
        stderr.contains("cannot hand an Ask decision"),
        "block must explain why the Ask was converted: {stderr}"
    );

    // The control that makes the assertion mean something: the same payload
    // under Claude Code stays an Ask (exit 0), so this test is pinning the
    // conversion rather than a guard that blocks unconditionally.
    let (code, _) = run_hook(&["guardrails", "guard-rm"], &[], payload);
    assert_eq!(code, Some(0), "an Ask under Claude Code still exits 0");
}

/// The stdin-parse fail-closed arm (`dispatch.rs`), the sibling of the
/// patch-normalization arm `security_critical_malformed_patch_blocks_…` covers.
/// Both are short, and both are the difference between exit 0 and exit 2 on a
/// security-critical hook.
#[test]
fn security_critical_unparseable_stdin_blocks_under_codex() {
    let (code, stderr) = run_hook(
        &["cadence", "prevent-secret-writes"],
        &[("CADENCE_HARNESS", "codex")],
        "this is not JSON at all",
    );
    assert_eq!(code, Some(2));
    assert!(
        stderr.contains("could not be parsed"),
        "block must name the parse failure: {stderr}"
    );

    // A non-security-critical hook keeps failing open on the same input.
    let (code, _) = run_hook(
        &["guardrails", "warn-cron-datetime"],
        &[("CADENCE_HARNESS", "codex")],
        "this is not JSON at all",
    );
    assert_eq!(code, Some(0));
}

/// `prevent-secret-writes` genuinely adapts to patches: a secret introduced by
/// an `apply_patch` `Add File` is blocked exactly as the plain `Write` is.
#[test]
fn patch_add_file_carrying_a_secret_is_blocked() {
    let secret = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
    let patch = format!("*** Begin Patch\n*** Add File: config.env\n+{secret}\n*** End Patch");
    let payload = serde_json::json!({
        "tool_name": "apply_patch",
        "cwd": "/private/tmp",
        "tool_input": patch,
    })
    .to_string();
    let (code, stderr) = run_hook(
        &["cadence", "prevent-secret-writes"],
        &[("CADENCE_HARNESS", "codex")],
        &payload,
    );
    assert_eq!(code, Some(2), "a patched-in secret must block: {stderr}");

    // Control: the same guard on the same content through a plain Write. If
    // this did not block, the assertion above would prove nothing about the
    // patch route.
    let write = serde_json::json!({
        "tool_name": "Write",
        "cwd": "/private/tmp",
        "tool_input": {"file_path": "config.env", "content": secret},
    })
    .to_string();
    let (code, _) = run_hook(&["cadence", "prevent-secret-writes"], &[], &write);
    assert_eq!(code, Some(2), "control: the plain Write must block too");
}

/// `guard-dotfiles` sees a patch target: an `apply_patch` writing a managed
/// dotfile blocks, because normalization hands the guard a `file_path` it can
/// judge.
///
/// Unix-only, and deliberately so rather than for convenience. `judge_dotfile`
/// builds its comparison path with a forward slash (`{home}/{basename}`), while
/// `patch::clean_path` rewrites `\` to `/` on the way in — so on Windows the two
/// sides disagree (`C:\Users\x/.zshrc` vs `C:/Users/x/.zshrc`) and the guard
/// never matches. That asymmetry is real but out of scope here: the guard exists
/// for chezmoi-managed dotfiles (`~/.dotfiles/dot_zshrc`, `chezmoi apply`), a
/// workflow that does not run on Windows. Gating keeps this test honest about
/// what it covers instead of asserting a platform behaviour nobody ships.
#[test]
#[cfg(unix)]
fn patch_target_reaches_guard_dotfiles() {
    // Not `std::env::var("HOME")` — the guards resolve the home directory
    // through this helper, so the test asks the same way they do.
    let home = cadence_hooks_core::paths::user_home_lossy_or_default();
    let patch =
        format!("*** Begin Patch\n*** Update File: {home}/.zshrc\n@@\n-old\n+new\n*** End Patch");
    let payload = serde_json::json!({
        "tool_name": "apply_patch",
        "cwd": "/private/tmp",
        "tool_input": patch,
    })
    .to_string();
    let (code, stderr) = run_hook(
        &["guardrails", "guard-dotfiles"],
        &[
            ("CADENCE_GUARD_DOTFILES", "1"),
            ("CADENCE_HARNESS", "codex"),
        ],
        &payload,
    );
    assert_eq!(code, Some(2), "a patched dotfile must block: {stderr}");

    // Control: with the guard's opt-in unset, the same patch passes — so the
    // block above is guard-dotfiles deciding, not the patch route erroring.
    let (code, _) = run_hook(
        &["guardrails", "guard-dotfiles"],
        &[("CADENCE_HARNESS", "codex")],
        &payload,
    );
    assert_eq!(code, Some(0));
}

/// A Codex local function call traverses the common PreToolUse path and reaches
/// a security-critical guard — the `nested-function-calls` capability claim,
/// asserted against the binary rather than restated as prose.
#[test]
fn codex_local_function_call_reaches_a_security_critical_guard() {
    // Not `std::env::var("HOME")` — that is unset on Windows, where the home
    // directory comes from USERPROFILE. The guards resolve it through this
    // helper, so the test asks the same way they do.
    let home = cadence_hooks_core::paths::user_home_lossy_or_default();
    let payload = serde_json::json!({
        "tool_name": "exec_command",
        "cwd": "/private/tmp",
        "tool_input": {"cmd": format!("rm -rf {home}/Documents")},
    })
    .to_string();
    let (code, stderr) = run_hook(&["guardrails", "guard-rm"], &[], &payload);
    assert_eq!(
        code,
        Some(2),
        "a Codex local function call must reach guard-rm: {stderr}"
    );
    assert!(stderr.contains("guard-rm"));
}

/// `ObsidianTrashGuard`'s delete-detection branch, driven through the binary.
///
/// The guard's new `operation() == Some("delete")` arm was unit-tested only at
/// the `check_delete_in_vault` helper — the pre-existing-shaped half — so the
/// dispatch wiring this PR actually changed (a patch normalizing into an `Edit`
/// carrying `operation: "delete"`, reaching `run()`) was never exercised end to
/// end.
#[test]
fn patch_delete_inside_a_vault_reaches_the_trash_guard() {
    let vault = tempfile::tempdir().expect("temp vault");
    let vault_path = vault.path().to_string_lossy().into_owned();
    let patch =
        format!("*** Begin Patch\n*** Delete File: {vault_path}/notes/todo.md\n*** End Patch");
    let payload = serde_json::json!({
        "tool_name": "apply_patch",
        "cwd": &vault_path,
        "tool_input": patch,
    })
    .to_string();

    let (code, stderr) = run_hook(
        &["obsidian", "trash-guard"],
        &[("OBSIDIAN_VAULT", vault_path.as_str())],
        &payload,
    );
    assert_eq!(code, Some(2), "a patch delete in the vault must block");
    assert!(
        stderr.contains(".trash"),
        "block must point at the vault's trash: {stderr}"
    );

    // Control: the same patch with no vault configured passes, so the block
    // above is the vault check deciding rather than the route erroring.
    let (code, _) = run_hook(&["obsidian", "trash-guard"], &[], &payload);
    assert_eq!(code, Some(0));
}

#[test]
fn multi_file_patch_normalizes_all_targets() {
    let input = HookInput::from_json(
        r#"{"tool_name":"apply_patch","tool_input":"*** Begin Patch\n*** Add File: one\n+x\n*** Delete File: two\n*** End Patch"}"#,
    )
    .unwrap();
    let paths = input
        .normalized_inputs()
        .unwrap()
        .into_iter()
        .filter_map(|item| item.file_path())
        .collect::<Vec<_>>();
    assert_eq!(paths, ["one", "two"]);
}

#[test]
fn sandbox_fixture_identifies_symlink_and_traversal_escape_targets() {
    let temp = tempfile::tempdir().unwrap();
    let outside = temp.path().join("outside");
    fs::write(&outside, "protected").unwrap();
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let workspace = fs::canonicalize(workspace).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&outside, workspace.join("escape")).unwrap();

        // Canonicalized writes through a workspace symlink resolve outside the
        // allowed root. Windows runners do not create this Unix symlink.
        let symlink_target = fs::canonicalize(workspace.join("escape")).unwrap();
        assert!(!symlink_target.starts_with(&workspace));
    }

    // Lexical traversal resolves outside the allowed root on every platform.
    let traversal = fs::canonicalize(workspace.join("../outside")).unwrap();
    assert!(!traversal.starts_with(&workspace));
}

#[test]
fn paired_harness_fixtures_cover_and_normalize_every_route() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut expected_routes = None;
    for harness in ["claude", "codex"] {
        let fixture = fs::read_to_string(
            root.join("tests/fixtures/harness")
                .join(format!("{harness}.jsonl")),
        )
        .unwrap();
        let mut routes = Vec::new();
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let route = row["route"].as_str().unwrap();
            routes.push(route.to_string());
            if route == "malformed" {
                assert!(HookInput::from_json(row["payloadRaw"].as_str().unwrap()).is_err());
                continue;
            }
            let raw = row["payload"].to_string();
            if route == "lifecycle-events" {
                let input = MetricsInput::from_json(&raw).unwrap();
                assert_eq!(input.hook_event_name.as_deref(), Some("SessionEnd"));
                continue;
            }
            let input = HookInput::from_json(&raw).unwrap();
            if harness == "codex" && matches!(route, "shell" | "unified-exec") {
                assert_eq!(input.normalized_tool_name(), Some("Bash"));
                assert!(input.command().is_some());
            }
            if harness == "codex" && route == "subagents" {
                assert_eq!(input.normalized_tool_name(), Some("Agent"));
            }
            if harness == "codex" && route == "mcp-filesystem-write" {
                assert_eq!(input.normalized_tool_name(), Some("Write"));
                assert_eq!(input.operation(), Some("create"));
            }
            if harness == "codex" && route == "mcp-functions" {
                assert_eq!(input.normalized_tool_name(), Some("Read"));
                assert_eq!(input.operation(), Some("read"));
            }
            if harness == "codex" && route == "apply-patch" {
                assert_eq!(input.normalized_inputs().unwrap().len(), 1);
            }
        }
        if let Some(expected) = &expected_routes {
            assert_eq!(&routes, expected);
        } else {
            expected_routes = Some(routes);
        }
    }
}
