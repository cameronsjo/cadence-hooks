//! Run the runner-pool workflow audit after a workflow file is edited
//! (cadence-hooks#1072).
//!
//! The path-scoped `cicd.md` rule tells Claude to run
//! `cadence-forge:auditing-runner-pool-workflows`' `scripts/audit-workflows.py`
//! after editing `.github/workflows/*.y{a,}ml`. Nothing enforced that. This
//! PostToolUse check runs the audit and hands its findings back as a nudge.
//!
//! **Never blocks (ADR-0001).** Every way the audit can fail to run — script
//! absent, no `python3`, spawn error, timeout, exit 2 — degrades: absent script
//! and spawn trouble are silent, and the audit's own exit 2 ("could not run",
//! never a clean result) becomes a one-line note. Only exit 1 (a FAIL finding)
//! carries the findings.
//!
//! **The script is located, never configured.** It is executed, so the only
//! place searched is the plugin cache under Claude's config dir; an env var or
//! a repo-relative path would let a repo's `.envrc` or checkout choose the code
//! that runs. The cache layout is `plugins/cache/<marketplace>/cadence-forge/
//! <sha>/skills/auditing-runner-pool-workflows/scripts/audit-workflows.py`; the
//! newest match wins.

use cadence_hooks_core::display::{HOOK_OUTPUT_BUDGET_UTF16, clamp_hook_output, sanitize_field};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

/// Wall-clock cap on the audit. Under the 5s hooks.json timeout.
const AUDIT_TIMEOUT: Duration = Duration::from_millis(3500);

/// Longest single findings line echoed back.
const MAX_LINE: usize = 400;

const SCRIPT_SUFFIX: [&str; 4] = [
    "skills",
    "auditing-runner-pool-workflows",
    "scripts",
    "audit-workflows.py",
];

/// Runs the runner-pool audit when a workflow file is written or edited.
pub struct AuditRunnerPool;

impl Check for AuditRunnerPool {
    fn name(&self) -> &str {
        "audit-runner-pool"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        if !matches!(
            input.normalized_tool_name(),
            Some("Write" | "Edit" | "MultiEdit")
        ) {
            return CheckResult::allow();
        }
        let Some(path) = input.file_path() else {
            return CheckResult::allow();
        };
        let path = crate::warn_live_memory_write::anchor_to_cwd(&path, input.cwd.as_deref());
        let Some(root) = workflow_repo_root(&path) else {
            return CheckResult::allow();
        };
        let cache = cadence_hooks_core::paths::claude_config_dir()
            .join("plugins")
            .join("cache");
        audit(&root, &cache, AUDIT_TIMEOUT)
    }
}

/// The repo root when `path` is a workflow file directly under
/// `<root>/.github/workflows/` with a `.yml`/`.yaml` extension. Pure.
///
/// Segment-based, so `.github/workflows/sub/x.yml` (GitHub ignores it) and
/// `docs/.github-workflows/x.yml` never match; `.`/`..` are resolved first.
pub fn workflow_repo_root(path: &str) -> Option<PathBuf> {
    let absolute = path.starts_with('/') || path.starts_with('\\');
    let mut parts: Vec<&str> = Vec::new();
    for c in path.split(['/', '\\']) {
        match c {
            "" | "." => {}
            ".." if parts.last().is_some_and(|l| *l != "..") => {
                parts.pop();
            }
            v => parts.push(v),
        }
    }
    let n = parts.len();
    if n < 3 || parts[n - 3] != ".github" || parts[n - 2] != "workflows" {
        return None;
    }
    let file = parts[n - 1].to_ascii_lowercase();
    if !(file.ends_with(".yml") || file.ends_with(".yaml")) || file == ".yml" || file == ".yaml" {
        return None;
    }
    let joined = parts[..n - 3].join("/");
    Some(PathBuf::from(if absolute {
        format!("/{joined}")
    } else {
        joined
    }))
}

/// The newest `audit-workflows.py` under `<cache>/*/cadence-forge/*/`, by mtime.
pub fn find_script(cache: &Path) -> Option<PathBuf> {
    let mut best: Option<(SystemTime, PathBuf)> = None;
    for marketplace in std::fs::read_dir(cache).ok()?.flatten() {
        let forge = marketplace.path().join("cadence-forge");
        let Ok(versions) = std::fs::read_dir(&forge) else {
            continue;
        };
        for version in versions.flatten() {
            let script = SCRIPT_SUFFIX
                .iter()
                .fold(version.path(), |p, seg| p.join(seg));
            let Ok(meta) = std::fs::metadata(&script) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            if best.as_ref().is_none_or(|(t, _)| mtime > *t) {
                best = Some((mtime, script));
            }
        }
    }
    best.map(|(_, p)| p)
}

/// Locate the script under `cache`, run it against `root`, and translate the
/// exit code. Split from [`AuditRunnerPool::run`] so tests can supply both.
pub fn audit(root: &Path, cache: &Path, timeout: Duration) -> CheckResult {
    let Some(script) = find_script(cache) else {
        return CheckResult::allow();
    };
    let Some((code, stdout)) = run_script(&script, root, timeout) else {
        return CheckResult::allow();
    };
    match code {
        1 => CheckResult::nudge(render(
            "Runner-pool audit found problems in the edited workflow",
            &stdout,
        )),
        2 => CheckResult::nudge(render(
            "Runner-pool audit could not run (this is not a clean result)",
            &stdout,
        )),
        _ => CheckResult::allow(),
    }
}

/// Spawn `python3 <script> <root>` with a wall-clock cap. `None` on any spawn
/// trouble, a timeout, or death by signal. Stdout goes to a temp file, so a
/// chatty audit can never fill a pipe and stall against the poll loop.
fn run_script(script: &Path, root: &Path, timeout: Duration) -> Option<(i32, String)> {
    let out = tempfile::tempfile().ok()?;
    let mut reader = out.try_clone().ok()?;
    let mut child = Command::new("python3")
        .arg(script)
        .arg(root)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let code = status.code()?;
    use std::io::{Read, Seek, SeekFrom};
    let mut bytes = Vec::new();
    reader.seek(SeekFrom::Start(0)).ok()?;
    reader.take(256 * 1024).read_to_end(&mut bytes).ok()?;
    Some((code, String::from_utf8_lossy(&bytes).into_owned()))
}

/// Header plus the audit's output, one sanitized line at a time (the findings
/// quote workflow contents, which a repo controls), clamped to the hook budget.
fn render(header: &str, stdout: &str) -> String {
    let body: Vec<String> = stdout
        .lines()
        .map(|l| sanitize_field(l, MAX_LINE))
        .filter(|l| !l.trim().is_empty())
        .collect();
    let msg = if body.is_empty() {
        format!("{header}.")
    } else {
        format!("{header}:\n\n{}", body.join("\n"))
    };
    clamp_hook_output(&msg, HOOK_OUTPUT_BUDGET_UTF16, None).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::{make_edit, make_write};

    #[test]
    fn workflow_path_table() {
        let cases: &[(&str, Option<&str>)] = &[
            ("/r/.github/workflows/ci.yml", Some("/r")),
            ("/r/.github/workflows/ci.yaml", Some("/r")),
            ("/r/.github/workflows/CI.YML", Some("/r")),
            ("/r/x/../.github/workflows/ci.yml", Some("/r")),
            (".github/workflows/ci.yml", Some("")),
            ("/r/.github/workflows/ci.txt", None),
            ("/r/.github/workflows/.yml", None),
            ("/r/.github/workflows/sub/ci.yml", None),
            ("/r/.github/ci.yml", None),
            ("/r/github/workflows/ci.yml", None),
            ("/r/docs/.github/workflows-old/ci.yml", None),
            ("/r/ci.yml", None),
        ];
        for (path, want) in cases {
            assert_eq!(workflow_repo_root(path), want.map(PathBuf::from), "{path}");
        }
    }

    fn fake_cache(script_body: &str) -> tempfile::TempDir {
        let cache = tempfile::tempdir().unwrap();
        let dir = SCRIPT_SUFFIX[..3].iter().fold(
            cache
                .path()
                .join("workbench")
                .join("cadence-forge")
                .join("abc123"),
            |p, s| p.join(s),
        );
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(SCRIPT_SUFFIX[3]), script_body).unwrap();
        cache
    }

    #[test]
    fn missing_script_is_silent() {
        let cache = tempfile::tempdir().unwrap();
        let r = audit(Path::new("/r"), cache.path(), Duration::from_secs(2));
        assert!(matches!(r.outcome, Outcome::Allow));
        let gone = Path::new("/nonexistent/cache/dir");
        assert!(matches!(
            audit(Path::new("/r"), gone, Duration::from_secs(2)).outcome,
            Outcome::Allow
        ));
    }

    #[test]
    fn newest_script_wins() {
        let cache = fake_cache("print('old')");
        let dir = SCRIPT_SUFFIX[..3].iter().fold(
            cache
                .path()
                .join("workbench")
                .join("cadence-forge")
                .join("def456"),
            |p, s| p.join(s),
        );
        std::fs::create_dir_all(&dir).unwrap();
        let newer = dir.join(SCRIPT_SUFFIX[3]);
        std::fs::write(&newer, "print('new')").unwrap();
        let later = SystemTime::now() + Duration::from_secs(60);
        std::fs::File::options()
            .write(true)
            .open(&newer)
            .unwrap()
            .set_modified(later)
            .unwrap();
        assert_eq!(find_script(cache.path()), Some(newer));
    }

    #[cfg(unix)]
    #[test]
    fn exit_codes_map_to_verdicts() {
        // (script body, expects nudge, text the nudge must carry)
        let cases: &[(&str, bool, &str)] = &[
            ("import sys\nprint('ok')\nsys.exit(0)", false, ""),
            (
                "import sys\nprint('FAIL ci.yml: job x has no timeout')\nsys.exit(1)",
                true,
                "FAIL ci.yml: job x has no timeout",
            ),
            (
                "import sys\nprint('no YAML parser')\nsys.exit(2)",
                true,
                "could not run",
            ),
            ("import sys\nsys.exit(7)", false, ""),
            (
                "import os, signal\nos.kill(os.getpid(), signal.SIGKILL)",
                false,
                "",
            ),
        ];
        for (body, nudges, needle) in cases {
            let cache = fake_cache(body);
            let r = audit(Path::new("/r"), cache.path(), Duration::from_secs(5));
            match (&r.outcome, nudges) {
                (Outcome::Nudge, true) => {
                    let m = r.message.as_deref().unwrap_or_default();
                    assert!(m.contains(needle), "{body}: {m}");
                }
                (Outcome::Allow, false) => {}
                _ => panic!("{body}: unexpected outcome, message {:?}", r.message),
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn hung_audit_fails_open_within_the_timeout() {
        let cache = fake_cache("import time\ntime.sleep(30)");
        let t = Instant::now();
        let r = audit(Path::new("/r"), cache.path(), Duration::from_millis(300));
        assert!(matches!(r.outcome, Outcome::Allow));
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn findings_are_sanitized_and_clamped() {
        let cache = fake_cache(
            "import sys\nprint('FAIL a\\x1b[31m\\u200bb')\nprint('x' * 200000)\nsys.exit(1)",
        );
        let r = audit(Path::new("/r"), cache.path(), Duration::from_secs(5));
        assert!(matches!(r.outcome, Outcome::Nudge));
        let m = r.message.unwrap();
        assert!(!m.contains('\x1b') && !m.contains('\u{200b}'));
        assert!(m.chars().count() < 20_000, "{}", m.len());
    }

    #[test]
    fn non_workflow_and_non_write_inputs_allow_without_spawning() {
        for input in [
            make_write("/r/src/main.rs", "x"),
            make_edit("/r/README.md", "a", "b"),
        ] {
            assert!(matches!(
                AuditRunnerPool.run(&input).outcome,
                Outcome::Allow
            ));
        }
    }
}
