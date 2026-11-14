//! The identity term source is found through the account database, not `HOME`
//! or `USERPROFILE` (cameronsjo/cadence-hooks#1617).
//!
//! A repo's settings `env` block reaches every hook process and can set either
//! variable. These run the real binary with both pointed at an empty directory,
//! set on the child only, and assert the tier still looks in the account's own
//! home: the passwd entry on unix, the profile known folder on Windows.

mod support;

use std::process::Output;

fn status_with_home(home: &std::path::Path) -> Output {
    support::cadence_hooks()
        .args(["cadence", "redact-scan", "--status"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .output()
        .expect("run cadence-hooks")
}

#[cfg(any(unix, windows))]
#[test]
fn an_empty_home_does_not_move_the_term_source() {
    let account = cadence_hooks_core::paths::account_home()
        .expect("the account database names a home directory on this platform");
    let empty = tempfile::tempdir().expect("temp HOME");
    let out = status_with_home(empty.path());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let expected = account
        .join(".config")
        .join("cadence")
        .join("redaction.toml");
    assert!(
        stdout.contains(&expected.display().to_string()),
        "the report must name the account home's term source {}: {stdout}",
        expected.display()
    );
    assert!(
        !stdout.contains(&empty.path().display().to_string()),
        "the report must not look under the HOME the env set: {stdout}"
    );
    // Where this machine has a term source, the tier is still armed with an
    // empty HOME: the disarm itself, end to end.
    if expected.is_file() {
        assert!(stdout.contains("tier: ARMED"), "{stdout}");
        assert_eq!(out.status.code(), Some(0), "{stdout}");
    }
}
