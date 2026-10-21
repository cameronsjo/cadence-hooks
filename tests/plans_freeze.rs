//! `docs/plans/` takes no new plans (cadence-hooks#1446).
//!
//! cadence-hooks moved to OpenSpec on 2026-10-20: new work is an
//! `openspec/changes/<id>/` proposal, and the plans already in `docs/plans/`
//! finish in place. Every plan is named `YYYY-MM-DD-<slug>.md`, so a later
//! date, or a name without a date, is a new plan.

use std::fs;
use std::path::Path;

/// The last date a plan may carry.
const PLANS_FROZEN_AFTER: &str = "2026-10-20";

#[test]
fn docs_plans_takes_no_new_plans() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/plans");
    let entries = fs::read_dir(&dir).expect("read docs/plans");
    let mut rejected = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        // Editor and OS droppings (.DS_Store, swap files) are not plans.
        if name.starts_with('.') {
            continue;
        }
        let date = name.get(..PLANS_FROZEN_AFTER.len()).unwrap_or("");
        let dated = date.len() == PLANS_FROZEN_AFTER.len()
            && date.bytes().enumerate().all(|(i, b)| {
                if i == 4 || i == 7 {
                    b == b'-'
                } else {
                    b.is_ascii_digit()
                }
            });
        if !dated || date > PLANS_FROZEN_AFTER {
            rejected.push(name);
        }
    }
    assert!(
        rejected.is_empty(),
        "docs/plans/ takes no new plans (every plan here is named YYYY-MM-DD-*, dated {PLANS_FROZEN_AFTER} or earlier); propose the work as an OpenSpec change instead (openspec/changes/, see CLAUDE.md): {rejected:?}"
    );
}
