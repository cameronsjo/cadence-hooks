# Negative-testing a guard

Loaded from `developing-guards` § Writing tests. It applies to any check whose
job is to go red: a cadence-hooks guard, a repo lint, a policy assertion over a
config tree. The principle is the always-on § *The verifier is code too* in
cadence's rules; this is the procedure for it.

A guard that cannot fail reads as proof while proving nothing. You find that
out by mutating its input and demanding red, not by reading the guard. In one
session three fail-opens measured `PASS` against the real tree before the
assertions that catch them existed: a NetworkPolicy dropped from its
kustomization, an extra `Group` subject on a secrets-bearing RoleBinding, and
`secrets` added to a ClusterRole. A fourth sat in the fix itself: the new check
matched the literal `secrets` but not `resources: ["*"]`.

## The loop

1. **Write the detector, then the mutation that should trip it.** One case per
   detector, each the smallest edit that commits exactly the violation it
   forbids.
2. **Run the baseline first.** The unmutated tree must pass. If it already fails,
   every case goes red for the wrong reason, so abort instead of reporting the
   cases.
3. **Apply one mutation and prove it applied.** Compare the file before and
   after. A substitution that matches nothing leaves the file unchanged, and the
   case then tests the clean tree.
4. **Demand red for this detector.** Assert the non-zero exit *and* that the
   output names the rule you broke. A red from an unrelated rule is not this
   case passing.
5. **Restore, then run the next case.** Finish with the baseline again, which
   must still pass.
6. **A green mutation is a defect in the guard.** Fix the guard and keep the
   case. It is the regression test for that fix.

## Mutate a copy, not the checkout

Restoring with `git checkout -- <file>` discards any uncommitted work in that
file; in the run that wrote the harness above it silently ate two review fixes.
Mutate a scratch copy of the tree, so there is nothing to restore. If the
harness has to mutate in place, it must refuse to start on a dirty tree.

```bash
#!/usr/bin/env bash
set -euo pipefail
lint=(./scripts/lint-policy.sh)   # the guard under test; exits non-zero on a violation
src="$(git rev-parse --show-toplevel)"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
cp -R "$src/." "$work/"; cd "$work"
fails=0

"${lint[@]}" > base.log 2>&1 || { echo "ABORT baseline already red"; cat base.log; exit 1; }

case_red() { # $1 = case name, $2 = file, $3 = perl substitution, $4 = rule name the lint must print
  cp "$2" "$2.orig"
  perl -0pi -e "$3" "$2"
  if cmp -s "$2" "$2.orig"; then echo "BROKEN $1: mutation did not apply"; fails=$((fails + 1))
  else
    rc=0; "${lint[@]}" > case.log 2>&1 || rc=$?
    if [[ $rc -ne 0 ]] && grep -qF -- "$4" case.log; then echo "RED    $1"
    else echo "GREEN  $1: guard missed it (rc=$rc)"; fails=$((fails + 1)); fi
  fi
  mv "$2.orig" "$2"
  return 0
}

case_red wildcard-resources k8s/rbac.yaml 's/resources: \[[^]]*\]/resources: ["*"]/' 'cluster-role-secrets'

"${lint[@]}" > base.log 2>&1 || { echo "ABORT baseline red after restore"; exit 1; }
[[ $fails -eq 0 ]]
```

## Traps

- **The mutation did not happen.** `perl -pi`, `sed -i`, and `yq -i` all exit 0
  when the pattern matches nothing. Step 3's comparison is what catches it.
- **The exit code is not the verdict.** Some tools exit 0 whichever way they
  decide: `authelia crypto hash validate` reports a mismatch in its output and
  still exits 0. Read the tool's contract and assert on what actually carries
  the verdict.
- **The predicate has the wrong polarity.** An assertion written as
  `allowPrivilegeEscalation == True` reported correct manifests as failing.
  Run the check against one known-good and one known-bad input before trusting
  either verdict.
- **Only the literal form is tested.** Mutate the way someone would actually
  write the forbidden thing: the wildcard (`"*"`), the alias, the other key
  order, the second document in the file. The easiest spelling of a violation
  is the one most likely to slip past.

## Where this sits

For a cadence-hooks guard, the evasion tests in
[testing-patterns.md](testing-patterns.md) are this loop at the unit level: feed
the guard the violation it exists for and assert it blocks. To go the other way
and prove a Rust test suite covers a named control (break the code, demand a
test goes red), use `cadence-forge:mutation-sweeping`.
