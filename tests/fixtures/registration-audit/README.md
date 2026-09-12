# Registration-audit manifest fixture

A checked-in copy of every `BINARY_PLUGIN_DIRS` plugin's `hooks.json`, laid out
as a workspace root so `tests/hook_registration_audit.rs` resolves it with the
same code that resolves a developer's sibling checkout.

## Why it exists

The audit cross-references this binary's subcommands against the plugin wiring.
That wiring lives in the `cameronsjo/cadence` monorepo — a separate, private
repository CI does not check out. Before this fixture, every wiring assertion
returned early on CI and the suite reported 20 passing tests having asserted
nothing (cadence-hooks#909 fixed the *skip* logic; it could not supply a subject
to assert against). The fixture is that subject, so the assertions gate a PR.

## What is redacted

Every hook's `if:` **value** is replaced with a placeholder. The audit reads only
whether an `if:` key is *present* (`bash_hooks_have_if_filter`), never its
content, so redaction costs no coverage. The values are per-guard command
prefilters — publishing the complete set here would publish, by omission, the
exact list of commands each guard never sees. Everything else is verbatim.

`fixture_manifests_match_the_monorepo_default_branch` applies the same redaction
to the live manifest before comparing, so the drift check is unaffected.

## Refreshing it

Run from the workspace root that holds both checkouts:

```bash
git -C cadence fetch origin
bash cadence-hooks/scripts/refresh-registration-audit-fixture.sh
```

`origin/main` is only as current as the last fetch, which is why the fetch is
step one. The drift check compares against `origin/main` rather than the
sibling's working tree on purpose: a checkout parked on a feature branch or a
few commits behind would otherwise manufacture fixture drift.
