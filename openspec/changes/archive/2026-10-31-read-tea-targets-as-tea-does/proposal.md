## Why

`guard-forge-write` refused `tea pr create` on an owned Gitea repo three ways (cameronsjo/cadence-hooks#1601). Reading tea 0.16.0's source and running it showed the guard did not read `tea` the way tea does: tea's repo flag is `--repo`/`-r` and `-R` is `--remote` (a git remote name); tea keeps the first two parts of a slug, so `--repo git.sjo.lol/cameron/lectern` requests `/repos/git.sjo.lol/cameron`; a slug goes to the tea login's host; and with no `--repo` tea uses the repo of the directory it runs in, which the guard never read.

## What Changes

- The tea target is `--repo`/`-r`, read as tea reads it (first two parts; a URL or one-part slug is unreadable). `-R`/`--remote` names the git remote tea reads, never a repo.
- A bare tea slug is owned when it is owned on every tea login host: the `--login` one, else every login in tea's `config.yml` plus a `GITEA_INSTANCE_URL` host. `CADENCE_EXTRA_HOSTS` decides only when no login host is known. The guard reads only each login's `name` and `url` keys.
- A tea write with no `--repo` is judged on the git remotes of the directory it runs in (the payload `cwd` plus literal `cd`s, both the whole-command and per-segment readings): every remote, or the one `--remote` names, must be owned. No `cwd`, no repo, an unreadable remote or a `cd` the guard cannot read stays unresolvable. A git timeout fails open.
- Review (security and code) added refusals where the guard would otherwise judge something tea does not use: a `--repo`/`--owner` it cannot read literally, a `--repo` that is also a local directory, `repos create|delete` without `--owner`, a remote path that is not exactly `owner/repo` (tea reads the last two parts of an https remote), a tea config entry it cannot read, and a `GITEA_INSTANCE_URL` set outside the tea call's own prefix. `--login` and an env login move the host a directory remote is judged on, and `env -C` moves the directory.
- PR review (round 2): tea's flags are read as its urfave/cli parser reads them (one or two dashes, name or alias, `=` or the next word), and a near miss of a repo, login, remote or owner flag is refused. A tea config with any login the guard cannot read (including a compact list at the `logins:` key's column), or a `--login` naming no saved login, refuses and never falls back to `CADENCE_EXTRA_HOSTS`; only a missing config does. The `GITEA_INSTANCE_URL` refusal fires on an assignment, not a mention.
- Security review (round 3): tea's flag reading stops where urfave/cli stops (`--`, a lone `-`, or `-` plus a non-letter, such as a `- fixed` comment body). A config with content that yields no login (`logins :`, JSON, a BOM) is unreadable and refuses. An assignment in front of `tea` to `HOME`, `XDG_CONFIG_HOME` or a `GITEA_*` variable refuses.
- Review round 4: the value-flag list is tea 0.16's own for these writes, and an unknown flag followed by a `-` word refuses. The flag-stop test reads one byte, as tea does. An assignment, `export` or `unset` of `GITEA_INSTANCE_URL`, `HOME` or `XDG_CONFIG_HOME` anywhere in the command, or `env -i`/`env -u`, refuses. The inline `GITEA_*` refusal is narrowed to the variables tea reads. tea's own `logins: []` counts as no config.
- Tea block messages say `--repo owner/repo`, say `-R` is `--remote`, and name the reason. `glab` is unchanged.

## Impact

- Code: `crates/guardrails/src/guard_forge_write.rs`.
- Case 3 of the issue stays blocked: `--repo host/owner/repo` names owner `host` to tea, so allowing it would allow a write tea sends elsewhere.
