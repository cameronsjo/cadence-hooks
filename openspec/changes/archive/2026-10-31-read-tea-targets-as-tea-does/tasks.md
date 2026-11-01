## 1. Read tea targets as tea does

- [x] 1.1 Read the tea target from `--repo`/`-r` only, first two slug parts; `-R` is `--remote`
- [x] 1.2 Judge a bare tea slug on the tea login hosts from tea's config, `--login` and `GITEA_INSTANCE_URL`
- [x] 1.3 Judge a tea write with no `--repo` on every git remote of the directory it runs in, following literal `cd`s
- [x] 1.4 Name `--repo` and the host rule in tea block messages

## 2. Tests

- [x] 2.1 A test for each of the three refusal shapes in #1601, plus parser tests
- [x] 2.2 Stage each rule off once and confirm its test goes red
