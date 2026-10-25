## 1. Guard

- [x] 1.1 Count a looped `gh repo archive|delete|edit|create` whose argument spells out its owner as naming its target, and leave it to the per-segment check
- [x] 1.2 Name the repository argument, not `-R`, in the loop block and single-command fixes for those verbs
- [x] 1.3 Pin the issue's loop (allowed from `/tmp`, an owned checkout, and under strict), an unowned literal owner, a variable owner, a bare name, a mixed loop and `gh repo rename`
- [x] 1.4 Step over the value of `--template` and `-p` under `gh repo create`, keep `gh repo edit --template` a boolean, and pin the single command and the loop
- [x] 1.5 Call an expanded target a repo you don't own only when `names_literal_unowned_owner` reads a literal owner the allowlist rejects, in the loop `-R` arm and the single command

## 2. Docs

- [x] 2.1 Update the loop and strict-loops paragraphs in `docs/configuration.md`
- [x] 2.2 Stage the CHANGELOG.md bullet under [Unreleased]
