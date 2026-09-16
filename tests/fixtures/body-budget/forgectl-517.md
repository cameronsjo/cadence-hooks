Closes #498.

> **#515 has merged** (`e4c2009`), and this PR now targets `main`. It was stacked on #515 while that fix — a demonstrated RCE in the containment logic this feature reuses — was in review. The diff here is the feature plus two review findings from #515, described below.

## What it does

```sh
printf 'the-secret' | forgectl env set agentgateway.llm_key_hermes --sops
# added agentgateway.llm_key_hermes to secrets.sops.yaml
```

One key into a SOPS-encrypted YAML file, from piped stdin, a no-echo prompt, or `--clipboard`. The value never enters an argv, terminal output, or a transcript — the same guarantee `env set` already gives `.env`.

Both obvious alternatives break that. `sops set file '["a"]["b"]' '"value"'` puts the plaintext in argv — visible in `ps`, left in shell history, which is what #498 was filed about. `sops file` opens `$EDITOR` on the whole decrypted document.

**The mechanism.** `sops <file>` decrypts to a temp file, runs `$EDITOR`, and re-encrypts what comes back. `EDITOR` is forgectl re-invoking itself (a hidden `__sops-edit`), the key path travels in the child's environment, and the value travels as a **file whose path** is in the environment. The value itself is never an argument and never an environment variable.

## The diff stays reviewable, deliberately

The edit is line-wise text, not a YAML round-trip. Re-emitting reflows every block and reorders keys, and in an encrypted file every reflowed line is a ciphertext change — a one-key write would produce an unreviewable whole-file diff. Measured: a replace changes 3 lines (the value plus sops' `lastmodified` and `mac`), an add is 2 insertions and 1 deletion, and untouched values keep byte-identical ciphertext.

## Success means it landed *encrypted*

A decrypt round-trip alone cannot detect a cleartext write, because cleartext round-trips perfectly. So the driver also re-parses the ciphertext and requires the scalar at exactly that path to carry `ENC[AES256_GCM,`.

That check earns its place: with `unencrypted_suffix` in force, sops writes a matching key in **plaintext** beside its encrypted siblings. Measured live, and every encrypted file in the estate this targets carries that setting.

## Three brakes on a measured unbounded loop

sops answers a document it cannot parse by re-invoking its editor forever — **36,851 invocations and 8.4 MB of stderr in three minutes**, still going when killed. Each brake catches it somewhere different:

| Brake | Catches |
|---|---|
| `NormalizeValue` refuses C0 bytes and invalid UTF-8 | The value that *produces* the unparseable document |
| `__sops-edit` parses its own output, exits non-zero | The document, before sops sees it — one clean `rc=201`, file byte-identical |
| A counter file created `O_EXCL` | The second invocation, so a loop that starts dies on its first retry |

A 60s context deadline bounds the case none of the three can see: sops failing to parse for a reason the editor never touched.

## Target rules — both must hold, no escape hatch

- filename matches `*.sops.yaml`, `*.sops.yml`, `*.enc.yaml`, `*.enc.yml`, `secrets.yaml`, `secrets.yml`, `secrets.*.yaml`/`.yml`
- content carries a top-level `sops:` mapping

`--any-file` is **refused** with `--sops` rather than silently ignored. A SOPS file under another name is unreachable — a deliberate refusal: the alternative is an interactive confirmation, and that path is exactly where #515's defect lived. A rename costs less than the surface.

## Review round — three Criticals, all reproduced

A two-arm Opus review (security, correctness) over the finished branch found three Critical defects. None was a design mistake. All three were the same shape: **a check that looked right and could not go red on the case it existed for.**

**1. The encryption-rule check tested only the leaf.** sops applies these rules to a key *and its whole subtree*, so an ancestor decides the outcome. A path whose parent carried `_unencrypted` passed the check and the secret landed in plaintext, reported as success:

```
printf 'sk-…' | forgectl env set notes_unencrypted.token --sops
replaced notes_unencrypted.token in secrets.sops.yaml   # rc=0
notes_unencrypted:
    token: sk-…                                          # plaintext
```

Backwards, the same bug made an ancestor-scoped `encrypted_regex` refuse every key beneath the block it matched. `WouldStoreCleartext` now takes `[]string` and walks every segment — the signature change is the fix, because it makes the leaf-only call unwritable.

**2. The encrypted-at-path assertion was document-order dependent.** It scanned for the first line beginning `leaf + ":"` anywhere in the document, so any same-named encrypted key elsewhere satisfied it — and sops' own metadata always carries an encrypted `mac`, giving a leaf named `mac` a guaranteed false pass. Proven by reordering one write: identical input passed with the secret in plaintext, or correctly went red, depending only on which line came first. It resolves the path through `yaml.v3` now.

**3. A bare prefix match destroyed a colon-bearing sibling.** `a:b: 'v'` is valid YAML and decodes to the key `a:b`. Setting `a` matched that line, and since the replace cuts at the first colon the result was `a: 'new'` — another key and its encrypted value gone, reported as `replaced a`, passing every downstream check. `findLeaf` now requires a space or end-of-line after the colon.

## Deviations from the plan

| Deviation | Why |
|---|---|
| `exec.SensitiveRunner`, not `exec.Runner` | The plan's own step required capturing sops' output to a file, which `Runner` cannot do — and `runAndWrap` logs child stderr at `Error` level, where a parse error quoting `key: '<the secret>'` would land on disk |
| The target gate refuses rather than confirms | #515's review found the confirmation path carried an RCE, and its TTY probe reads stdin — making the plan's own piped example impossible |
| Three env vars, not five | The work directory is named once; every variable is a name an attacker could try to set |
| The nonce is **not** a privilege boundary | The plan claimed it was. A caller who can set the environment can create the files it names, and one who can exec forgectl can already write YAML with a shell. It bounds a *stray* invocation; the output validation and once-only counter are load-bearing |
| An error relay was added | The editor's refusals are the actionable ones and live only in the child, whose stderr is sops' stderr and unsurfaceable |
| The filename check precedes the existence check | Answering existence first turns a refused path into an existence oracle |

## Three comments corrected rather than deleted

Each claimed a control the code does not have — this repo's documented signature defect:

- `readOutcome`'s stated reason was wrong about which path reaches its default.
- `ReplaceSopsNonce` still called the nonce a privilege boundary, contradicting the two artifacts that correctly do not.
- The editor's write claimed a restated mode prevented a umask widening a file. `os.WriteFile` applies a mode only at creation.

## Two review findings from #515, fixed here

CodeRabbit raised three findings on #515. One was already fixed there (`dc8b7ef`); the other two land in this PR, because this branch contains that base and the `--sops` write path depends on exactly that lock correctness.

**`openLock` did not validate the descriptor it returned.** `withFileLock` Lstats the lock name and then opens it, and `O_NOFOLLOW` closes that window for a **symlink only** — a swap to a FIFO inside the same window is not a symlink, so nothing refused it. `flock` locks an open file description, so two writers holding locks on two FIFO inodes would both believe they held the lock, and the parse-and-write section that exists to prevent a lost update would stop preventing one. `openLock` now does the post-open regular-file check `openRegular` already did.

Proven with a negative control: with the check reverted, the new `fifo` subtest fails and the `symlink` subtest still passes — so the new check is what adds the FIFO refusal rather than restating `O_NOFOLLOW`.

The doc comment claiming the Lstat refused a FIFO was corrected, not deleted. It asserted a control the code did not have, which is this package's signature defect.

**Four refusal branches abandoned an open directory descriptor.** A `Target` owns a dirfd, and `resolveEnvTarget` returned an empty `Target` on four refusal paths without closing it, so a long-lived process refusing repeatedly retained one descriptor per attempt. Every refusal routes through one closure now; a caller-side `defer` gives no signal when a return is missed.

## Verification

```
gofmt -l .              # clean
go vet ./...            # clean
go test ./... -count=1  # all packages pass
golangci-lint run       # clean over this diff
FORGECTL_REQUIRE_SOPS_INTEGRATION=1 go test -run Integration ./internal/sops
```

`golangci-lint run` reports `0 issues`. It previously reported two inherited `internal/cli/pr_pick.go` errcheck findings: `main` rewrote that file in #516, so a branch predating that rewrite carries the older copy and `new-from-rev` reads those lines as newly added. Merging `main` up cleared them.

The macOS CI job installs `sops` and `age` from checksum-verified release assets rather than Homebrew. `brew install sops` cannot work on the self-hosted runner — its Homebrew prefix is owned by another user, so the step dies on `/opt/homebrew` not writable. The neighbouring tmux step survives only because tmux is already in the runner image and its `brew list` short-circuits.

**Gated integration tests** drive the real `sops` binary against a minted age identity: the byte-exact round-trip, the absent trailing newline from `--extract --output`, the diff shape with untouched values byte-identical, the `rc=200` idempotent case, and refusals leaving the file byte-identical. The gate was verified **in both directions** — with `sops` off `PATH` the tests skip by default and **fail** under `FORGECTL_REQUIRE_SOPS_INTEGRATION=1`, which CI sets. A CI step that installs a tool is a file anyone can edit in a PR; the env gate is what makes its removal go red.

**A property test** asserts that for twenty-five document shapes nobody designed around — anchors, merge keys, flow mappings, literal scalars, quoted and numeric keys, odd indents — `SetScalar` either refuses or leaves a parseable document with every key intact and the value reachable at the requested path.

**End to end against the built binary**: the ancestor case refuses with zero plaintext written, an ancestor-scoped `encrypted_regex` no longer falsely refuses, the ordinary path round-trips with siblings intact, the `sops` metadata block is unwritable, and no work directory or temp output file is left behind.

## Known residual, stated plainly

The work directory is a sibling of the target and therefore inside the repository, and there is **no signal handler** on this path. The staged plaintext and the decrypted read-back are now deleted the moment they are consumed, which shrinks the window to the span where the file must exist — but a `SIGINT` inside that span still skips the deferred cleanup. Reproduced on the first of forty kill attempts before the fix. A handler and a location outside the work tree are the remaining work; I did not fold them in because both add surface this diff has not reviewed.

## Where to start reading

`internal/sops/edit.go` is the line editor and the place a bug corrupts a file; `internal/sops/driver.go` is the sequence around it. `internal/cli/sops_edit.go` is the other half of the editor protocol.

Session-Id: 2d4b9aa6-61b9-4645-8591-016fae184f38
Model: claude-opus-5
Harness: claude-code 2.1.269
Machine: cf6e768835c7

🤖 Generated with [Claude Code](https://claude.com/claude-code)



<!-- This is an auto-generated comment: release notes by coderabbit.ai -->
## Summary by CodeRabbit

* **New Features**
  * Added `forgectl env set --sops` for securely updating values in supported SOPS-encrypted YAML files.
  * Supports dotted paths, secure input through prompts or clipboard, and clear added/replaced result reporting.
  * Protects encrypted files by validating targets, preserving ciphertext on failures, and refusing unsafe or unsupported edits.
  * Added a SOPS health check to `forgectl doctor`.

* **Documentation**
  * Added usage guidance, requirements, limitations, security considerations, and lock-file behavior for SOPS-backed environment updates.
<!-- end of auto-generated comment: release notes by coderabbit.ai -->
