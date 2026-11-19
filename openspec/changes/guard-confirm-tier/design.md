## Context

A guard in the confirm tier asks "are you sure?" and lets a deliberate second attempt through. The threat model is ADR-0046's: a cooperative model making an honest mistake. A retry is the decision the tier asks for, so nothing here resists a model that retries on purpose. What it does prevent is a pass reaching something that did not decide: another session, another agent, or a different action.

## Decisions

### The key

`SHA-256(hook ␟ session_id ␟ agent_id ␟ action)`, with U+001F as the separator and `agent_id` empty on the main thread (a subagent shares its parent's `session_id`, so the agent id is what keeps its pass its own). The digest names the marker (`confirm-<digest>` in the private per-user marker directory) and is repeated inside it, so a file left under another name never counts.

The action is what the guard already extracted, never the raw command text, which is rarely byte-identical on a retry:

| Guard | Action |
|---|---|
| `enforce-worktree` | judged repo root, plus the file path (Edit, Write) or `git commit` (Bash) |
| `guard-op-vault-scan` | the sorted scans read: `op item list` / `op vault list`, with the `--vault` each names |
| `guard-held-close` | the sorted held entries the close would hit (`owner/repo#N …`) |

### One tool call, several processes

A hook wired twice under one matcher (`guard-op-vault-scan` is, for `Bash(*op item*)` and `Bash(*op vault*)`) spawns two processes for one tool call. A presence-only marker would let the second process of the first attempt pass on the first process's marker, and the tool call would still be denied by the first; the retry would then find the marker consumed and block again, forever. So the marker records the `tool_use_id` that wrote it, in one of two states:

- `pending <call>`: a process of the same call blocks and writes nothing; a process of a later call passes and rewrites the marker as `consumed <its call>`.
- `consumed <call>`: a process of the same call passes (it is the same retry); a later call writes a new `pending` and blocks.

Every write is idempotent for the processes of one call, so sibling races end in the same verdict for all of them. Single use falls out of the second state.

### Lifetime

Ten minutes from the blocked attempt (`CONFIRM_TTL`). The stamp is written into the marker; a stamp more than 60 seconds in the future reads as invalid. An expired marker is replaced by a new `pending`, and that attempt blocks.

### The ledger row

The pass returns an allow with `BypassProvenance { kind: Confirmed, mechanism: "confirm-retry", armed_by_session }`, and the dispatch seam writes the `used` row as for any bypass: hook, tool, repo basename, session, agent, `kind: "confirmed"`. No command text or path, per the ledger privacy rule. For `enforce-worktree` the mechanism reads `confirm-retry (dismiss-enforce-worktree 30m)` and `expiresAt` is the snooze end, when the snooze write succeeded.

### Fail directions

A pass needs a recorded decision, so every doubt blocks; and a block that cannot be confirmed says so.

| Condition | Verdict | Message ends with |
|---|---|---|
| No `session_id` (or empty) | block, nothing written | "A second attempt will be blocked too: …" |
| No `tool_use_id` (Codex payloads, a hand probe) | block, nothing written | same |
| Marker directory fell back to the shared temp base (not private) | block, marker never read or written | same |
| Marker unreadable, a symlink, malformed, under another key, expired, or future-stamped | treated as absent: new `pending`, block | "Are you sure? … run the same action again" |
| `pending` write fails | block | "A second attempt will be blocked too: the confirmation could not be recorded" |
| `consumed` write fails on a retry | block, the `pending` marker is left as it was | same |

The failed write is the case that could loop: told to retry, the model retries, finds no marker, and is told to retry again. Instead the message names the failure and sends the model to the guard's other route or to the operator, and no write failure ever produces a pass. A later retry whose write works still passes, because a failed `consumed` write leaves the `pending` marker intact.

### enforce-worktree arms the dismiss snooze

Decision 3 of the owner's brief: a confirmed retry arms the existing snooze (the marker and sidecar `dismiss-enforce-worktree --for 30m` writes), through one shared writer, so there is no second mechanism. Consequence: after the confirmed edit, later edits and commits in that checkout ride the snooze for 30 minutes and are recorded as `dismissal` bypasses, exactly as after a dismiss; and the snooze is per checkout, so it covers every session in that checkout, as a dismiss does. The confirm pass itself is still per session, agent and action. If the snooze write fails, the confirmed action passes and the next one blocks again.

Only the block `assess_dir` returns for a primary checkout qualifies. The guard records each such block on its git probe, and the confirm step matches the final block's message against them by prefix (the cd and worktree hints are appended to it). Blocks about a command the guard could not read (a symlink created in the same command, an unresolved `cd`) keep blocking with no confirm line.

### guard-browser-device stays

Its handshake blocks the first Chrome action of a session and then opens every later one, whatever the tool. The tier is per action and single use, so moving it would block every new Chrome action once, which is more friction for no gain. It keeps its own marker.

## Risks

- A model that retries without reading the message passes on the second try. Accepted: ADR-0046 rule 1, and the reason the owner asked for this.
- A hard-coded ten minutes. If the operator wants it tunable, that is a later change.
