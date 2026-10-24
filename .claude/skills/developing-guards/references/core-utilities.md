---
license: Apache-2.0 WITH Commons-Clause
---

# Core Utilities Reference

## Contents

- [shell module (`crates/core/src/shell.rs`)](#shell-module-cratescoresrcshellrs)
- [loop_analysis module (`crates/core/src/loop_analysis.rs`)](#loop_analysis-module-cratescoresrcloop_analysisrs)
- [config module (`crates/core/src/config.rs`)](#config-module-cratescoresrcconfigrs)

API reference for shared modules in `crates/core/src/`. These are the building blocks guards use for shell parsing, loop analysis, and config matching.

## shell module (`crates/core/src/shell.rs`)

### strip_quotes(s: &str) -> String

Removes content between matching `'` or `"` delimiters (including the delimiters). Unmatched quotes consume the rest of the string.

```rust
strip_quotes("gh pr create --title 'test' --body \"desc\"") // redaction-lint: allow — Rust fixture
// → "gh pr create --title  --body "  // redaction-lint: allow — expected output, not an instruction

strip_quotes("echo \"unterminated")
// → "echo "
```

**Use before substring matching** to avoid false positives on quoted content:

```rust
let stripped = strip_quotes(command);
let push_count = stripped.matches("git push").count();
```

### host_and_repo_from_url(url: &str) -> Option<(String, String)>

Extracts `(host, "owner/repo")` from any git remote URL format:

| Input | Output |
|---|---|
| `https://github.com/owner/repo.git` | `Some(("github.com", "owner/repo"))` |
| `git@github.com:owner/repo.git` | `Some(("github.com", "owner/repo"))` |
| `ssh://git@github.com/owner/repo.git` | `Some(("github.com", "owner/repo"))` |
| `https://token:x-oauth@github.com/owner/repo.git` | `Some(("github.com", "owner/repo"))` |
| `git@gitea.internal:cameron/cadence.git` | `Some(("gitea.internal", "cameron/cadence"))` |
| `not-a-url` | `None` |

Handles: credentials, ports, trailing slashes, subpaths, `.git` suffix stripping, host case normalization.

### repo_from_url(url: &str) -> Option\<String>

Convenience wrapper — returns just `"owner/repo"`, discarding the host.

### git_command(work_dir: &str, args: &[&str]) -> Option\<String>

Runs `git -C <work_dir> <args...>` and returns trimmed stdout on success. Returns `None` on failure or empty output.

```rust
git_command("/project", &["branch", "--show-current"])  // → Some("main")
git_command("/project", &["remote", "get-url", "origin"]) // → Some("https://...")
```

### parse_work_dir(command: &str, cwd: &str) -> String

Resolves the effective working directory from `cd` chains in a command:

```rust
parse_work_dir("cd /project && git push", "/home/user")
// → "/project"

parse_work_dir("cd repo && cd nested && git push", "/home/user")
// → "/home/user/repo/nested"

parse_work_dir("cd /fail || cd /recover && git push", "/home")
// → "/recover"  (cd before || is skipped — only runs on failure path)

parse_work_dir("git push origin main", "/home/user")
// → "/home/user"  (no cd → returns cwd unchanged)
```

Handles: `&&`, `;`, `||` operators, double-quoted paths, single-quoted paths, `~` expansion via `$HOME`, absolute vs relative paths.

**Important:** `cd` before `||` does NOT apply — those commands only run on the failure path, so the `cd` hasn't taken effect for subsequent commands.

### LOOP_PATTERN (LazyLock\<Regex>)

Detects shell loops: `for ... in` and `while ... do`.

```rust
LOOP_PATTERN.is_match("for repo in list; do git push; done")  // true
LOOP_PATTERN.is_match("while true; do git push; done")        // true
LOOP_PATTERN.is_match("git push origin main")                 // false
LOOP_PATTERN.is_match("echo information about this")          // false (word boundary)
```

Used as a regex fallback when the AST parser (`loop_analysis`) fails.

## loop_analysis module (`crates/core/src/loop_analysis.rs`)

AST-based analysis using `brush-parser`. Three entry points, each returning a purpose-built enum.

### analyze_gh_loops(command: &str) -> LoopAnalysis

Parses shell command, walks AST, finds `gh` commands inside loop bodies.

```rust
pub enum LoopAnalysis {
    NoLoops,                          // No loops found
    AllTargetsExplicit(Vec<LoopedCommand>),  // All gh commands have -R/--repo
    MissingTargets(Vec<LoopedCommand>),     // Some gh commands lack -R/--repo
    ParseFailed,                      // brush-parser couldn't parse
}

pub struct LoopedCommand {
    pub name: String,                 // "gh"
    pub explicit_repo: Option<String>, // Value of -R/--repo flag
    pub args: Vec<String>,            // All suffix arguments
}
```

Recurses into nested loops, brace groups, subshells, and if clauses. Python list comprehensions inside `gh api | python3 -c "..."` are NOT detected as shell loops (correct behavior).

### analyze_push_loops(command: &str) -> LoopAnalysis

Same as above but for `git push` commands. `explicit_repo` is the remote name (first positional arg after `push`, skipping flags).

### analyze_push_chain(command: &str) -> ChainAnalysis

Analyzes **top-level** (non-loop) `git push` commands in `&&`/`;`/`||` chains:

```rust
pub enum ChainAnalysis {
    SingleOrNone,                     // 0 or 1 push — nothing to analyze
    SameRemote(String),               // All pushes target same remote
    DifferentRemotes(Vec<LoopedCommand>), // Pushes target different remotes
    MissingRemotes(Vec<LoopedCommand>),   // Some pushes lack explicit remote
    ParseFailed,                      // brush-parser couldn't parse
}
```

**Key design:** Loop body pushes are excluded from chain analysis. They're handled by `analyze_push_loops()` separately. This prevents double-counting.

Recurses into brace groups, subshells, and if clauses but NOT into loops.

### Handling ParseFailed

When the AST parser fails, fall back to regex:

```rust
match loop_analysis::analyze_push_loops(command) {
    LoopAnalysis::MissingTargets(_) => {
        return CheckResult::block("...");
    }
    LoopAnalysis::ParseFailed => {
        // Regex fallback — less precise but safe
        let stripped = strip_quotes(command);
        if LOOP_PATTERN.is_match(&stripped) {
            return CheckResult::block("...");
        }
    }
    LoopAnalysis::AllTargetsExplicit(_) | LoopAnalysis::NoLoops => {}
}
```

**Never block on `ParseFailed` alone.** Always provide a fallback path — regex detection, substring counting, or `allow()`.

## config module (`crates/core/src/config.rs`)

### AllowEntry

Parsed allowlist entry supporting four formats:

```rust
pub struct AllowEntry {
    pub host: Option<String>,   // None = use default_host()
    pub owner: String,
    pub repo: Option<String>,   // None = allow all repos for this owner
}
```

| Entry string | host | owner | repo |
|---|---|---|---|
| `cameronsjo` | None | `cameronsjo` | None |
| `gitea.internal/cameron` | `gitea.internal` | `cameron` | None |
| `cameronsjo/cadence` | None | `cameronsjo` | `cadence` |
| `gitea.internal/cameron/cadence` | `gitea.internal` | `cameron` | `cadence` |

**Disambiguation heuristic:** When an entry has exactly one `/`, a dot in the first segment means host/owner; no dot means owner/repo. Git forge usernames never contain dots.

All values are lowercased on parse for case-insensitive matching.

### parse_allow_entry(entry: &str) -> AllowEntry

Parses a single entry string.

### parse_env_list(value: &str) -> Vec\<String>

Splits a string by whitespace or commas. Intentionally lenient — LLMs tend to generate comma-separated values where Unix convention expects space-separated.

```rust
parse_env_list("a b c")      // → ["a", "b", "c"]
parse_env_list("a,b,c")      // → ["a", "b", "c"]
parse_env_list("a, b, c")    // → ["a", "b", "c"]
parse_env_list("")            // → []
```

### env_allow_entries(var: &str) -> Vec\<AllowEntry>

Reads an env var and parses it as a list of `AllowEntry` values. Combines `parse_env_list()` and `parse_allow_entry()`.

```rust
// Given: GIT_GUARDRAILS_ALLOWED_OWNERS="cameronsjo gitea.internal/cameron"
let owners = env_allow_entries("GIT_GUARDRAILS_ALLOWED_OWNERS");
// → [AllowEntry{host:None, owner:"cameronsjo", repo:None},
//    AllowEntry{host:Some("gitea.internal"), owner:"cameron", repo:None}]
```

### default_host() -> String

Returns `GH_HOST` env var, falling back to `"github.com"`. Used when `AllowEntry.host` is `None`.

### is_allowed(host, owner, repo, owner_entries, repo_entries) -> bool

Checks if a `(host, owner, repo)` triple matches any entry in either the owner or repo allowlists. Repo entries are checked first (more specific). Bare entries (no host) match against `default_host()`.

```rust
let owners = env_allow_entries("GIT_GUARDRAILS_ALLOWED_OWNERS");
let repos = env_allow_entries("GIT_GUARDRAILS_ALLOWED_REPOS");

is_allowed("github.com", "cameronsjo", "repo", &owners, &repos)  // true
is_allowed("gitea.internal", "cameronsjo", "repo", &owners, &repos)  // false (bare entry defaults to github.com)
```

### AllowEntry Display

`AllowEntry` implements `Display` for block messages:

```rust
parse_allow_entry("cameronsjo").to_string()                    // "cameronsjo"
parse_allow_entry("gitea.internal/cameron").to_string()        // "gitea.internal/cameron"
parse_allow_entry("cameronsjo/cadence").to_string()            // "cameronsjo/cadence"
```

Use this when constructing the `Allowed:` line in block messages.
