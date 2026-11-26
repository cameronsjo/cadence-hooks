//! Scan code for known insecure patterns.
//!
//! Maintains a table of language-specific anti-patterns (pickle, innerHTML,
//! `shell=True`, unsafe Go imports, etc.) and warns when written code matches.

use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

/// A security pattern to check for in a specific file extension.
struct SecurityPattern {
    extensions: &'static [&'static str],
    pattern: &'static str,
    message: &'static str,
    /// When true, skip this pattern in test files (`*.test.*`, `*.spec.*`,
    /// `tests/`, `__tests__/`), where it is routine scaffolding rather than a
    /// security risk.
    skip_in_tests: bool,
}

const PATTERNS: &[SecurityPattern] = &[
    SecurityPattern {
        extensions: &["py"],
        pattern: r"pickle[.]loads",
        message: "RCE risk: use json or msgpack instead of pickle",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["py"],
        pattern: r"yaml[.]load[(]",
        message: "Use yaml.safe_load()",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["py"],
        pattern: r"shell\s*=\s*True",
        message: "Command injection risk: pass arg list to subprocess",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["py"],
        pattern: r"trust_remote_code\s*=\s*True",
        message: "Runs arbitrary code from model repos",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["py"],
        pattern: r"__import__[(]",
        message: "Arbitrary module loading",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["js", "jsx", "mjs", "cjs"],
        pattern: r"new\s+Function[(]",
        message: "Function() constructor can run arbitrary code",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["js", "jsx", "mjs", "cjs"],
        pattern: r"[.]innerHTML\s*=",
        message: "XSS risk: use textContent or sanitize first",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["js", "jsx", "mjs", "cjs"],
        pattern: r"Math[.]random[(][)]",
        message: "Not cryptographically secure",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["ts", "tsx"],
        pattern: r"[)\]}]\s+as\s+[A-Z]",
        message: "Type assertion bypasses validation",
        skip_in_tests: true,
    },
    SecurityPattern {
        extensions: &["go"],
        pattern: r#""text/template""#,
        message: "Use html/template for HTML output",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["go"],
        pattern: r#""math/rand""#,
        message: "Use crypto/rand for security-sensitive randomness",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["go"],
        pattern: r#""unsafe""#,
        message: "unsafe package -- document safety invariants",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["rs"],
        pattern: r"unsafe\s*[{]",
        message: "Ensure // SAFETY: comment and test with Miri",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["rs"],
        pattern: r"from_utf8_unchecked",
        message: "UB risk on external input",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["java"],
        pattern: r"ObjectInputStream",
        message: "Deserialization RCE -- use ObjectInputFilter",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["java"],
        pattern: r"java\.util\.Random(?:$|[^A-Za-z])",
        message: "Use SecureRandom for security-sensitive values",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["cs"],
        pattern: r"BinaryFormatter",
        message: "RCE vector, removed in .NET 9",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["cs"],
        pattern: r"TypeNameHandling",
        message: "Deserialization attack -- ensure TypeNameHandling.None",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["cs"],
        pattern: r"DtdProcessing[.]Parse",
        message: "XXE risk -- use DtdProcessing.Prohibit",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["swift"],
        pattern: r"UserDefaults.*(password|secret|token|apiKey)",
        message: "Store secrets in Keychain",
        skip_in_tests: false,
    },
    // Python — RCE / command injection
    SecurityPattern {
        extensions: &["py"],
        pattern: r"\beval\s*[(]",
        message: "RCE risk: eval() executes arbitrary code",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["py"],
        pattern: r"\bexec\s*[(]",
        message: "RCE risk: exec() runs arbitrary code",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["py"],
        pattern: r"\bos[.]system\s*[(]",
        message: "Command injection risk: use subprocess with an arg list",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["py"],
        pattern: r"pickle[.]load[(]",
        message: "RCE risk: use json or msgpack instead of pickle",
        skip_in_tests: false,
    },
    // JS/JSX — RCE / XSS
    SecurityPattern {
        extensions: &["js", "jsx", "mjs", "cjs"],
        pattern: r"\beval\s*[(]",
        message: "RCE risk: eval() executes arbitrary code",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["js", "jsx", "mjs", "cjs"],
        pattern: r"\bdocument[.]write\s*[(]",
        message: "XSS risk: avoid document.write()",
        skip_in_tests: false,
    },
    SecurityPattern {
        extensions: &["jsx", "tsx"],
        pattern: r"dangerouslySetInnerHTML",
        message: "XSS risk: sanitize before dangerouslySetInnerHTML",
        skip_in_tests: false,
    },
];

struct CompiledPattern {
    extensions: &'static [&'static str],
    regex: Regex,
    message: &'static str,
    skip_in_tests: bool,
}

static COMPILED_PATTERNS: LazyLock<Vec<CompiledPattern>> = LazyLock::new(|| {
    PATTERNS
        .iter()
        .filter_map(|sp| {
            Regex::new(sp.pattern).ok().map(|regex| CompiledPattern {
                extensions: sp.extensions,
                regex,
                message: sp.message,
                skip_in_tests: sp.skip_in_tests,
            })
        })
        .collect()
});

/// True when `path` is a test file (`*.test.*`, `*.spec.*`, or under
/// `tests/` / `__tests__/`).
fn is_test_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let filename = lower.rsplit('/').next().unwrap_or(&lower);
    if filename.contains(".test.") || filename.contains(".spec.") {
        return true;
    }
    lower
        .split('/')
        .any(|seg| seg == "__tests__" || seg == "tests")
}

/// Scan content for security anti-patterns matching the given file extension.
///
/// Returns `(line_number, message)` tuples for each violation found.
/// Pure function — no I/O.
pub fn scan_content(content: &str, ext: &str) -> Vec<(usize, &'static str)> {
    scan_content_filtered(content, ext, false)
}

fn scan_content_filtered(
    content: &str,
    ext: &str,
    in_test_file: bool,
) -> Vec<(usize, &'static str)> {
    // Skip regex table initialization altogether for extensions with no rules
    // (e.g. `.md`, `.json`, `.toml`, `.sh`).
    if !PATTERNS.iter().any(|sp| sp.extensions.contains(&ext)) {
        return Vec::new();
    }

    let mut warnings = Vec::new();

    for sp in COMPILED_PATTERNS.iter() {
        if !sp.extensions.contains(&ext) || (in_test_file && sp.skip_in_tests) {
            continue;
        }

        for m in sp.regex.find_iter(content) {
            // Count newlines, not lines: a partial line before the match
            // ("data = " before "pickle.loads") must not add a line.
            let line_num = content[..m.start()].matches('\n').count() + 1;
            warnings.push((line_num, sp.message));
        }
    }

    warnings
}

/// Compute which pattern messages were newly introduced by an `Edit` or
/// `MultiEdit` (count increased in `new_text` relative to `old_text`).
fn introduced_messages(
    fragments: &[(String, String)],
    ext: &str,
    in_test_file: bool,
) -> HashSet<&'static str> {
    let mut introduced = HashSet::new();
    for (new_text, old_text) in fragments {
        let new_hits = scan_content_filtered(new_text, ext, in_test_file);
        if new_hits.is_empty() {
            continue;
        }
        let mut new_counts: HashMap<&'static str, usize> = HashMap::new();
        for (_, msg) in new_hits {
            *new_counts.entry(msg).or_insert(0) += 1;
        }
        let mut old_counts: HashMap<&'static str, usize> = HashMap::new();
        if !old_text.is_empty() {
            for (_, msg) in scan_content_filtered(old_text, ext, in_test_file) {
                *old_counts.entry(msg).or_insert(0) += 1;
            }
        }
        for (msg, count) in new_counts {
            if count > old_counts.get(msg).copied().unwrap_or(0) {
                introduced.insert(msg);
            }
        }
    }
    introduced
}

/// Line ranges in `content` covered by each non-empty `new_text` fragment, used
/// to narrow post-edit hints to the edited region when the file also has
/// pre-existing matches of the same pattern elsewhere.
fn edited_line_ranges(content: &str, fragments: &[(String, String)]) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    for (new_text, _) in fragments {
        if new_text.is_empty() {
            continue;
        }
        let mut search_start = 0;
        while let Some(rel) = content[search_start..].find(new_text.as_str()) {
            let abs = search_start + rel;
            let start_line = content[..abs].matches('\n').count() + 1;
            let end_line = start_line + new_text.matches('\n').count();
            ranges.push((start_line, end_line));
            search_start = abs + new_text.len();
        }
    }
    ranges
}

/// Scans written code for known insecure patterns across multiple languages.
pub struct SecurityPatternScanner;

impl Check for SecurityPatternScanner {
    fn name(&self) -> &str {
        "check-security-patterns"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(path) = input.file_path() else {
            return CheckResult::allow();
        };

        // Skip hook/config files
        if path.contains("/.claude/hooks/")
            || path.contains("/.claude/settings")
            || path.contains("/.claude/rules/")
            || path.ends_with("CLAUDE.md")
        {
            return CheckResult::allow();
        }

        let ext = path.rsplit('.').next().unwrap_or("");
        if !PATTERNS.iter().any(|sp| sp.extensions.contains(&ext)) {
            return CheckResult::allow();
        }
        let in_test_file = is_test_path(&path);

        // For Edit/MultiEdit, only nudge when the edit actually introduces a
        // pattern rather than re-emitting pre-existing hints on every unrelated
        // edit to the file.
        let is_edit = input
            .tool_input
            .as_ref()
            .is_some_and(|ti| ti.content.is_none());
        let edit_fragments = if is_edit {
            input.edit_fragments()
        } else {
            None
        };
        let introduced = edit_fragments
            .as_deref()
            .map(|frags| introduced_messages(frags, ext, in_test_file));
        if let Some(ref intro) = introduced
            && intro.is_empty()
        {
            return CheckResult::allow();
        }

        // Scan the *resulting* document, not the raw edit fragment (#131).
        // effective_content() simulates Edit/MultiEdit against the on-disk file
        // (correct line numbers, no stale pre-edit content); for Write it's the
        // content as-is. Fall back to the current on-disk file when the payload
        // carries no editable text, and fail open (allow) when neither is
        // available (ADR-0001) — this guard is advisory only.
        let content = match input.effective_content() {
            Some(c) => c,
            None => match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => return CheckResult::allow(),
            },
        };

        let mut warnings = scan_content_filtered(&content, ext, in_test_file);
        if let Some(ref intro) = introduced {
            warnings.retain(|(_, msg)| intro.contains(msg));
            if let Some(ref frags) = edit_fragments {
                let ranges = edited_line_ranges(&content, frags);
                if !ranges.is_empty() {
                    let in_ranges: Vec<_> = warnings
                        .iter()
                        .copied()
                        .filter(|(line, _)| ranges.iter().any(|(s, e)| line >= s && line <= e))
                        .collect();
                    if !in_ranges.is_empty() {
                        warnings = in_ranges;
                    }
                }
            }
        }
        if warnings.is_empty() {
            return CheckResult::allow();
        }

        let filename = path.rsplit('/').next().unwrap_or(&path);
        let mut msg = format!("Security hints for {filename}:\n");
        for (line_num, message) in &warnings {
            msg.push_str(&format!("  L{line_num}: {message}\n"));
        }

        // Advisory only — never block
        CheckResult::nudge(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;

    // --- scan_content: per-pattern tests ---

    #[test]
    fn py_pickle_loads() {
        let results = scan_content("pickle.loads(data)", "py");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("pickle"));
    }

    #[test]
    fn py_yaml_load() {
        let results = scan_content("yaml.load(f)", "py");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("safe_load"));
    }

    #[test]
    fn py_shell_true() {
        let results = scan_content("subprocess.run(cmd, shell=True)", "py");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("injection"));
    }

    #[test]
    fn py_trust_remote_code() {
        let results = scan_content("model = load(trust_remote_code=True)", "py");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("arbitrary code"));
    }

    #[test]
    fn py_dunder_import() {
        let results = scan_content("__import__('os')", "py");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("module loading"));
    }

    #[test]
    fn js_new_function() {
        // Testing detection of Function constructor pattern
        let results = scan_content("new Function('return 1')", "js");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("arbitrary code"));
    }

    #[test]
    fn jsx_inner_html() {
        let results = scan_content("el.innerHTML = userInput;", "jsx");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("XSS"));
    }

    #[test]
    fn mjs_math_random() {
        let results = scan_content("const id = Math.random()", "mjs");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("cryptographically"));
    }

    #[test]
    fn cjs_inner_html() {
        let results = scan_content("node.innerHTML = data;", "cjs");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("XSS"));
    }

    #[test]
    fn ts_type_assertion() {
        // Pattern requires preceding ), ], }, or word char — typical assertion context
        let results = scan_content("const x = getInput() as UserData;", "ts");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("assertion"));
    }

    #[test]
    fn tsx_type_assertion() {
        let results = scan_content("const y = getValue() as Props;", "tsx");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("assertion"));
    }

    #[test]
    fn go_text_template() {
        let results = scan_content(r#"import "text/template""#, "go");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("html/template"));
    }

    #[test]
    fn go_math_rand() {
        let results = scan_content(r#"import "math/rand""#, "go");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("crypto/rand"));
    }

    #[test]
    fn go_unsafe_import() {
        let results = scan_content(r#"import "unsafe""#, "go");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("unsafe"));
    }

    #[test]
    fn rs_unsafe_block() {
        let results = scan_content("unsafe {", "rs");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("SAFETY"));
    }

    #[test]
    fn rs_from_utf8_unchecked() {
        let results = scan_content("from_utf8_unchecked(bytes)", "rs");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("UB"));
    }

    #[test]
    fn java_object_input_stream() {
        let results = scan_content("new ObjectInputStream(stream)", "java");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("Deserialization"));
    }

    #[test]
    fn java_util_random() {
        let results = scan_content("java.util.Random r = new", "java");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("SecureRandom"));
    }

    #[test]
    fn cs_binary_formatter() {
        let results = scan_content("new BinaryFormatter()", "cs");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("RCE"));
    }

    #[test]
    fn cs_type_name_handling() {
        // Pattern matches every occurrence — both TypeNameHandling references flagged
        let results = scan_content("TypeNameHandling = TypeNameHandling.All", "cs");
        assert_eq!(results.len(), 2);
        assert!(results[0].1.contains("Deserialization"));
    }

    #[test]
    fn cs_dtd_processing() {
        let results = scan_content("DtdProcessing.Parse", "cs");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("XXE"));
    }

    #[test]
    fn swift_user_defaults_secret() {
        let content = r#"UserDefaults.standard.set(password, forKey: "pw")"#;
        let results = scan_content(content, "swift");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("Keychain"));
    }

    // --- scan_content: cross-cutting tests ---

    #[test]
    fn wrong_extension_skipped() {
        let results = scan_content("pickle.loads(data)", "js");
        assert!(results.is_empty());
    }

    #[test]
    fn multiple_violations_all_reported() {
        let content = "pickle.loads(x)\nyaml.load(f)\nshell = True";
        let results = scan_content(content, "py");
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn same_pattern_multiple_occurrences() {
        // Bug: scan_content uses re.find() which returns only the first match.
        // Multiple occurrences of the same pattern are silently dropped.
        let content = "yaml.load(a)\nok_line()\nyaml.load(b)";
        let results = scan_content(content, "py");
        assert_eq!(
            results.len(),
            2,
            "should report both yaml.load occurrences, got {results:?}"
        );
    }

    #[test]
    fn line_number_accuracy() {
        let content = "line1\nline2\nline3\nline4\npickle.loads(x)";
        let results = scan_content(content, "py");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 5);
    }

    #[test]
    fn line_number_accuracy_for_mid_line_match() {
        // Match that does NOT start at column 0: the partial line before the
        // pattern must not inflate the line count.
        let content = "import pickle\ndata = pickle.loads(blob)";
        let results = scan_content(content, "py");
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].0, 2,
            "pickle.loads is on line 2, got line {}",
            results[0].0
        );
    }

    #[test]
    fn clean_content_no_warnings() {
        let results = scan_content("fn safe_code() { println!(\"hello\"); }", "rs");
        assert!(results.is_empty());
    }

    // --- false positive regression tests ---

    #[test]
    fn ts_import_alias_not_flagged() {
        let results = scan_content("import { foo as Bar } from 'module';", "ts");
        assert!(
            results.is_empty(),
            "import alias should not trigger type assertion warning"
        );
    }

    #[test]
    fn ts_comment_as_not_flagged() {
        let results = scan_content("// known as Unknown type in the system", "ts");
        assert!(
            results.is_empty(),
            "prose 'as' in comments should not trigger"
        );
    }

    #[test]
    fn ts_paren_as_assertion_flagged() {
        // `)` before `as` — typical type assertion after function call
        let results = scan_content("const x = getInput() as UserData;", "ts");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("assertion"));
    }

    #[test]
    fn ts_bracket_as_assertion_flagged() {
        let results = scan_content("const x = items[0] as Config;", "ts");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("assertion"));
    }

    #[test]
    fn ts_brace_as_assertion_flagged() {
        let results = scan_content("const x = { foo: 1 } as Record<string, number>;", "ts");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("assertion"));
    }

    #[test]
    fn ts_bare_variable_as_not_flagged() {
        // Bare `variable as Type` is ambiguous — we accept this false negative
        // to avoid false positives on import aliases and comments
        let results = scan_content("const x = input as UserData;", "ts");
        assert!(results.is_empty());
    }

    #[test]
    fn java_random_access_not_flagged() {
        let results = scan_content("implements RandomAccess {", "java");
        assert!(
            results.is_empty(),
            "RandomAccess should not trigger java.util.Random warning"
        );
    }

    #[test]
    fn java_random_event_not_flagged() {
        let results = scan_content("class RandomEventGenerator {", "java");
        assert!(
            results.is_empty(),
            "RandomEventGenerator should not trigger"
        );
    }

    #[test]
    fn java_util_random_still_flagged() {
        let results = scan_content("java.util.Random r = new java.util.Random();", "java");
        assert!(
            !results.is_empty(),
            "java.util.Random should still be flagged"
        );
        assert!(results[0].1.contains("SecureRandom"));
    }

    #[test]
    fn java_util_random_at_eol_flagged() {
        let results = scan_content("import java.util.Random\nnext line", "java");
        assert!(
            !results.is_empty(),
            "java.util.Random at end of line should be flagged"
        );
    }

    // --- run() guard clauses ---

    #[test]
    fn no_file_path_allows() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = SecurityPatternScanner.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn claude_hooks_path_skipped() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/home/dev/.claude/hooks/check.sh".into()),
                path: None,
                command: None,
                content: None,
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        let result = SecurityPatternScanner.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn claude_rules_path_skipped() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/home/dev/.claude/rules/security.md".into()),
                path: None,
                command: None,
                content: None,
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        let result = SecurityPatternScanner.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn claude_md_skipped() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/project/CLAUDE.md".into()),
                path: None,
                command: None,
                content: None,
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        let result = SecurityPatternScanner.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    // --- new RCE / XSS pattern coverage (#131) ---

    #[test]
    fn py_eval() {
        let results = scan_content("result = eval(user_input)", "py");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("eval"));
    }

    #[test]
    fn py_exec() {
        let results = scan_content("exec(compiled)", "py");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("exec"));
    }

    #[test]
    fn py_os_system() {
        let results = scan_content("os.system(cmd)", "py");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("injection"));
    }

    #[test]
    fn py_pickle_load() {
        let results = scan_content("obj = pickle.load(f)", "py");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("pickle"));
    }

    #[test]
    fn js_eval() {
        let results = scan_content("eval(payload)", "js");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("eval"));
    }

    #[test]
    fn js_document_write() {
        let results = scan_content("document.write(html)", "js");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("XSS"));
    }

    #[test]
    fn jsx_dangerously_set_inner_html() {
        let results = scan_content("<div dangerouslySetInnerHTML={{ __html: raw }} />", "jsx");
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("sanitize"));
    }

    // --- false-positive regressions for the new patterns ---

    #[test]
    fn py_retrieval_not_flagged() {
        // `retrieval(` embeds "eval(" but the \b boundary before eval fails.
        let results = scan_content("retrieval(query)", "py");
        assert!(
            results.is_empty(),
            "retrieval() must not trip eval, got {results:?}"
        );
    }

    #[test]
    fn py_execute_not_flagged() {
        // `execute(` embeds "exec" but the required `[(]` after exec is absent.
        let results = scan_content("cursor.execute(sql)", "py");
        assert!(
            results.is_empty(),
            "execute() must not trip exec, got {results:?}"
        );
    }

    #[test]
    fn py_pickle_loads_not_double_counted() {
        // pickle.loads matches only the existing `pickle[.]loads` pattern; the
        // new `pickle[.]load[(]` requires "load(" and must not also fire.
        let results = scan_content("pickle.loads(blob)", "py");
        assert_eq!(
            results.len(),
            1,
            "pickle.loads must match exactly once, got {results:?}"
        );
    }

    #[test]
    fn js_medieval_not_flagged() {
        let results = scan_content("medieval(theme)", "js");
        assert!(
            results.is_empty(),
            "medieval() must not trip eval, got {results:?}"
        );
    }

    // --- run() routing through effective_content (#129, #131) ---

    use cadence_hooks_core::test_builders::{make_edit, make_multi_edit};

    /// Write source into a temp file with the given extension; returns
    /// (tempdir guard, absolute path).
    fn on_disk_source(ext: &str, content: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("code.{ext}"));
        std::fs::write(&path, content).unwrap();
        (dir, path.to_str().unwrap().to_string())
    }

    #[test]
    fn run_edit_introducing_pattern_scans_effective_content() {
        // An Edit whose new_string introduces os.system on line 2 must be
        // flagged with the correct post-edit line number — proving the guard
        // scans the simulated document, not the raw edit fragment.
        let (_dir, path) = on_disk_source("py", "import os\nplaceholder()\n");
        let input = make_edit(&path, "placeholder()", r#"os.system("rm -rf /")"#);
        let result = SecurityPatternScanner.run(&input);
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.unwrap();
        assert!(msg.contains("L2"), "expected line 2, got: {msg}");
        assert!(
            msg.contains("injection"),
            "expected injection hint, got: {msg}"
        );
    }

    #[test]
    fn all_security_patterns_compile_into_static_table() {
        assert_eq!(
            COMPILED_PATTERNS.len(),
            PATTERNS.len(),
            "every entry in PATTERNS must compile cleanly into COMPILED_PATTERNS"
        );
    }

    #[test]
    fn run_multi_edit_scans_resulting_document_not_stale() {
        // The on-disk file is clean; only the applied MultiEdit introduces the
        // pattern. A stale pre-edit scan would miss it.
        let (_dir, path) = on_disk_source("py", "import os\nprint('hi')\n");
        let input = make_multi_edit(&path, &[("print('hi')", "os.system('x')")]);
        let result = SecurityPatternScanner.run(&input);
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(result.message.unwrap().contains("injection"));
    }

    #[test]
    fn run_edit_unrelated_to_preexisting_pattern_allows() {
        // An Edit that touches line 3 must NOT re-emit a pre-existing hint on
        // line 1.
        let (_dir, path) = on_disk_source("py", "os.system('preexisting')\n\nprint('old')\n");
        let input = make_edit(&path, "print('old')", "print('new')");
        let result = SecurityPatternScanner.run(&input);
        assert_eq!(
            result.outcome,
            Outcome::Allow,
            "unrelated edit should not re-nudge: {:?}",
            result.message
        );
    }

    #[test]
    fn run_edit_carrying_through_preexisting_pattern_allows() {
        let (_dir, path) = on_disk_source("py", "os.system('preexisting')\nprint('old')\n");
        let input = make_edit(
            &path,
            "os.system('preexisting')\nprint('old')",
            "os.system('preexisting')\nprint('new')",
        );
        let result = SecurityPatternScanner.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn run_ts_type_assertion_skipped_in_test_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("register.test.ts");
        let content = "const x = getMock() as UserData;\n";
        std::fs::write(&path, content).unwrap();
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some(path.to_string_lossy().into_owned()),
                content: Some(content.into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(SecurityPatternScanner.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn run_real_security_pattern_still_fires_in_test_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.test.tsx");
        let content = "<div dangerouslySetInnerHTML={{ __html: raw }} />\n";
        std::fs::write(&path, content).unwrap();
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some(path.to_string_lossy().into_owned()),
                content: Some(content.into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(SecurityPatternScanner.run(&input).outcome, Outcome::Nudge);
    }
}
