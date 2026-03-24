//! Scan code for known insecure patterns.
//!
//! Maintains a table of language-specific anti-patterns (pickle, innerHTML,
//! `shell=True`, unsafe Go imports, etc.) and warns when written code matches.

use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;

/// A security pattern to check for in a specific file extension.
struct SecurityPattern {
    extensions: &'static [&'static str],
    pattern: &'static str,
    message: &'static str,
}

const PATTERNS: &[SecurityPattern] = &[
    SecurityPattern {
        extensions: &["py"],
        pattern: r"pickle[.]loads",
        message: "RCE risk: use json or msgpack instead of pickle",
    },
    SecurityPattern {
        extensions: &["py"],
        pattern: r"yaml[.]load[(]",
        message: "Use yaml.safe_load()",
    },
    SecurityPattern {
        extensions: &["py"],
        pattern: r"shell\s*=\s*True",
        message: "Command injection risk: pass arg list to subprocess",
    },
    SecurityPattern {
        extensions: &["py"],
        pattern: r"trust_remote_code\s*=\s*True",
        message: "Runs arbitrary code from model repos",
    },
    SecurityPattern {
        extensions: &["py"],
        pattern: r"__import__[(]",
        message: "Arbitrary module loading",
    },
    SecurityPattern {
        extensions: &["js", "jsx", "mjs", "cjs"],
        pattern: r"new\s+Function[(]",
        message: "Function() constructor can run arbitrary code",
    },
    SecurityPattern {
        extensions: &["js", "jsx", "mjs", "cjs"],
        pattern: r"[.]innerHTML\s*=",
        message: "XSS risk: use textContent or sanitize first",
    },
    SecurityPattern {
        extensions: &["js", "jsx", "mjs", "cjs"],
        pattern: r"Math[.]random[(][)]",
        message: "Not cryptographically secure",
    },
    SecurityPattern {
        extensions: &["ts", "tsx"],
        pattern: r"[)\]}]\s+as\s+[A-Z]",
        message: "Type assertion bypasses validation",
    },
    SecurityPattern {
        extensions: &["go"],
        pattern: r#""text/template""#,
        message: "Use html/template for HTML output",
    },
    SecurityPattern {
        extensions: &["go"],
        pattern: r#""math/rand""#,
        message: "Use crypto/rand for security-sensitive randomness",
    },
    SecurityPattern {
        extensions: &["go"],
        pattern: r#""unsafe""#,
        message: "unsafe package -- document safety invariants",
    },
    SecurityPattern {
        extensions: &["rs"],
        pattern: r"unsafe\s*[{]",
        message: "Ensure // SAFETY: comment and test with Miri",
    },
    SecurityPattern {
        extensions: &["rs"],
        pattern: r"from_utf8_unchecked",
        message: "UB risk on external input",
    },
    SecurityPattern {
        extensions: &["java"],
        pattern: r"ObjectInputStream",
        message: "Deserialization RCE -- use ObjectInputFilter",
    },
    SecurityPattern {
        extensions: &["java"],
        pattern: r"java\.util\.Random(?:$|[^A-Za-z])",
        message: "Use SecureRandom for security-sensitive values",
    },
    SecurityPattern {
        extensions: &["cs"],
        pattern: r"BinaryFormatter",
        message: "RCE vector, removed in .NET 9",
    },
    SecurityPattern {
        extensions: &["cs"],
        pattern: r"TypeNameHandling",
        message: "Deserialization attack -- ensure TypeNameHandling.None",
    },
    SecurityPattern {
        extensions: &["cs"],
        pattern: r"DtdProcessing[.]Parse",
        message: "XXE risk -- use DtdProcessing.Prohibit",
    },
    SecurityPattern {
        extensions: &["swift"],
        pattern: r"UserDefaults.*(password|secret|token|apiKey)",
        message: "Store secrets in Keychain",
    },
];

/// Scan content for security anti-patterns matching the given file extension.
///
/// Returns `(line_number, message)` tuples for each violation found.
/// Pure function — no I/O.
pub fn scan_content(content: &str, ext: &str) -> Vec<(usize, &'static str)> {
    let mut warnings = Vec::new();

    for sp in PATTERNS {
        if !sp.extensions.contains(&ext) {
            continue;
        }

        if let Ok(re) = Regex::new(sp.pattern) {
            for m in re.find_iter(content) {
                let line_num = content[..m.start()].lines().count() + 1;
                warnings.push((line_num, sp.message));
            }
        }
    }

    warnings
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

        // Prefer content from the tool input (Write/Edit); fall back to disk (Read/Grep)
        let content = match input.content() {
            Some(c) => c.to_string(),
            None => match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => return CheckResult::allow(),
            },
        };

        let warnings = scan_content(&content, ext);
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
            }),
            cwd: None,
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
            }),
            cwd: None,
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
            }),
            cwd: None,
        };
        let result = SecurityPatternScanner.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }
}
