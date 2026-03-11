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
        pattern: r"\s+as\s+[A-Z]",
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
        pattern: r"java[.]util[.]Random[^N]",
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

        // Must be a real file to scan
        if !std::path::Path::new(path).is_file() {
            return CheckResult::allow();
        }

        let ext = path.rsplit('.').next().unwrap_or("");
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return CheckResult::allow(),
        };

        let mut warnings = Vec::new();

        for sp in PATTERNS {
            if !sp.extensions.contains(&ext) {
                continue;
            }

            if let Ok(re) = Regex::new(sp.pattern)
                && let Some(m) = re.find(&content)
            {
                // Find line number
                let line_num = content[..m.start()].lines().count() + 1;
                warnings.push(format!("  L{line_num}: {}", sp.message));
            }
        }

        if warnings.is_empty() {
            return CheckResult::allow();
        }

        let filename = path.rsplit('/').next().unwrap_or(path);
        let mut msg = format!("Security hints for {filename}:\n");
        for w in &warnings {
            msg.push_str(&format!("{w}\n"));
        }

        // Advisory only — never block
        CheckResult::warn(msg)
    }
}
