//! Directory targets named through a variable the same command set to a
//! literal (cameronsjo/cadence-hooks#1287).
//!
//! `M=/abs/repo; git -C "$M" commit …` names its checkout as plainly as
//! `git -C /abs/repo commit …` does, but every guard that resolves a `cd` /
//! `git -C` / `--git-dir` / `--work-tree` target read `"$M"` as unknowable and
//! refused. [`resolve_literal_dir_variables`] rewrites such a read to the
//! literal it is bound to wherever that rewrite is an identity under bash —
//! the shell would expand the read to exactly that text — so every guard sees
//! the directory without learning a second grammar. It runs once per check,
//! at the dispatch seam ([`crate::decide_check`]).
//!
//! **What is resolved.** A plain `$NAME` / `${NAME}`, unquoted or inside
//! double quotes, alone or with literal text around it (`"$M/sub"`), that is
//! the operand of `-C`, `cd`, `pushd`, `--git-dir` or `--work-tree` (spaced
//! or glued as `--git-dir=`/`-C`), when:
//!
//! - an earlier statement of the same group assigned it and nothing else: a
//!   statement that is only `NAME=literal` words (optionally after `export`),
//!   opening its list (after `;`, a newline, `&`, a group opener or the start)
//!   or chained by `&&` after another such statement, outside every `if` /
//!   loop body of that group, and ending in `;`, a newline, `&&`, `||` or the
//!   end. A `(…)`/`$(…)`/`{…}` group sees what was assigned before it opened;
//!   what it assigns ends with it.
//! - every mention of `NAME` anywhere in the command is a `NAME=literal`
//!   assignment of that same value ([`crate::shell::literal_values_of`]) — so
//!   no reassignment, `read`, `for NAME in`, `unset NAME`, `${NAME:=…}`, and
//!   no prefix assignment `NAME=x cmd` that differs;
//! - the value is a plain word with no blank, quote, backslash, expansion,
//!   glob, brace, tilde or `#`, so the rewrite reads the same unquoted or
//!   quoted.
//!
//! **What still refuses** (the command is left as written, and each guard
//! fails closed on it as before): anything above that does not hold, and any
//! command carrying a construct that can assign a variable whose name is
//! computed — `eval`, `source`/`.`, `declare`/`typeset`/`local`/`readonly`,
//! `read`/`mapfile`/`readarray`/`getopts`, `let`, `unset`, `printf -v`,
//! `wait -p`, `trap`, `alias`, `enable`, `fc`, `builtin`, `coproc`, `case`,
//! `function`, `[[ … ]]` and `(( … ))`/`$(( … ))`/`$[ … ]` arithmetic, an
//! array-element assignment, a `${…}` with any operator, `$'…'`/`$"…"`,
//! backticks, a command word built from an expansion, and a heredoc the scan
//! cannot pair with its terminator. Text inside single quotes and inside a
//! quoted-delimiter heredoc body is data to this shell and is neither read for
//! these nor rewritten.
//!
//! **Residual, by design:** a variable the session's shell already declared
//! `readonly`, integer (`-i`), case-folding or as a nameref, an alias or a
//! function the shell defined before the command ran, and an `IFS` the
//! environment changed. None is visible in the command; each is the same
//! trust every guard already extends to the shell it runs in.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

/// `command` with each directory-target read of a literal-bound variable
/// replaced by that literal, or `command` itself when there is none or the
/// scan cannot vouch for the command. Linear in the command's length.
pub fn resolve_literal_dir_variables(command: &str) -> Cow<'_, str> {
    if !command.contains('$') || !command.contains('=') {
        return Cow::Borrowed(command);
    }
    let Some(uses) = Scan::new(command).run() else {
        return Cow::Borrowed(command);
    };
    if uses.is_empty() {
        return Cow::Borrowed(command);
    }
    let mentions = crate::shell::variable_mentions(command);
    let mut values: HashMap<&str, Option<String>> = HashMap::new();
    let mut out = String::with_capacity(command.len());
    let mut at = 0;
    for found in &uses {
        let value = values
            .entry(found.name.as_str())
            .or_insert_with(|| bound_literal(command, &mentions, &found.name));
        if let Some(value) = value {
            out.push_str(&command[at..found.start]);
            out.push_str(value);
            at = found.end;
        }
    }
    if at == 0 {
        return Cow::Borrowed(command);
    }
    out.push_str(&command[at..]);
    Cow::Owned(out)
}

/// The one literal every mention of `name` assigns, when it is safe to splice
/// in place of a read of `name` in either quoting.
fn bound_literal(
    command: &str,
    mentions: &HashMap<String, Vec<usize>>,
    name: &str,
) -> Option<String> {
    if shell_managed(name) {
        return None;
    }
    let ends = mentions.get(name)?;
    let values = crate::shell::literal_values_of(command, mentions, ends)?;
    let (first, rest) = values.split_first()?;
    if rest.iter().any(|value| value != first) || !splices_verbatim(first) {
        return None;
    }
    Some(first.clone())
}

/// Variables the shell itself sets or reads specially: a literal assignment
/// to one does not fix what a later read gives.
fn shell_managed(name: &str) -> bool {
    name.starts_with("BASH")
        || matches!(
            name,
            "_" | "PWD"
                | "OLDPWD"
                | "IFS"
                | "CDPATH"
                | "REPLY"
                | "RANDOM"
                | "SRANDOM"
                | "SECONDS"
                | "LINENO"
                | "OPTARG"
                | "OPTIND"
                | "OPTERR"
                | "PIPESTATUS"
                | "FUNCNAME"
                | "DIRSTACK"
                | "EPOCHSECONDS"
                | "EPOCHREALTIME"
                | "HISTCMD"
                | "GROUPS"
                | "UID"
                | "EUID"
                | "PPID"
                | "SHLVL"
                | "COLUMNS"
                | "LINES"
                | "MAPFILE"
                | "COPROC"
        )
}

/// Does `value` read the same spliced into a word bare or inside double
/// quotes? No blank (field splitting), quote, escape, expansion, glob, brace,
/// tilde, comment, history or operator character.
fn splices_verbatim(value: &str) -> bool {
    !value.is_empty()
        && !value.chars().any(|c| {
            c.is_whitespace()
                || c.is_control()
                || matches!(
                    c,
                    '\'' | '"'
                        | '\\'
                        | '$'
                        | '`'
                        | '~'
                        | '*'
                        | '?'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '('
                        | ')'
                        | ';'
                        | '&'
                        | '|'
                        | '<'
                        | '>'
                        | '#'
                        | '!'
                )
        })
}

/// Builtins that can set a variable whose name or value the command computes,
/// or run text as code in this shell. Their presence in command position
/// anywhere refuses the whole command.
const ASSIGNING_BUILTINS: &[&str] = &[
    "eval", "source", ".", "declare", "typeset", "local", "readonly", "read", "readarray",
    "mapfile", "getopts", "let", "unset", "trap", "alias", "unalias", "enable", "fc", "builtin",
];

/// Reserved words that refuse the command: their bodies are grammar this scan
/// does not follow (`case` patterns unbalance parens), or they assign through
/// arithmetic (`((`, `[[`).
const REFUSED_KEYWORDS: &[&str] = &["case", "esac", "function", "coproc", "select", "[[", "(("];

/// The operands whose variable read is rewritten.
const TARGET_FLAGS: &[&str] = &["-C", "cd", "pushd", "--git-dir", "--work-tree"];

/// A read to rewrite: the byte span of `$NAME`/`${NAME}`.
struct Use {
    start: usize,
    end: usize,
    name: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Closer {
    Paren,
    Brace,
}

/// What an open group restores when it closes.
struct Frame {
    closer: Closer,
    dquote: bool,
    compound: usize,
    word_start: Option<usize>,
    word_dynamic: bool,
    word_cmd_pos: bool,
    cmd_pos: bool,
    simple: Simple,
    /// Opened inside a word (`$(`, `<(`): the word goes on after it.
    in_word: bool,
}

/// How a statement ended.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Term {
    Seq,
    And,
    Or,
    Pipe,
    Background,
    Close,
}

/// The command word of the simple command being read, where its operands
/// matter.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Simple {
    None,
    Export,
    Printf,
    Wait,
    /// `command` / `time`: option words keep command position.
    Runner,
}

#[derive(Default)]
struct Statement {
    /// Opens a list (or `&&`-follows a dominating statement) outside every
    /// compound of its group.
    eligible: bool,
    /// Only assignment words so far (after an optional leading `export`).
    pure: bool,
    names: Vec<String>,
}

struct Heredoc {
    delimiter: String,
    strip_tabs: bool,
    expands: bool,
}

struct Scan<'a> {
    src: &'a str,
    b: &'a [u8],
    i: usize,
    frames: Vec<Frame>,
    dquote: bool,
    /// Open `if`/loop compounds in the current group.
    compound: usize,
    cmd_pos: bool,
    word_start: Option<usize>,
    /// The current word carries an expansion or substitution.
    word_dynamic: bool,
    word_cmd_pos: bool,
    /// The next word is a redirection's target, not a command word.
    redirect_target: bool,
    prev_word: Option<(usize, usize)>,
    simple: Simple,
    stmt: Statement,
    /// Names a dominating statement assigned, and per group depth the names
    /// first bound there (which go when it closes).
    bound: HashSet<String>,
    bound_at: Vec<Vec<String>>,
    heredocs: Vec<Heredoc>,
    uses: Vec<Use>,
}

impl<'a> Scan<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src,
            b: src.as_bytes(),
            i: 0,
            frames: Vec::new(),
            dquote: false,
            compound: 0,
            cmd_pos: true,
            word_start: None,
            word_dynamic: false,
            word_cmd_pos: false,
            redirect_target: false,
            prev_word: None,
            simple: Simple::None,
            stmt: Statement {
                eligible: true,
                pure: true,
                names: Vec::new(),
            },
            bound: HashSet::new(),
            bound_at: vec![Vec::new()],
            heredocs: Vec::new(),
            uses: Vec::new(),
        }
    }

    fn peek(&self, k: usize) -> Option<u8> {
        self.b.get(self.i + k).copied()
    }

    /// The reads to rewrite, or `None` when the command is not one this scan
    /// can vouch for.
    fn run(mut self) -> Option<Vec<Use>> {
        while self.i < self.b.len() {
            let c = self.b[self.i];
            if self.dquote {
                match c {
                    b'"' => {
                        self.dquote = false;
                        self.i += 1;
                    }
                    b'\\' => self.i += 2,
                    b'`' => return None,
                    b'$' => self.dollar()?,
                    b'\n' if !self.heredocs.is_empty() => return None,
                    _ => self.i += 1,
                }
                continue;
            }
            match c {
                b' ' | b'\t' | b'\r' => {
                    self.end_word()?;
                    self.i += 1;
                }
                b'\n' => {
                    self.end_word()?;
                    self.end_statement(Term::Seq)?;
                    self.i += 1;
                    self.skip_heredoc_bodies()?;
                }
                b'#' if self.word_start.is_none() => {
                    while self.i < self.b.len() && self.b[self.i] != b'\n' {
                        self.i += 1;
                    }
                }
                b'\\' => {
                    if self.peek(1) == Some(b'\n') {
                        self.i += 2;
                    } else {
                        self.start_word();
                        self.i += 2;
                    }
                }
                b'\'' => {
                    self.start_word();
                    let close = self.src[self.i + 1..].find('\'')?;
                    self.i += close + 2;
                }
                b'"' => {
                    self.start_word();
                    self.dquote = true;
                    self.i += 1;
                }
                b'`' => return None,
                b'$' => {
                    self.start_word();
                    self.dollar()?;
                }
                b';' => {
                    self.end_word()?;
                    if self.peek(1) == Some(b';') {
                        return None;
                    }
                    self.end_statement(Term::Seq)?;
                    self.i += 1;
                }
                b'&' => {
                    self.end_word()?;
                    match self.peek(1) {
                        Some(b'&') => {
                            self.end_statement(Term::And)?;
                            self.i += 2;
                        }
                        Some(b'>') => {
                            self.stmt.pure = false;
                            self.redirect_target = true;
                            self.i += 2;
                        }
                        _ => {
                            self.end_statement(Term::Background)?;
                            self.i += 1;
                        }
                    }
                }
                b'|' => {
                    self.end_word()?;
                    if self.peek(1) == Some(b'|') {
                        self.end_statement(Term::Or)?;
                        self.i += 2;
                    } else {
                        self.end_statement(Term::Pipe)?;
                        self.i += if self.peek(1) == Some(b'&') { 2 } else { 1 };
                    }
                }
                b'(' => {
                    self.end_word()?;
                    if self.peek(1) == Some(b'(') {
                        return None;
                    }
                    self.open(Closer::Paren);
                    self.i += 1;
                }
                b')' => {
                    self.end_word()?;
                    self.close(Closer::Paren)?;
                    self.i += 1;
                }
                b'<' | b'>' => self.redirection()?,
                _ => {
                    self.start_word();
                    self.i += 1;
                }
            }
        }
        if self.dquote {
            return None;
        }
        self.end_word()?;
        self.end_statement(Term::Seq)?;
        if !self.frames.is_empty() || !self.heredocs.is_empty() || self.compound != 0 {
            return None;
        }
        Some(self.uses)
    }

    fn start_word(&mut self) {
        if self.word_start.is_none() {
            self.word_start = Some(self.i);
            self.word_dynamic = false;
            self.word_cmd_pos = self.cmd_pos && !self.redirect_target;
        }
    }

    /// A redirection operator at `self.i`.
    fn redirection(&mut self) -> Option<()> {
        // A word glued to the operator that is only digits (`2>`) or `{fd}`
        // names the descriptor; it is not a word of the command.
        if let Some(start) = self.word_start {
            let text = &self.src[start..self.i];
            if !text.is_empty() && text.bytes().all(|c| c.is_ascii_digit()) {
                self.word_start = None;
            } else if text.starts_with('{') && text.ends_with('}') {
                return None;
            }
        }
        self.end_word()?;
        self.stmt.pure = false;
        let rest = &self.b[self.i..];
        if rest.starts_with(b"<<<") {
            self.redirect_target = true;
            self.i += 3;
            return Some(());
        }
        if rest.starts_with(b"<<") {
            self.i += 2;
            return self.heredoc_introducer();
        }
        if matches!(rest.get(1), Some(b'(')) {
            // `<(…)` / `>(…)`: a process substitution, its own process.
            self.start_word();
            self.word_dynamic = true;
            self.open(Closer::Paren);
            self.i += 2;
            return Some(());
        }
        self.i += 1;
        while matches!(self.peek(0), Some(b'>' | b'&' | b'|')) {
            self.i += 1;
        }
        self.redirect_target = true;
        Some(())
    }

    /// Read a heredoc's delimiter word just past its `<<`.
    fn heredoc_introducer(&mut self) -> Option<()> {
        let strip_tabs = self.peek(0) == Some(b'-');
        if strip_tabs {
            self.i += 1;
        }
        while matches!(self.peek(0), Some(b' ' | b'\t')) {
            self.i += 1;
        }
        let plain = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-');
        let (delimiter, expands) = match self.peek(0)? {
            quote @ (b'\'' | b'"') => {
                let close = self.src[self.i + 1..].find(quote as char)?;
                let word = &self.src[self.i + 1..self.i + 1 + close];
                if word.is_empty() || !word.bytes().all(plain) {
                    return None;
                }
                self.i += close + 2;
                (word.to_string(), false)
            }
            _ => {
                let start = self.i;
                while self.peek(0).is_some_and(plain) {
                    self.i += 1;
                }
                if start == self.i {
                    return None;
                }
                (self.src[start..self.i].to_string(), true)
            }
        };
        if !matches!(
            self.peek(0),
            None | Some(b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b')' | b'<' | b'>')
        ) {
            return None;
        }
        self.heredocs.push(Heredoc {
            delimiter,
            strip_tabs,
            expands,
        });
        Some(())
    }

    /// Skip the bodies of the heredocs the line just ended introduced. An
    /// expanding body runs its expansions in this shell, so one that can
    /// assign refuses the command; nothing in a body is rewritten.
    fn skip_heredoc_bodies(&mut self) -> Option<()> {
        for doc in std::mem::take(&mut self.heredocs) {
            loop {
                if self.i >= self.b.len() {
                    return None;
                }
                let end = self.src[self.i..]
                    .find('\n')
                    .map_or(self.b.len(), |n| self.i + n);
                let line = &self.src[self.i..end];
                self.i = (end + 1).min(self.b.len());
                let check = if doc.strip_tabs {
                    line.trim_start_matches('\t')
                } else {
                    line
                };
                if check == doc.delimiter {
                    break;
                }
                if doc.expands && (line.ends_with('\\') || body_may_assign(line)) {
                    return None;
                }
            }
        }
        Some(())
    }

    /// A `$` at `self.i`, unquoted or inside double quotes.
    fn dollar(&mut self) -> Option<()> {
        self.word_dynamic = true;
        let start = self.i;
        match self.peek(1) {
            Some(b'(') => {
                if self.peek(2) == Some(b'(') {
                    return None;
                }
                self.open(Closer::Paren);
                self.i += 2;
            }
            Some(b'{') => {
                let rest = &self.src[start + 2..];
                let len = ident_len(rest);
                if len == 0 || rest.as_bytes().get(len) != Some(&b'}') {
                    return None;
                }
                self.i = start + 2 + len + 1;
                self.consider_use(start, &rest[..len]);
            }
            Some(b'[') => return None,
            Some(b'\'' | b'"') if !self.dquote => return None,
            Some(c) if c.is_ascii_alphabetic() || c == b'_' => {
                let rest = &self.src[start + 1..];
                let len = ident_len(rest);
                self.i = start + 1 + len;
                self.consider_use(start, &rest[..len]);
            }
            Some(c) if c.is_ascii_digit() || b"@*#?$!-".contains(&c) => self.i += 2,
            _ => self.i += 1,
        }
        Some(())
    }

    /// Record the read spanning `start..self.i` of `name` when it is a
    /// directory operand and `name` is bound here.
    fn consider_use(&mut self, start: usize, name: &str) {
        if !self.bound.contains(name) {
            return;
        }
        let word_start = self.word_start.unwrap_or(start);
        let prefix: String = self.src[word_start..start]
            .chars()
            .filter(|&c| c != '"')
            .collect();
        let target = match prefix.as_str() {
            "" => self
                .prev_word
                .is_some_and(|(s, e)| TARGET_FLAGS.contains(&&self.src[s..e])),
            "-C" | "--git-dir=" | "--work-tree=" => true,
            _ => false,
        };
        if target {
            self.uses.push(Use {
                start,
                end: self.i,
                name: name.to_string(),
            });
        }
    }

    /// Open a group: `(`, `$(`, `<(`, `>(` or `{`.
    fn open(&mut self, closer: Closer) {
        self.stmt.pure = false;
        let word_start = self.word_start.take();
        self.frames.push(Frame {
            closer,
            dquote: self.dquote,
            compound: self.compound,
            in_word: word_start.is_some(),
            word_start,
            word_dynamic: self.word_dynamic,
            word_cmd_pos: self.word_cmd_pos,
            cmd_pos: self.cmd_pos,
            simple: self.simple,
        });
        self.bound_at.push(Vec::new());
        self.dquote = false;
        self.compound = 0;
        self.cmd_pos = true;
        self.redirect_target = false;
        self.prev_word = None;
        self.simple = Simple::None;
        self.stmt = Statement {
            eligible: true,
            pure: true,
            names: Vec::new(),
        };
    }

    /// Close the innermost group, which must be one `closer` ends.
    fn close(&mut self, closer: Closer) -> Option<()> {
        self.end_statement(Term::Close)?;
        if self.compound != 0 {
            return None;
        }
        let frame = self.frames.pop()?;
        if frame.closer != closer {
            return None;
        }
        for name in self.bound_at.pop().unwrap_or_default() {
            self.bound.remove(&name);
        }
        self.dquote = frame.dquote;
        self.compound = frame.compound;
        self.word_start = frame.word_start;
        self.word_dynamic = frame.word_dynamic;
        self.word_cmd_pos = frame.word_cmd_pos;
        self.simple = frame.simple;
        // A substitution's word goes on where it stood. After a group comes
        // an operator or a redirection — or a function definition's body
        // (`f() {`), after its `()`.
        self.cmd_pos = if frame.in_word {
            frame.cmd_pos
        } else {
            closer == Closer::Paren
        };
        self.prev_word = None;
        self.stmt = Statement::default();
        Some(())
    }

    /// End the current word, if any, and read it.
    fn end_word(&mut self) -> Option<()> {
        let Some(start) = self.word_start.take() else {
            return Some(());
        };
        let raw = &self.src[start..self.i];
        let dynamic = std::mem::take(&mut self.word_dynamic);
        self.prev_word = Some((start, self.i));
        if std::mem::take(&mut self.redirect_target) {
            return Some(());
        }
        if !self.word_cmd_pos {
            return self.operand(raw, dynamic);
        }
        if let Some(name) = assignment_name(raw) {
            if raw.as_bytes().get(name.len()) == Some(&b'[') {
                return None;
            }
            if raw.as_bytes().get(name.len()) == Some(&b'+') {
                self.stmt.pure = false;
            }
            self.stmt.names.push(name.to_string());
            return Some(());
        }
        if dynamic {
            // A command word an expansion builds may be any builtin.
            return None;
        }
        let word = dequote(raw);
        if ASSIGNING_BUILTINS.contains(&word.as_str()) || REFUSED_KEYWORDS.contains(&word.as_str())
        {
            return None;
        }
        let first = self.stmt.names.is_empty() && self.simple == Simple::None;
        match word.as_str() {
            "if" | "while" | "until" => {
                self.compound += 1;
                self.stmt.pure = false;
            }
            "for" => {
                self.compound += 1;
                self.stmt.pure = false;
                self.cmd_pos = false;
            }
            "then" | "else" | "elif" | "do" | "!" => self.stmt.pure = false,
            "fi" | "done" => {
                self.compound = self.compound.checked_sub(1)?;
                self.stmt.pure = false;
                self.cmd_pos = false;
            }
            "{" => {
                self.open(Closer::Brace);
            }
            "}" => {
                self.close(Closer::Brace)?;
            }
            "export" if first => {
                self.simple = Simple::Export;
                self.cmd_pos = false;
            }
            "command" | "time" => {
                self.simple = Simple::Runner;
                self.stmt.pure = false;
            }
            "printf" => {
                self.simple = Simple::Printf;
                self.stmt.pure = false;
                self.cmd_pos = false;
            }
            "wait" => {
                self.simple = Simple::Wait;
                self.stmt.pure = false;
                self.cmd_pos = false;
            }
            _ if self.simple == Simple::Runner && word.starts_with('-') => {}
            _ => {
                self.stmt.pure = false;
                self.cmd_pos = false;
            }
        }
        Some(())
    }

    /// A word after the command word.
    fn operand(&mut self, raw: &str, dynamic: bool) -> Option<()> {
        match self.simple {
            Simple::Export => {
                if dynamic || raw.contains('`') {
                    return None;
                }
                match assignment_name(raw) {
                    Some(name) if raw.as_bytes().get(name.len()) == Some(&b'=') => {
                        self.stmt.names.push(name.to_string());
                    }
                    Some(_) => return None,
                    None if raw.starts_with('-') => return None,
                    None => self.stmt.pure = false,
                }
            }
            Simple::Printf if dequote(raw).starts_with("-v") => return None,
            Simple::Wait if dequote(raw).starts_with('-') => return None,
            _ => self.stmt.pure = false,
        }
        Some(())
    }

    /// End the current statement with `term`, recording what a dominating
    /// one bound.
    fn end_statement(&mut self, term: Term) -> Option<()> {
        let stmt = std::mem::take(&mut self.stmt);
        let dominates = stmt.eligible
            && stmt.pure
            && !stmt.names.is_empty()
            && self.compound == 0
            && matches!(term, Term::Seq | Term::And | Term::Or);
        if dominates {
            for name in stmt.names {
                if self.bound.insert(name.clone()) {
                    if let Some(here) = self.bound_at.last_mut() {
                        here.push(name);
                    }
                }
            }
        }
        self.stmt = Statement {
            eligible: self.compound == 0
                && match term {
                    Term::Seq | Term::Background => true,
                    Term::And => dominates,
                    Term::Or | Term::Pipe | Term::Close => false,
                },
            pure: true,
            names: Vec::new(),
        };
        self.cmd_pos = true;
        self.redirect_target = false;
        self.prev_word = None;
        self.simple = Simple::None;
        Some(())
    }
}

/// Length of the identifier `rest` starts with (0 when none).
fn ident_len(rest: &str) -> usize {
    let bytes = rest.as_bytes();
    if !bytes
        .first()
        .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
    {
        return 0;
    }
    bytes
        .iter()
        .position(|c| !(c.is_ascii_alphanumeric() || *c == b'_'))
        .unwrap_or(bytes.len())
}

/// The name a `NAME=`, `NAME+=` or `NAME[` word starts with.
fn assignment_name(raw: &str) -> Option<&str> {
    let len = ident_len(raw);
    let rest = &raw[len..];
    (len > 0 && (rest.starts_with('=') || rest.starts_with("+=") || rest.starts_with('[')))
        .then(|| &raw[..len])
}

/// A word with its quotes and backslashes removed — over-eager inside double
/// quotes, which only reads more words as a refused builtin.
fn dequote(raw: &str) -> String {
    raw.chars().filter(|c| !matches!(c, '\'' | '"' | '\\' | '\n')).collect()
}

/// Can an expanding heredoc body line assign a variable in this shell? Its
/// `$( )` and backticks run in their own process; `${…}` operators and
/// arithmetic run here.
fn body_may_assign(line: &str) -> bool {
    if line.contains("$((") || line.contains("$[") {
        return true;
    }
    let mut rest = line;
    while let Some(at) = rest.find("${") {
        let after = &rest[at + 2..];
        let len = ident_len(after);
        if len == 0 || after.as_bytes().get(len) != Some(&b'}') {
            return true;
        }
        rest = &after[len..];
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved(command: &str) -> String {
        resolve_literal_dir_variables(command).into_owned()
    }

    /// Shapes the issue reported and their everyday siblings: each read
    /// resolves to the literal.
    #[test]
    fn resolves_a_literal_bound_directory_target() {
        let cases: &[(&str, &str)] = &[
            // cameronsjo/cadence-hooks#1287, the enforce-worktree report.
            (
                r#"M=/abs/meta; (cd "$M" && npx markdownlint-cli2 a.md); git -C "$M" add a.md; git -C "$M" commit -F /tmp/msg -- a.md"#,
                r#"M=/abs/meta; (cd "/abs/meta" && npx markdownlint-cli2 a.md); git -C "/abs/meta" add a.md; git -C "/abs/meta" commit -F /tmp/msg -- a.md"#,
            ),
            // The prevent-secret-push report.
            (
                r#"W=/abs/wt; git -C "$W" fetch origin --quiet; git -C "$W" merge-tree --write-tree a b"#,
                r#"W=/abs/wt; git -C "/abs/wt" fetch origin --quiet; git -C "/abs/wt" merge-tree --write-tree a b"#,
            ),
            ("M=/a && git -C $M commit", "M=/a && git -C /a commit"),
            ("M=/a\ngit -C ${M} commit", "M=/a\ngit -C /a commit"),
            (
                r#"export M=/a; cd "$M/sub" && git commit"#,
                r#"export M=/a; cd "/a/sub" && git commit"#,
            ),
            (r#"M='/a'; pushd "${M}""#, r#"M='/a'; pushd "/a""#),
            (r#"M="/a"; git -C"$M" log"#, r#"M="/a"; git -C"/a" log"#),
            (
                r#"G=/r/.git; T=/r; git --git-dir="$G" --work-tree "$T" commit"#,
                r#"G=/r/.git; T=/r; git --git-dir="/r/.git" --work-tree "/r" commit"#,
            ),
            ("A=/a && B=/b; git -C $B log", "A=/a && B=/b; git -C /b log"),
            ("M=/a || true; git -C $M log", "M=/a || true; git -C /a log"),
            // A group reads what was assigned before it opened.
            (
                r#"M=/a; ( cd "$M" ); x=$(git -C "$M" rev-parse HEAD)"#,
                r#"M=/a; ( cd "/a" ); x=$(git -C "/a" rev-parse HEAD)"#,
            ),
            // Inside a group, an assignment binds for the rest of that group.
            ("(M=/a; git -C $M commit)", "(M=/a; git -C /a commit)"),
            // A loop body after the assignment.
            (
                "M=/a; for f in x y; do git -C \"$M\" add \"$f\"; done",
                "M=/a; for f in x y; do git -C \"/a\" add \"$f\"; done",
            ),
            // Repeating the same literal is harmless.
            ("M=/a; M=/a; git -C $M log", "M=/a; M=/a; git -C /a log"),
            // A heredoc with a quoted delimiter is data; the scan continues
            // past its terminator.
            (
                "M=/a; git -C \"$M\" commit -F - <<'EOF'\nread $M\nEOF\ngit -C \"$M\" log",
                "M=/a; git -C \"/a\" commit -F - <<'EOF'\nread $M\nEOF\ngit -C \"/a\" log",
            ),
            // Single-quoted text is data to this shell.
            (
                "M=/a; git -C \"$M\" commit -m 'eval read $M'",
                "M=/a; git -C \"/a\" commit -m 'eval read $M'",
            ),
            // A relative literal resolves to itself; the guard reads it
            // against wherever the shell is then.
            ("M=sub; cd $M", "M=sub; cd sub"),
            // Controls for refusals below: the same shapes with nothing that
            // can assign still resolve, so each refusal is the hazard's.
            (
                "M=/a; 2>/dev/null true x; git -C $M log",
                "M=/a; 2>/dev/null true x; git -C /a log",
            ),
            (
                "M=/a; command -v git; git -C $M log",
                "M=/a; command -v git; git -C /a log",
            ),
            (
                "M=/a; printf '%s' x; git -C $M log",
                "M=/a; printf '%s' x; git -C /a log",
            ),
            ("M=/a; wait; git -C $M log", "M=/a; wait; git -C /a log"),
            (
                "M=/a; export N=/b; git -C $M log",
                "M=/a; export N=/b; git -C /a log",
            ),
            (
                "M=/a; cat <<EOF\n$(id) ${HOME}\nEOF\ngit -C $M log",
                "M=/a; cat <<EOF\n$(id) ${HOME}\nEOF\ngit -C /a log",
            ),
            (
                "M=/a; x=$(pwd) y=1; git -C $M log",
                "M=/a; x=$(pwd) y=1; git -C /a log",
            ),
        ];
        for (command, want) in cases {
            assert_eq!(resolved(command), *want, "{command}");
        }
    }

    /// Every shape that may not hold the literal at the read, or that this
    /// scan cannot vouch for, is left exactly as written.
    #[test]
    fn leaves_every_unprovable_shape_as_written() {
        let cases: &[(&str, &str)] = &[
            ("M=$(pwd); git -C \"$M\" commit", "substitution"),
            ("M=`pwd`; git -C \"$M\" commit", "backtick"),
            ("M=/a$X; git -C \"$M\" commit", "expansion in value"),
            ("M=\"/a b\"; git -C \"$M\" commit", "blank in value"),
            ("M=~/a; git -C \"$M\" commit", "tilde"),
            ("M=/a*; git -C \"$M\" commit", "glob"),
            ("M={/a,/b}; git -C \"$M\" commit", "brace"),
            ("M=; git -C \"$M\" commit", "empty"),
            ("M=(/a); git -C \"$M\" commit", "array"),
            ("git -C \"$M\" commit", "never assigned"),
            ("git -C \"$M\" commit; M=/a", "assigned after the read"),
            ("M=/a git -C \"$M\" commit", "prefix assignment"),
            ("M=/a cd x; git -C \"$M\" commit", "prefix assignment, later read"),
            ("M=/a | true; git -C \"$M\" commit", "pipeline element"),
            ("M=/a & git -C \"$M\" commit", "backgrounded"),
            ("(M=/a); git -C \"$M\" commit", "subshell assignment"),
            ("{ M=/a; }; git -C \"$M\" commit", "group assignment"),
            ("x=$(M=/a); git -C \"$M\" commit", "substitution assignment"),
            ("false || M=/a; git -C \"$M\" commit", "|| conditional"),
            ("false && M=/a; git -C \"$M\" commit", "&& conditional"),
            ("cd /x && M=/a; git -C \"$M\" commit", "&& after a command"),
            ("if x; then M=/a; fi; git -C \"$M\" commit", "if branch"),
            ("while x; do M=/a; done; git -C \"$M\" commit", "loop body"),
            ("M=/a; M=/b; git -C \"$M\" commit", "reassigned"),
            ("M=/a; if x; then M=/p; fi; git -C \"$M\" commit", "conditional reassign"),
            ("M=/a; M+=/b; git -C \"$M\" commit", "append"),
            ("M=/a; unset M; git -C \"$M\" commit", "unset"),
            ("M=/a; read M </f; git -C \"$M\" commit", "read"),
            ("M=/a; for M in /p; do :; done; git -C \"$M\" commit", "for name"),
            ("M=/a; : ${M:=/p}; git -C \"$M\" commit", "default assign"),
            ("M=/a; git -C \"${M:-/p}\" commit", "operator read"),
            ("M=/a; f() { M=/p; }; f; git -C \"$M\" commit", "function reassign"),
            ("M=/a; n=M; read \"$n\" </f; git -C \"$M\" commit", "dynamic read"),
            ("M=/a; read \"$n\" </f; git -C \"$M\" commit", "read, name unknown"),
            ("M=/a; r''ead \"$n\"; git -C \"$M\" commit", "quoted read"),
            ("M=/a; \\read \"$n\"; git -C \"$M\" commit", "escaped read"),
            ("M=/a; command read \"$n\"; git -C \"$M\" commit", "command read"),
            ("M=/a; command -p read \"$n\"; git -C \"$M\" commit", "command -p read"),
            ("M=/a; 2>/dev/null read \"$n\"; git -C \"$M\" commit", "redirect first"),
            ("M=/a; >f read \"$n\"; git -C \"$M\" commit", "redirect target first"),
            ("M=/a; x=1 read \"$n\"; git -C \"$M\" commit", "prefix then read"),
            ("M=/a; (read \"$n\"; git -C \"$M\" commit)", "read in group"),
            ("M=/a; $c \"$n\"; git -C \"$M\" commit", "dynamic command word"),
            ("M=/a; \"$c\" x; git -C \"$M\" commit", "quoted dynamic command"),
            ("M=/a; eval \"$s\"; git -C \"$M\" commit", "eval"),
            ("M=/a; source ./env; git -C \"$M\" commit", "source"),
            ("M=/a; . ./env; git -C \"$M\" commit", "dot"),
            ("M=/a; declare -u M=/a; git -C \"$M\" commit", "declare"),
            ("M=/a; local M=/a; git -C \"$M\" commit", "local"),
            ("M=/a; export \"$n=/p\"; git -C \"$M\" commit", "dynamic export"),
            ("M=/a; printf -v \"$n\" /p; git -C \"$M\" commit", "printf -v"),
            ("M=/a; printf -v\"$n\" /p; git -C \"$M\" commit", "printf -v glued"),
            ("M=/a; wait -p \"$n\"; git -C \"$M\" commit", "wait -p"),
            ("M=/a; let \"$n=1\"; git -C \"$M\" commit", "let"),
            ("M=/a; (( $n = 1 )); git -C \"$M\" commit", "arithmetic command"),
            ("M=/a; x=$(( $n = 1 )); git -C \"$M\" commit", "arithmetic expansion"),
            ("M=/a; x=$[ $n = 1 ]; git -C \"$M\" commit", "old arithmetic"),
            ("M=/a; [[ $n -eq 1 ]]; git -C \"$M\" commit", "[[ arithmetic"),
            ("M=/a; a[$n=1]=x; git -C \"$M\" commit", "array subscript"),
            ("M=/a; x=${y^}; git -C \"$M\" commit", "case operator"),
            ("M=/a; x=${!y}; git -C \"$M\" commit", "indirection"),
            ("M=/a; x=$'\\x4d'; git -C \"$M\" commit", "ansi-c"),
            ("M=/a; trap 'x' DEBUG; git -C \"$M\" commit", "trap"),
            ("M=/a; alias g=x; git -C \"$M\" commit", "alias"),
            ("M=/a; case x in x) ;; esac; git -C \"$M\" commit", "case"),
            ("M=/a; function f { :; }; git -C \"$M\" commit", "function keyword"),
            ("M=/a; git -C \"$M\" commit -m \"`id`\"", "backtick in dquote"),
            ("M=/a; cat <<EOF\n${M:=x}\nEOF\ngit -C \"$M\" commit", "assigning body"),
            ("M=/a; cat <<EOF\nno end\ngit -C \"$M\" commit", "unterminated heredoc"),
            ("M=/a; cat <<E'O'F\nx\nEOF\ngit -C \"$M\" commit", "split delimiter"),
            ("PWD=/a; cd x; git -C \"$PWD\" commit", "shell-managed name"),
            ("IFS=/; M=/a; git -C $M commit", "IFS changed"),
            ("M=/a; git -C \"$M\" commit -m \"M=/p\"", "conflicting mention"),
            ("M=/a; (git -C \"$M\" commit", "unbalanced group"),
            ("M=/a; echo \"$M", "unterminated quote"),
            ("M=/a; git -C '$M' commit", "single-quoted read"),
            ("M=/a; git -C \\$M commit", "escaped read"),
            ("M=/a; bash -c 'git -C \"$M\" commit'", "child script"),
            ("M=/a; git -C \"$MX\" commit", "different name"),
        ];
        for (command, why) in cases {
            assert_eq!(
                resolved(command),
                *command,
                "{why}: must be left as written"
            );
        }
    }

    /// Reads outside a directory operand stay as written: the rewrite is
    /// scoped to what the guards resolve.
    #[test]
    fn rewrites_only_directory_operands() {
        for command in [
            "M=/a; echo $M",
            "M=/a; git -C /x add \"$M\"",
            "M=/a; cat \"$M/x\"",
            "M=/a; cd -- \"$M\"",
        ] {
            assert_eq!(resolved(command), command);
        }
    }

    #[test]
    fn a_flood_of_assignments_and_reads_stays_linear() {
        let mut command = String::new();
        let mut i = 0;
        while command.len() < 200 * 1024 {
            command.push_str(&format!("X{i}=/a/b; git -C \"$X{i}\" status; "));
            i += 1;
        }
        let started = std::time::Instant::now();
        let out = resolve_literal_dir_variables(&command);
        assert!(out.contains("git -C \"/a/b\" status"));
        // Debug builds are several times slower than the release binary the
        // budget is for.
        assert!(started.elapsed() < std::time::Duration::from_secs(5));

        let mut command = String::from("X=/a; ");
        while command.len() < 200 * 1024 {
            command.push_str("git -C \"$X\" status; ");
        }
        let started = std::time::Instant::now();
        assert!(!resolve_literal_dir_variables(&command).contains("$X"));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
}
