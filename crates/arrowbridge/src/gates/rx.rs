//! One regex wrapper for every gate. It makes Rust's engine answer as PYTHON's `re` does on the same text, then fails closed where the engine gives up.
//!
//! Differences found against the pinned originals and closed here (each has a vector or a test):
//!  - `\s` also matches 0x1c to 0x1f in Python (rewritten, `python_space`).
//!  - `\w` and `\b`: Python's word character is a letter, a number or `_` (str.isalnum); Rust's also counts combining marks, joiners and connector
//!    punctuation, and misses the number-other characters (superscripts, fractions). Before matching, the text is mapped one character to one character
//!    (`normalize`) so both engines see the same word characters; the offsets are mapped back, so the text a guard returns is always the ORIGINAL text.
//!  - ignore-case: Python folds U+0130 and U+0131 to `i`, Rust does not (mapped to `i` when the pattern is case-insensitive).
//!  - speed and give-up: a pattern with a lookaround runs on the slow backtracking engine and used to give up on ordinary long prose. A linear prefilter
//!    (the same pattern with the lookarounds removed, which can only match MORE) answers "no match" at once for benign text; only a text that passes it reaches
//!    the slow engine. A real give-up (the backtrack limit) is reported to the caller, which decides the safe side for that pattern.
use super::patterns_gen::Pat;
use fancy_regex::{Regex, RegexBuilder};
use std::sync::OnceLock;

/// Generous: only a runaway reaches it (the prefilter keeps benign text off the slow engine).
const BACKTRACK_LIMIT: usize = 50_000_000;

/// Python's `\s` also matches the four ASCII separators 0x1c to 0x1f (str.isspace); Rust's does not. Rewrite every `\s` so the two engines agree
/// (inside a character class the range is added, outside the class becomes one). `\S` is not used by any gate pattern and is refused loudly.
fn python_space(pat: &str) -> String {
    let mut out = String::with_capacity(pat.len() + 16);
    let (mut in_class, mut it) = (false, pat.chars().peekable());
    while let Some(c) = it.next() {
        match c {
            '\\' => match it.next() {
                Some('s') => out.push_str(if in_class { "\\s\\x1c-\\x1f" } else { "[\\s\\x1c-\\x1f]" }),
                Some('S') => panic!("a gate pattern uses \\S: translate it before use"),
                Some(n) => { out.push('\\'); out.push(n); }
                None => out.push('\\'),
            },
            '[' if !in_class => { in_class = true; out.push(c); }
            ']' if in_class => { in_class = false; out.push(c); }
            _ => out.push(c),
        }
    }
    out
}


/// The same pattern with every lookaround group removed: it can only match MORE than the original, so "no match" from it is a sure "no match".
fn strip_lookarounds(p: &str) -> String {
    let cs: Vec<char> = p.chars().collect();
    let starts = |i: usize, s: &str| cs[i..].iter().take(s.chars().count()).copied().eq(s.chars());
    let (mut out, mut i, mut in_class) = (String::with_capacity(p.len()), 0usize, false);
    while i < cs.len() {
        let c = cs[i];
        if c == '\\' { out.push(c); if i + 1 < cs.len() { out.push(cs[i + 1]); } i += 2; continue; }
        if in_class { if c == ']' { in_class = false; } out.push(c); i += 1; continue; }
        if c == '[' { in_class = true; out.push(c); i += 1; continue; }
        let la = ["(?=", "(?!", "(?<=", "(?<!"].into_iter().find(|s| c == '(' && starts(i, s));
        if let Some(s) = la {
            let (mut depth, mut j, mut cls) = (1usize, i + s.chars().count(), false);
            while j < cs.len() && depth > 0 {
                match cs[j] {
                    '\\' => j += 1,
                    ']' if cls => cls = false,
                    '[' if !cls => cls = true,
                    '(' if !cls => depth += 1,
                    ')' if !cls => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            i = j;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Characters where the two engines disagree about "word": Rust's `\w` but not Python's (marks, joiners, connector punctuation, enclosed letters) and Python's
/// but not Rust's (number-other: superscripts, fractions).
fn word_diff() -> &'static regex::Regex {
    static R: OnceLock<regex::Regex> = OnceLock::new();
    R.get_or_init(|| regex::Regex::new(r"[\w--[\p{L}\p{N}_]]|[\p{N}--\w]").expect("word diff class"))
}

/// The text as Rust must see it, and (when anything changed) the original byte offset of every normalized byte, plus one past the end.
struct Norm { text: String, map: Option<Vec<usize>> }

fn normalize(text: &str, ci: bool) -> Norm {
    if text.is_ascii() { return Norm { text: text.to_string(), map: None }; }
    let (mut out, mut map, mut changed) = (String::with_capacity(text.len()), Vec::with_capacity(text.len() + 1), false);
    let mut buf = [0u8; 4];
    for (i, c) in text.char_indices() {
        let rep = if c.is_ascii() { None }
            else if ci && (c == '\u{130}' || c == '\u{131}') { Some('i') }
            else if word_diff().is_match(c.encode_utf8(&mut buf)) { Some(if c.is_numeric() { '_' } else { '\u{1}' }) }
            else { None };
        match rep {
            Some(r) => { changed = true; out.push(r); map.push(i); }
            None => { out.push(c); for k in 0..c.len_utf8() { map.push(i + k); } }
        }
    }
    map.push(text.len());
    if changed { Norm { text: out, map: Some(map) } } else { Norm { text: text.to_string(), map: None } }
}

impl Norm {
    fn orig(&self, n: usize) -> usize { self.map.as_ref().map(|m| m[n]).unwrap_or(n) }
}

/// One match, as slices of the ORIGINAL text.
pub struct Hit<'a> { pub whole: &'a str, pub group1: Option<&'a str> }

pub struct Rx { re: Regex, pre: Option<regex::Regex>, ci: bool }

impl Rx {
    pub fn new(p: &Pat) -> Rx { Rx::from_parts(p.name, p.flags, p.text) }

    /// A pattern written in this crate (the companion's own few), with Python's flag letters ("i", "m", "s", "x").
    pub fn from_parts(name: &str, flag_letters: &str, text: &str) -> Rx {
        let flags = if flag_letters.is_empty() { String::new() } else { format!("(?{flag_letters})") };
        let translated = python_space(text);
        let re = RegexBuilder::new(&format!("{flags}{translated}")).backtrack_limit(BACKTRACK_LIMIT).build();
        let pre = regex::Regex::new(&format!("{flags}{}", strip_lookarounds(&translated))).ok();
        Rx { re: re.unwrap_or_else(|e| panic!("pattern {name} does not compile: {e}")), pre, ci: flag_letters.contains('i') }
    }

    /// Python's `bool(r.search(text))`. Err when the engine gave up (the caller picks the safe answer for THIS pattern).
    pub fn try_search(&self, text: &str) -> Result<bool, ()> {
        let n = normalize(text, self.ci);
        if let Some(pre) = &self.pre { if !pre.is_match(&n.text) { return Ok(false); } }
        self.re.is_match(&n.text).map_err(|_| ())
    }

    /// `try_search` where a give-up counts as a match.
    pub fn search(&self, text: &str) -> bool { self.try_search(text).unwrap_or(true) }

    /// Python's `r.sub(rep, text)` with a fixed replacement. On a give-up the text is returned unchanged.
    pub fn replace_all(&self, text: &str, rep: &str) -> String {
        self.sub_with(text, |_| rep.to_string()).unwrap_or_else(|| text.to_string())
    }

    /// Python's `r.findall(text)` for a pattern without groups: every whole match, in order, as the original text. None when the engine gives up.
    pub fn find_all(&self, text: &str) -> Option<Vec<String>> {
        let mut out = Vec::new();
        self.each(text, |h| out.push(h.whole.to_string()))?;
        Some(out)
    }

    /// Python's `r.sub(f, text)`: each match replaced by `f(hit)`. None when the engine gives up.
    pub fn sub_with(&self, text: &str, mut f: impl FnMut(&Hit) -> String) -> Option<String> {
        let n = normalize(text, self.ci);
        if let Some(pre) = &self.pre { if !pre.is_match(&n.text) { return Some(text.to_string()); } }
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for caps in self.re.captures_iter(&n.text) {
            let caps = caps.ok()?;
            let m = caps.get(0)?;
            let (s, e) = (n.orig(m.start()), n.orig(m.end()));
            out.push_str(&text[last..s]);
            let g1 = caps.get(1).map(|g| &text[n.orig(g.start())..n.orig(g.end())]);
            out.push_str(&f(&Hit { whole: &text[s..e], group1: g1 }));
            last = e;
        }
        out.push_str(&text[last..]);
        Some(out)
    }

    fn each(&self, text: &str, mut f: impl FnMut(&Hit)) -> Option<()> {
        let n = normalize(text, self.ci);
        if let Some(pre) = &self.pre { if !pre.is_match(&n.text) { return Some(()); } }
        for caps in self.re.captures_iter(&n.text) {
            let caps = caps.ok()?;
            let m = caps.get(0)?;
            let g1 = caps.get(1).map(|g| &text[n.orig(g.start())..n.orig(g.end())]);
            f(&Hit { whole: &text[n.orig(m.start())..n.orig(m.end())], group1: g1 });
        }
        Some(())
    }

    /// The first match (Python's `r.match(text)` for a pattern starting with \A): the end of the match (original offset) and capture group 1. Err when the engine gives up.
    pub fn first_capture(&self, text: &str) -> Result<Option<(usize, String)>, ()> {
        let n = normalize(text, self.ci);
        match self.re.captures(&n.text) {
            Ok(Some(c)) => Ok(Some((n.orig(c.get(0).map(|m| m.end()).unwrap_or(0)), c.get(1).map(|g| text[n.orig(g.start())..n.orig(g.end())].to_string()).unwrap_or_default()))),
            Ok(None) => Ok(None),
            Err(_) => Err(()),
        }
    }
}

/// Python's `re.sub(r"[ \t]{2,}", " ", s)` then `re.sub(r" ([.,;:!?])", r"\1", s)`: the tidy-up both guards do after removing a claim.
pub fn tidy(s: &str) -> String {
    let mut collapsed = String::with_capacity(s.len());
    let mut run = 0usize;
    let mut run_start = 0usize;
    for (i, c) in s.char_indices() {
        if c == ' ' || c == '\t' {
            if run == 0 { run_start = i; }
            run += 1;
        } else {
            if run > 0 { collapsed.push_str(if run >= 2 { " " } else { &s[run_start..i] }); run = 0; }
            collapsed.push(c);
        }
    }
    if run > 0 { collapsed.push_str(if run >= 2 { " " } else { &s[run_start..] }); }
    let mut out = String::with_capacity(collapsed.len());
    let mut chars = collapsed.chars().peekable();
    while let Some(c) = chars.next() {
        if c == ' ' && matches!(chars.peek(), Some('.' | ',' | ';' | ':' | '!' | '?')) { continue; }
        out.push(c);
    }
    out
}
