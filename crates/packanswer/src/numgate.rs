//! Number in quote gate, a belt on top of code assembly. Every maximal run of Unicode numeric characters (a superset of general category Nd, so
//! the stricter side), with interior separators and an attached unit token, must EQUAL a run of a quote, a stored context or a source field of the same
//! answer, or be a fixed chrome constant. Anything else: the caller replaces the whole answer. Never strip a number and keep the sentence.
use crate::Found;
use std::collections::HashSet;

/// The fixed chrome constants. Everything else must come from the answer's own source text.
pub const CHROME: [&str; 2] = ["911", "988"];

fn is_sep(c: char) -> bool {
    matches!(c, '.' | ',' | ':' | '/' | '-')
}

/// Each digit run of `s` with its separators and unit token (letters or % directly after, or after one space).
fn runs(s: &str) -> Vec<&str> {
    let cs: Vec<(usize, char)> = s.char_indices().collect();
    let end_of = |k: usize| cs.get(k).map_or(s.len(), |c| c.0);
    let mut out = Vec::new();
    let mut i = 0;
    while i < cs.len() {
        if !cs[i].1.is_numeric() {
            i += 1;
            continue;
        }
        let start = cs[i].0;
        let mut j = i;
        while j < cs.len() && (cs[j].1.is_numeric() || (is_sep(cs[j].1) && cs.get(j + 1).is_some_and(|n| n.1.is_numeric()))) {
            j += 1;
        }
        if cs.get(j).is_some_and(|c| c.1 == ' ') && cs.get(j + 1).is_some_and(|c| c.1.is_alphabetic() || c.1 == '%') {
            j += 1;
        }
        while j < cs.len() && (cs[j].1.is_alphabetic() || cs[j].1 == '%') {
            j += 1;
        }
        out.push(&s[start..end_of(j)]);
        i = j.max(i + 1);
    }
    out
}

/// Host credit and disclaimer lines are pinned words from the copy owner: never scanned here and never part of the allowed set. Each shown run must EQUAL
/// a run of the answer's own source text, so "5" is not vouched for by "2026-11-05".
pub fn passes(found: &Found) -> bool {
    let source = found.blocks.iter().flat_map(|b| {
        [b.quote.as_str(), b.url.as_str(), b.retrieved.as_str()].into_iter().chain(b.context.as_deref()).chain(b.context_url.as_deref())
    });
    let allowed: HashSet<&str> = source.clone().flat_map(runs).chain(CHROME).collect();
    let keys = found.chrome.iter().copied().chain(found.blocks.iter().filter_map(|b| b.label));
    source.chain(keys).all(|s| runs(s).iter().all(|r| allowed.contains(r)))
}
