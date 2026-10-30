//! Port of the parts of mvf_pack_safety the companion uses: the engine crisis floor line (crisis_lines_or_default with no manifest), the practitioner route
//! with no manifest (none), and the filtered reply. The manifest-driven paths are not used by the companion and are not ported.
use super::patterns_gen as p;

/// Manifest label suffixes to try, most specific first (a separator split, never a positional slice).
fn suffixes(language: &str) -> Vec<String> {
    let code = language.trim().to_lowercase();
    if code.is_empty() { return Vec::new(); }
    let primary = code.split('_').next().unwrap_or("").split('-').next().unwrap_or("").to_string();
    if primary != code { vec![code, primary] } else { vec![code] }
}

/// The floor's own label in `language`, falling back to the other language rather than dropping the number (Python's `_pick` over label_en, label_fr).
fn floor_label(language: &str) -> &'static str {
    for s in suffixes(language) {
        match s.as_str() { "en" => return p::FLOOR_LABEL_EN, "fr" => return p::FLOOR_LABEL_FR, _ => {} }
    }
    // other languages: the first label by sorted key (label_en before label_fr)
    p::FLOOR_LABEL_EN
}

/// What a person receives with no pack: the engine floor, never empty. Python: `crisis_lines_or_default(None, language)`.
pub fn crisis_lines_default(language: &str) -> Vec<String> {
    vec![format!("{}: {}", floor_label(language), p::FLOOR_TEL)]
}

/// Python: `practitioner_line({}, language)` is None (no pack declares a route).
pub fn practitioner_line_none() -> Option<String> { None }

pub fn filtered_reply(language: &str) -> &'static str {
    if language.starts_with("fr") { p::FILTERED_REPLY_FR } else { p::FILTERED_REPLY_EN }
}
