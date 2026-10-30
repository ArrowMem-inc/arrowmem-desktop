//! Port of mvf_link_gate.rewrite: any path, query or fragment after canada.ca or retraitequebec.gouv.qc.ca is cut back to the bare host. A link the person
//! typed this turn is never cut. The streaming LinkGate is not ported (the companion replies in one piece).
use super::patterns_gen as p;
use super::rx::Rx;
use std::sync::OnceLock;

fn fallback() -> &'static regex::Regex {
    static R: OnceLock<regex::Regex> = OnceLock::new();
    R.get_or_init(|| regex::Regex::new(r#"(?i)(canada\.ca|retraitequebec\.gouv\.qc\.ca)[/?#][^\s<>"'()\[\]]*"#).expect("link fallback"))
}

fn link() -> &'static Rx { static R: OnceLock<Rx> = OnceLock::new(); R.get_or_init(|| Rx::new(&p::LINK)) }

/// Python's `re.sub(r"^(?:https?://)?(?:www\.)?", "", url.lower())`.
fn bare(url: &str) -> String {
    let u = url.to_lowercase();
    let u = u.strip_prefix("https://").or_else(|| u.strip_prefix("http://")).unwrap_or(&u).to_string();
    u.strip_prefix("www.").map(str::to_string).unwrap_or(u)
}

pub fn rewrite(text: &str, typed: &str) -> String {
    let typed = typed.to_lowercase();
    link().sub_with(text, |c| {
        if typed.contains(&bare(c.whole)) { c.whole.to_string() } else { c.group1.map(str::to_lowercase).unwrap_or_default() }
    })
    // A give-up of the exact pattern must never leave a path on an official host: fall back to the linear rule that cuts EVERYTHING after the host
    // (it also drops trailing punctuation and ignores a link the person typed: shorter, never longer).
    .unwrap_or_else(|| fallback().replace_all(text, "$1").into_owned())
}
