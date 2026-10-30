//! Port of mvf_urgent.urgent_reply: the deterministic urgent gate. A message describing an emergency happening now never reaches the model.
//! Returns the fixed line and whether the 988 line must go with it, or None to let the turn reach the model. Never calls a model, never logs or keeps which
//! phrase matched.
use super::patterns_gen as p;
use super::rx::Rx;
use super::distress;
use std::sync::OnceLock;

struct Pats {
    en: Rx, fr: Rx, walkback: Rx, od: Rx, info: Rx, near_person: Rx, intent_before: Rx, ingest: Rx, drowsy: Rx, pet_case: Rx, person_exposed: Rx, toxic: Rx, pet_swallowed: Rx,
}

fn pats() -> &'static Pats {
    static P: OnceLock<Pats> = OnceLock::new();
    P.get_or_init(|| Pats {
        en: Rx::new(&p::URGENT_EN), fr: Rx::new(&p::URGENT_FR), walkback: Rx::new(&p::WALKBACK), od: Rx::new(&p::OD), info: Rx::new(&p::INFO),
        near_person: Rx::new(&p::NEAR_PERSON), intent_before: Rx::new(&p::INTENT_BEFORE), ingest: Rx::new(&p::INGEST), drowsy: Rx::new(&p::DROWSY),
        pet_case: Rx::new(&p::PET_CASE), person_exposed: Rx::new(&p::PERSON_EXPOSED), toxic: Rx::new(&p::TOXIC), pet_swallowed: Rx::new(&p::PET_SWALLOWED),
    })
}

/// Whether the incoming-distress list is available. The cloud and the companion both pass the module; None fails closed (`self_harm` true).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Distress { Available, Missing }

fn self_harm(text: &str, d: Distress) -> bool {
    match d { Distress::Missing => true, Distress::Available => distress::shows_distress(text) }
}

// Policy when the regex engine gives up on a pattern (a runaway): always the side that is MORE urgent for a person. `yes` = the pattern counts as matched,
// `no` = it counts as not matched; each use below says which one is the safe side for it.
fn yes(r: &Rx, t: &str) -> bool { r.try_search(t).unwrap_or(true) }
fn no(r: &Rx, t: &str) -> bool { r.try_search(t).unwrap_or(false) }

fn mask_informational_overdose(t: &str) -> String {
    let q = pats();
    // masking makes a message LESS urgent: only when every condition is certain (a give-up on any of them means: do not mask)
    if no(&q.od, t) && no(&q.info, t) && !yes(&q.near_person, t) && !yes(&q.intent_before, t) {
        q.od.replace_all(t, " ")
    } else {
        t.to_string()
    }
}

fn is_urgent(text: &str, d: Distress) -> bool {
    let t = mask_informational_overdose(text);
    let q = pats();
    yes(&q.en, &t) || yes(&q.fr, &t) || (d == Distress::Available && distress::shows_distress(&t) && !t.trim().is_empty())
}

fn animal(message: &str) -> bool {
    let q = pats();
    // the animal line carries no 911 and no 988: it is the LESS urgent answer, so a give-up on any pattern means NOT an animal case
    no(&q.pet_case, message) && (no(&q.toxic, message) || no(&q.pet_swallowed, message)) && !yes(&q.person_exposed, message)
}

fn ingestion(message: &str, prior: &[&str]) -> bool {
    let q = pats();
    if !yes(&q.drowsy, message) { return false; }
    let mut joined = prior.join(" ");
    if !prior.is_empty() { joined.push(' '); }
    joined.push_str(message);
    yes(&q.ingest, &joined)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Reply { pub line: &'static str, pub self_harm: bool }

fn is_fr(lang: &str) -> bool { lang.starts_with("fr") }

pub fn urgent_reply(user_texts: &[&str], lang: &str, d: Distress) -> Option<Reply> {
    let (&message, rest) = user_texts.split_last()?;
    let prior: &[&str] = if rest.is_empty() { &[] } else { &rest[rest.len() - 1..] };
    let q = pats();
    if animal(message) {
        return Some(Reply { line: if is_fr(lang) { p::ANIMAL_LINE_FR } else { p::ANIMAL_LINE_EN }, self_harm: false });
    }
    let ingest = ingestion(message, prior);
    let urgent_now = is_urgent(message, d) || ingest;
    let walked_back = !prior.is_empty() && is_urgent(prior[0], d) && yes(&q.walkback, message);
    if !(urgent_now || walked_back) { return None; }
    let fr_only = yes(&q.fr, message) && !yes(&q.en, message);
    let fr = is_fr(lang) || fr_only;
    let line = match (ingest, fr) {
        (true, true) => p::INGEST_LINE_FR, (true, false) => p::INGEST_LINE_EN,
        (false, true) => p::URGENT_LINE_FR, (false, false) => p::URGENT_LINE_EN,
    };
    Some(Reply { line, self_harm: self_harm(message, d) || (walked_back && self_harm(prior[0], d)) })
}

/// Python: `mvf_urgent._OD.sub(" ", text)`, the overdose word blanked (the companion decides distress for an animal message with it).
pub fn blank_overdose(text: &str) -> String { pats().od.replace_all(text, " ") }
