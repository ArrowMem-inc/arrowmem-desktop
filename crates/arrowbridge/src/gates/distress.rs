//! Port of mvf_distress.shows_distress: the person's own message against the active and the passive lists. Returns a bool and nothing else (zero retention).
use super::patterns_gen as p;
use super::rx::Rx;
use std::sync::OnceLock;

struct Lists { en: Rx, fr: Rx, passive: Rx }

fn lists() -> &'static Lists {
    static L: OnceLock<Lists> = OnceLock::new();
    L.get_or_init(|| Lists { en: Rx::new(&p::SELF_HARM_EN), fr: Rx::new(&p::SELF_HARM_FR), passive: Rx::new(&p::PASSIVE) })
}

pub fn shows_distress(text: &str) -> bool {
    let t = text.replace(['\u{2019}', '\u{2018}'], "'");
    let l = lists();
    l.en.search(&t) || l.fr.search(&t) || l.passive.search(&t)
}
