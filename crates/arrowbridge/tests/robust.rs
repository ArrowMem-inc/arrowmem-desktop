//! The gates never panic and never hang, whatever the text is (a safety gate that crashes or stalls is an outage). Deterministic pseudo-random input, no extra crate.
use arrowbridge::gates::{distress, urgent};
use std::time::{Duration, Instant};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; self.0 }
}

fn random_text(r: &mut Rng) -> String {
    const PIECES: &[&str] = &["chest ", "pain ", "overdose ", "je ", "veux ", "mourir ", "dog ", "ate ", "pills ", "drowsy ", "\n", "\u{1f}", "\u{2019}", "é", "😀", "I ", "want ", "to ", "die ",
        "no ", "point ", "going ", "on ", "about ", "(", ")", "[", "]", "\\", "'", " ", "  ", "\t", "\u{0}", "end ", "it ", "with ", "disappear ", "for "];
    let n = (r.next() % 40) as usize;
    (0..n).map(|_| PIECES[(r.next() as usize) % PIECES.len()]).collect()
}

#[test]
fn random_text_never_panics() {
    let mut r = Rng(0x9e3779b97f4a7c15);
    for _ in 0..20_000 {
        let a = random_text(&mut r);
        let b = random_text(&mut r);
        let _ = distress::shows_distress(&a);
        for d in [urgent::Distress::Available, urgent::Distress::Missing] {
            let _ = urgent::urgent_reply(&[&a], "en", d);
            let _ = urgent::urgent_reply(&[&a, &b], "fr-CA", d);
        }
    }
}

#[test]
fn long_adversarial_text_finishes_quickly() {
    let inputs = [
        "a ".repeat(60_000),
        "want to ".repeat(20_000),
        "overdose ".repeat(20_000),
        format!("{}die", "i ".repeat(40_000)),
        "no point in ".repeat(15_000),
        "\u{1f}".repeat(100_000),
        "(".repeat(100_000),
        "'".repeat(100_000),
        "é".repeat(100_000),
    ];
    for t in &inputs {
        let start = Instant::now();
        let _ = distress::shows_distress(t);
        let _ = urgent::urgent_reply(&[t], "en", urgent::Distress::Available);
        let _ = urgent::urgent_reply(&["hi", t], "en", urgent::Distress::Available);
        assert!(start.elapsed() < Duration::from_secs(20), "a gate took {:?} on a {} byte input", start.elapsed(), t.len());
    }
}

#[test]
fn an_empty_conversation_and_empty_text_say_nothing() {
    assert_eq!(urgent::urgent_reply(&[], "en", urgent::Distress::Available), None);
    assert_eq!(urgent::urgent_reply(&[""], "en", urgent::Distress::Available), None);
    assert!(!distress::shows_distress(""));
}

#[test]
fn the_output_guards_never_panic_and_never_hang() {
    use arrowbridge::gates::{factguard, linkgate, telguard};
    use std::collections::BTreeSet;
    let tel: BTreeSet<String> = ["911".to_string()].into();
    let none = BTreeSet::new();
    let mut r = Rng(0x2545f4914f6cdd1d);
    for _ in 0..20_000 {
        let t = random_text(&mut r) + "1-800-268-7708 ISP 3301 canada.ca/x Chapter 3";
        let _ = telguard::redact(&t, &tel);
        let _ = factguard::redact(&t, &none);
        let _ = linkgate::rewrite(&t, "canada.ca");
    }
    for t in ["1".repeat(200_000), "1-".repeat(100_000), "A".repeat(200_000), "canada.ca/".repeat(20_000), "ISP-".repeat(50_000), " ".repeat(200_000)] {
        let start = Instant::now();
        let _ = telguard::redact(&t, &tel);
        let _ = factguard::redact(&t, &none);
        let _ = linkgate::rewrite(&t, "");
        assert!(start.elapsed() < Duration::from_secs(20), "a guard took {:?} on {} bytes", start.elapsed(), t.len());
    }
}

#[test]
fn long_benign_prose_is_not_urgent_and_is_fast() {
    // Review finding 1: ordinary text of 4.7 KB and more used to answer "Call 911" because the slow engine gave up and a give-up counted as a match.
    let prose = "The Veterans Affairs disability benefit is described in section twelve of the guide. ".repeat(2500);
    let start = Instant::now();
    for d in [urgent::Distress::Available, urgent::Distress::Missing] {
        let r = urgent::urgent_reply(&[&prose], "en", d);
        if d == urgent::Distress::Available { assert_eq!(r, None, "benign prose must not be urgent"); }
    }
    assert!(!distress::shows_distress(&prose));
    assert!(urgent::urgent_reply(&[&format!("{prose} bleeding")], "en", urgent::Distress::Available).is_some(), "a real phrase at the end of long text is still caught");
    assert!(urgent::urgent_reply(&["a b ".repeat(60_000).as_str()], "en", urgent::Distress::Available).is_none());
    assert!(start.elapsed() < Duration::from_secs(5), "took {:?}", start.elapsed());
}

#[test]
fn marks_joiners_and_dotted_i_do_not_hide_a_crisis_phrase() {
    // Review findings 2 and 3, each answered by the original as urgent
    for t in ["he is unconscious\u{301}", "heart attack\u{200d}", "heart attack\u{fe0f}", "I have a se\u{130}zure", "\u{131} have a seizure", "my p\u{130}lls overdose"] {
        assert!(urgent::urgent_reply(&[t], "en", urgent::Distress::Available).is_some(), "{t:?}");
    }
}
