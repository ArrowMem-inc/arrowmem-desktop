//! The crisis line is a closed type. Two guards: what the gate emits is only a cleared line or the 911 line then the vet line, and the
//! type has no way in from outside urgent.rs.
use arrowbridge::gates::urgent::{self, Distress};
use serde_json::Value;
use std::collections::BTreeSet;

fn json(name: &str) -> Value {
    let raw = std::fs::read_to_string(format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"))).expect("vectors");
    serde_json::from_str(&raw).expect("json")
}

/// The cleared lines are read from the Python original's own vectors (every `out` line of the urgent cases), never from the Rust code under test. The only
/// other line the gate may emit is the 911 line, a blank line, then the vet line, with both parts read the same way.
#[test]
fn every_crisis_line_the_gate_emits_is_a_cleared_line_or_the_911_then_vet_join() {
    let parity = json("gates_vectors.json");
    let cases = parity["urgent"].as_array().expect("urgent");
    let mut cleared: BTreeSet<String> = BTreeSet::new();
    for c in cases {
        if let Some(o) = c["out"].as_array() { cleared.insert(o[0].as_str().expect("line").to_string()); }
    }
    let pet = json("urgent_pet_person.json");
    let pet_cases = pet["vectors"].as_array().expect("vectors");
    let mut joins = BTreeSet::new();
    for lang in ["en_ca", "fr_ca"] {
        let line = |t: &str| urgent::urgent_reply(&[t], lang, Distress::Available).expect("a reply").line.to_string();
        // the probes pick out the three lines; each must itself be in the cleared set read from the vectors
        let (person, vet) = (line("my chest hurts"), line("my dog ate chocolate"));
        assert!(cleared.contains(&person) && cleared.contains(&vet), "{lang}: a probe line is not in the original's vectors");
        joins.insert(format!("{person}\n\n{vet}"));
    }
    assert!(cleared.len() >= 6 && joins.len() == 2, "{} cleared lines, {} joins", cleared.len(), joins.len());
    let mut seen = 0;
    let mut check = |texts: Vec<&str>, lang: &str, d: Distress| {
        if let Some(r) = urgent::urgent_reply(&texts, lang, d) {
            seen += 1;
            let s = r.line.to_string();
            assert!(!s.is_empty() && (cleared.contains(&s) || joins.contains(&s)), "{texts:?} {lang}: not a cleared line: {s:?}");
        }
    };
    for c in cases {
        let texts: Vec<&str> = c["texts"].as_array().expect("texts").iter().map(|t| t.as_str().expect("t")).collect();
        let d = if c["distress"].as_bool().expect("d") { Distress::Available } else { Distress::Missing };
        check(texts, c["lang"].as_str().expect("lang"), d);
    }
    for c in pet_cases {
        check(vec![c["text"].as_str().expect("t")], c["lang"].as_str().expect("lang"), Distress::Available);
    }
    assert!(seen > 100, "only {seen} crisis replies were checked");
}

/// The type is closed: in urgent.rs the only constructors are two private fns, and nothing makes one from outside (no pub constructor, From, Default, serde,
/// DerefMut, public field). Also no other file of this crate names the type's constructors.
#[test]
fn the_crisis_line_type_can_only_be_built_inside_urgent_rs() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let urgent_src = std::fs::read_to_string(dir.join("gates/urgent.rs")).expect("urgent.rs");
    let code: String = urgent_src.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
    assert!(code.contains("pub struct CrisisLine(Cow<'static, str>);"), "the field must stay private");
    assert_eq!(code.matches("Self(Cow::").count(), 2, "exactly two constructors");
    assert_eq!(code.matches("CrisisLine::constant(").count() + code.matches("CrisisLine::person_then_vet(").count(), 3, "the gate's own call sites");
    for banned in ["pub fn constant", "pub fn person_then_vet", "pub fn new", "From<", "Default", "DerefMut", "Deserialize", "AsMut", "pub fn from"] {
        assert!(!code.contains(banned), "urgent.rs contains {banned}");
    }
    for entry in std::fs::read_dir(dir.join("gates")).expect("gates").chain(std::fs::read_dir(&dir).expect("src")) {
        let p = entry.expect("entry").path();
        if p.extension().is_some_and(|e| e == "rs") && !p.ends_with("urgent.rs") {
            let s = std::fs::read_to_string(&p).expect("src");
            assert!(!s.contains("CrisisLine"), "{} names CrisisLine", p.display());
        }
    }
}
