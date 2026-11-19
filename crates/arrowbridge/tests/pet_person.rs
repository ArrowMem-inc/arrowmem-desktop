//! A pet message that also carries the person's own self harm or urgent words keeps the person's help.
//! The vectors are the cloud gate's (the urgent_pet_person.json vector file, byte for byte). line A is the vet line, UA the 911 line first with
//! the vet line beside it. The 988 bit is read from the Reply itself (`r.self_harm`), never recomputed here: every consumer takes it from the Reply.
//! NAMED RESIDUAL (rust_line "A"): a French message with an UNACCENTED chest pain phrase ("mal a la poitrine") beside a pet that ate chocolate gets the vet line
//! alone in Rust, 911 plus vet on the web, because the pinned Rust lists lag the cloud. Not fixed here.
//! A vector with `rust_line` is a NAMED RESIDUAL: Rust answers that line today. When the pin moves and Rust answers `line`, this test fails: delete the `rust_line` field.
use arrowbridge::gates::urgent;
use serde_json::Value;

#[test]
fn the_shared_pet_and_person_vectors() {
    let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/urgent_pet_person.json")).expect("vectors");
    let v: Value = serde_json::from_str(&raw).expect("json");
    let mut bad = Vec::new();
    for c in v["vectors"].as_array().unwrap() {
        let (text, lang) = (c["text"].as_str().unwrap(), c["lang"].as_str().unwrap());
        let r = urgent::urgent_reply(&[text], lang, urgent::Distress::Available).expect("an animal reply");
        // the two cleared lines, read from the gate itself (a plain pet turn, a plain chest pain turn), never retyped
        let line = |t: &str| urgent::urgent_reply(&[t], lang, urgent::Distress::Available).unwrap().line.to_string();
        let (vet, person) = (line("my dog ate chocolate"), line("my chest hurts"));
        let code = c["rust_line"].as_str().unwrap_or(c["line"].as_str().unwrap());
        let want = if code == "A" { vet } else { format!("{person}\n\n{vet}") };
        if (r.line.to_string(), r.self_harm) != (want.clone(), c["sh"].as_bool().unwrap()) { bad.push(format!("{text:?} {lang} got {:?} {}", r.line, r.self_harm)); }
    }
    assert!(bad.is_empty(), "{} differ: {:#?}", bad.len(), bad);
}

/// Fail closed on the animal path too: no distress list means the 988 bit is true (web: `_self_harm(t, None)` is True).
#[test]
fn a_missing_distress_list_gives_the_988_bit_on_the_animal_path() {
    let r = urgent::urgent_reply(&["my dog ate chocolate"], "en_ca", urgent::Distress::Missing).expect("an animal reply");
    assert!(r.self_harm);
    let r = urgent::urgent_reply(&["my dog ate chocolate"], "en_ca", urgent::Distress::Available).expect("an animal reply");
    assert!(!r.self_harm);
}
