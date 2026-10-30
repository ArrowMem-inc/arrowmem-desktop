//! Parity of the Rust gates with the pinned Python originals: every vector was answered by mvf_urgent / mvf_distress (scripts/gen_gate_vectors.py).
use arrowbridge::gates::{distress, urgent};
use serde_json::Value;

fn vectors() -> Value {
    let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/gates_vectors.json")).expect("vectors");
    serde_json::from_str(&raw).expect("json")
}

#[test]
fn distress_answers_like_the_original_on_every_vector() {
    let v = vectors();
    let cases = v["distress"].as_array().unwrap();
    let mut bad = Vec::new();
    for c in cases {
        let t = c["text"].as_str().unwrap();
        if distress::shows_distress(t) != c["out"].as_bool().unwrap() { bad.push(t.to_string()); }
    }
    assert!(bad.is_empty(), "{} of {} differ, first: {:?}", bad.len(), cases.len(), &bad[..bad.len().min(5)]);
}

#[test]
fn urgent_answers_like_the_original_on_every_vector() {
    let v = vectors();
    let cases = v["urgent"].as_array().unwrap();
    let mut bad = Vec::new();
    for c in cases {
        let texts: Vec<&str> = c["texts"].as_array().unwrap().iter().map(|t| t.as_str().unwrap()).collect();
        let d = if c["distress"].as_bool().unwrap() { urgent::Distress::Available } else { urgent::Distress::Missing };
        let got = urgent::urgent_reply(&texts, c["lang"].as_str().unwrap(), d).map(|r| (r.line.to_string(), r.self_harm));
        let want = c["out"].as_array().map(|a| (a[0].as_str().unwrap().to_string(), a[1].as_bool().unwrap()));
        if got != want { bad.push(format!("{texts:?} lang={} got {got:?} want {want:?}", c["lang"])); }
    }
    assert!(bad.is_empty(), "{} of {} differ, first: {:#?}", bad.len(), cases.len(), &bad[..bad.len().min(5)]);
}
