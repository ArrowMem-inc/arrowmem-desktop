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
    let (mut ruled_line, mut ruled_bit, mut ruled_bit_missing) = (0usize, 0usize, 0usize);
    for c in cases {
        let texts: Vec<&str> = c["texts"].as_array().unwrap().iter().map(|t| t.as_str().unwrap()).collect();
        let d = if c["distress"].as_bool().unwrap() { urgent::Distress::Available } else { urgent::Distress::Missing };
        let got = urgent::urgent_reply(&texts, c["lang"].as_str().unwrap(), d).map(|r| (r.line.to_string(), r.self_harm));
        let want = c["out"].as_array().map(|a| (a[0].as_str().unwrap().to_string(), a[1].as_bool().unwrap()));
        if got == want { continue; }
        // The ONE ruled change from the pinned original. A pet message that also carries the person's own urgent words now answers
        // "the 911 line, a blank line, the vet line", where the original answered the vet line alone. Counted, so any other drift still fails.
        // the prefix must be exactly the 911 line of the vector's language, read from the gate itself (a plain chest pain turn), never retyped
        let person = urgent::urgent_reply(&["my chest hurts"], c["lang"].as_str().unwrap(), urgent::Distress::Available).unwrap().line;
        // The SECOND ruled change. The pinned original returned the 988 bit false on the animal path; the web gate now carries
        // `_self_harm(blank_overdose(message))` there, so the bit may differ only as false in the original and true here. Counted too.
        // The bit itself is proven against the web gate's current vectors in tests/pet_person.rs.
        let moved = match (&got, &want) {
            (Some((g, gs)), Some((w, ws))) if (*g == *w || *g == format!("{person}\n\n{w}")) && (gs == ws || (!*ws && *gs)) => Some((g != w, gs != ws)),
            _ => None,
        };
        match moved {
            Some((line_moved, bit_moved)) => {
                ruled_line += usize::from(line_moved);
                if bit_moved { if d == urgent::Distress::Missing { ruled_bit_missing += 1 } else { ruled_bit += 1 } }
            }
            None => bad.push(format!("{texts:?} lang={} got {got:?} want {want:?}", c["lang"])),
        }
    }
    assert_eq!((ruled_line, ruled_bit, ruled_bit_missing), (42, 243, 850), "the ruled changes move exactly these vectors: (line, bit with the list, bit with the list missing)");
    assert!(bad.is_empty(), "{} of {} differ, first: {:#?}", bad.len(), cases.len(), &bad[..bad.len().min(5)]);
}
