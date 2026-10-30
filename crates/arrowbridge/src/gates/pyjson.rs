//! `json.dumps(json.load(f))` as Python writes it (ensure_ascii, ", " and ": " separators): the guards run their patterns over that text, so the text must be
//! the same for the same file. Numbers: integers print as is, a float prints with Rust's shortest form (Python's differs only in exponent spelling, which no
//! pack file uses).
use serde_json::Value;

pub fn dumps(v: &Value) -> String {
    let mut out = String::new();
    write(v, &mut out);
    out
}

fn write(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => string(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() { if i > 0 { out.push_str(", "); } write(x, out); }
            out.push(']');
        }
        Value::Object(o) => {
            out.push('{');
            for (i, (k, x)) in o.iter().enumerate() { if i > 0 { out.push_str(", "); } string(k, out); out.push_str(": "); write(x, out); }
            out.push('}');
        }
    }
}

fn string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) { out.push_str(&format!("\\u{:04x}", u)); }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
