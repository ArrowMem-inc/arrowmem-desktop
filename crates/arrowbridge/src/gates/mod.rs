//! The deterministic gates. Every pattern table is generated from the pinned Python originals (patterns_gen.rs); the logic around them is ported by hand and
//! proven against vectors the originals produced (tests/parity.rs).

pub mod distress;
pub mod factguard;
pub mod linkgate;
pub mod packsafety;
mod patterns_gen;
mod pyjson;
mod rx;
pub use rx::Rx;
pub mod telguard;
pub mod urgent;

/// Python's `str.isspace` (what `.strip()` removes): Unicode White_Space plus the four ASCII separators 0x1c to 0x1f.
pub fn py_isspace(c: char) -> bool { c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c) }

/// Python's `str.strip()` and `str.lstrip()`.
pub fn py_strip(s: &str) -> &str { s.trim_matches(py_isspace) }
pub fn py_lstrip(s: &str) -> &str { s.trim_start_matches(py_isspace) }

/// The fixed pet lines of the urgent gate (Python: `mvf_urgent.ANIMAL_LINE.values()`).
pub fn animal_line_en() -> &'static str { patterns_gen::ANIMAL_LINE_EN }
pub fn animal_line_fr() -> &'static str { patterns_gen::ANIMAL_LINE_FR }
