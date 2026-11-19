//! The time bound of the crisis gate on long benign prose, alone in its own test binary. Cargo runs test binaries one after another and
//! this one holds one test, so no other test of this crate loads the machine while it is timed. The correctness asserts (benign prose is not urgent, a real
//! phrase at the end is caught) stay in robust.rs and do not depend on load. Measured alone on an idle 20 core machine in debug: 4.1 to 4.35 s, so the debug
//! bound is wide and the release bound is the tight one: `cargo test --release --test robust_timing`. The property: the regex give-up is a counted
//! backtrack limit, so a runaway ends in bounded work rather than "a give-up counted as a match" or a stall.
use arrowbridge::gates::urgent;
use std::time::{Duration, Instant};

#[test]
fn long_benign_prose_is_fast() {
    let prose = "The Veterans Affairs disability benefit is described in section twelve of the guide. ".repeat(2500);
    let bound = Duration::from_secs(if cfg!(debug_assertions) { 30 } else { 5 });
    let start = Instant::now();
    for d in [urgent::Distress::Available, urgent::Distress::Missing] {
        urgent::urgent_reply(&[&prose], "en", d);
    }
    urgent::urgent_reply(&[&format!("{prose} bleeding")], "en", urgent::Distress::Available);
    urgent::urgent_reply(&["a b ".repeat(60_000).as_str()], "en", urgent::Distress::Available);
    assert!(start.elapsed() < bound, "took {:?}, bound {:?}", start.elapsed(), bound);
}
