//! Reference only pack answering. A typed question is answered only by verbatim pack records with their
//! source. The crate authors no sentence: every word a person reads is a pack field or one of the `key` placeholders (the copy owner supplies the words).
//! No network, no file writes, no logging of a question or an answer. The crisis gate runs before any retrieval or selector call.
#![forbid(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]
#![deny(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::todo, clippy::unimplemented)]

pub mod integrity;
mod index;
pub mod numgate;
pub mod pack;
pub mod turn;

pub use pack::Pack;
pub use turn::{answer, answer_after};

/// Placeholder keys for every fixed line. UNCLEARED: the words belong to the copy owner; the UI maps a key to its words.
pub mod key {
    pub const NO_ANSWER: &str = "pack.no_answer";
    pub const PACK_UNAVAILABLE: &str = "pack.unavailable";
    pub const ENGLISH_ONLY: &str = "pack.english_only";
    pub const TOO_LONG: &str = "pack.too_long";
    pub const FOOD_SAFETY: &str = "pack.topic.food_safety";
    pub const PROVINCIAL_RULES: &str = "pack.topic.provincial_rules";
    pub const NATMED_CAUTION: &str = "pack.natmed.caution";
    pub const TRADITIONAL: &str = "pack.natmed.traditional_label";
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub quote: String,
    pub url: String,
    pub retrieved: String,
    /// Host credit and disclaimer lines, from hosts.json (words from the copy owner).
    pub credit: String,
    pub disclaimer: String,
    /// The stored verbatim context, shown behind an expand control; None for natural medicine (the shipped file carries none).
    pub context: Option<String>,
    /// The page the context was stored from, shown with the context (it can differ from `url`); None where there is no context.
    pub context_url: Option<String>,
    /// Some(key::TRADITIONAL) where a person flagged the quote as traditional use.
    pub label: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub blocks: Vec<Block>,
    /// Placeholder keys the UI renders around the blocks, in order.
    pub chrome: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The gate's fixed line, plus the engine floor line when the gate says the 988 line must go with it.
    Crisis { line: arrowbridge::gates::urgent::CrisisLine, floor: Vec<String> },
    Blocks(Found),
    /// A French turn: key::ENGLISH_ONLY first, then any English records found (possibly none). Never a translation.
    EnglishOnly(Found),
    /// key::NO_ANSWER, no digits, nothing else.
    NoAnswer,
    /// The pack failed verification or parsing: zero quotes. The crisis gate still ran first.
    PackUnavailable,
    /// Input over 2000 characters: key::TOO_LONG.
    TooLong,
}

pub struct Candidate<'a> {
    pub id: &'a str,
    pub quote: &'a str,
}

/// The app implements this over the loopback model. The crate holds no socket code and renders nothing the selector returns except ids it
/// already retrieved: anything else is dropped, and an empty or unusable result falls back to the retrieval order.
pub trait Selector {
    fn select(&self, question: &str, candidates: &[Candidate]) -> Vec<String>;
}
