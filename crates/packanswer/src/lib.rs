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

pub use pack::{Kind, Pack};
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
#[non_exhaustive]
pub struct Block {
    pub quote: String,
    pub url: String,
    pub retrieved: String,
    /// Host credit and disclaimer lines, from hosts.json (words from the copy owner).
    pub credit: String,
    pub disclaimer: String,
    /// The stored verbatim context, shown behind an expand control.
    pub context: Option<String>,
    /// The page the context was stored from, shown with the context (it can differ from `url`).
    pub context_url: Option<String>,
}

/// One natural medicine source record. It has no context field, and its fields are read through accessors only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub(crate) quote: String,
    pub(crate) url: String,
    pub(crate) retrieved: String,
    pub(crate) credit: String,
    pub(crate) disclaimer: String,
    pub(crate) label: Option<&'static str>,
}

impl Entry {
    pub fn quote(&self) -> &str {
        &self.quote
    }
    pub fn url(&self) -> &str {
        &self.url
    }
    pub fn retrieved(&self) -> &str {
        &self.retrieved
    }
    /// Host credit line, from hosts.json (words from the copy owner).
    pub fn credit(&self) -> &str {
        &self.credit
    }
    /// Host disclaimer line, from hosts.json (words from the copy owner).
    pub fn disclaimer(&self) -> &str {
        &self.disclaimer
    }
    /// Some(key::TRADITIONAL) where a person flagged the quote as traditional use.
    pub fn label(&self) -> Option<&'static str> {
        self.label
    }
}

/// At least one warning by type: the first is a field of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Warnings {
    pub(crate) first: Entry,
    pub(crate) rest: Vec<Entry>,
}

/// One plant: its own common name, then its records. The fields are private and the only read path is `entries`, which yields warnings, then
/// background, then uses, each with its mark. The crate builds a group only with at least one warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub(crate) plant: String,
    pub(crate) warnings: Warnings,
    pub(crate) background: Vec<Entry>,
    pub(crate) uses: Vec<Entry>,
}

impl Group {
    pub fn plant(&self) -> &str {
        &self.plant
    }

    /// Every record of the plant in the fixed order, each with its mark.
    pub fn entries(&self) -> impl Iterator<Item = (Kind, &Entry)> {
        std::iter::once(&self.warnings.first)
            .chain(&self.warnings.rest)
            .map(|e| (Kind::Warning, e))
            .chain(self.background.iter().map(|e| (Kind::Background, e)))
            .chain(self.uses.iter().map(|e| (Kind::Use, e)))
    }
}

/// A natural medicine answer: the caution key and one group per named plant, in private fields with read only accessors, built only inside this
/// crate. The types give a reader no way to edit what it reads; they cannot make a reader draw what it reads, in this order or at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatMed {
    pub(crate) caution: &'static str,
    pub(crate) groups: Vec<Group>,
}

impl NatMed {
    /// The fixed caution key, to be drawn above the first group.
    pub fn caution(&self) -> &'static str {
        self.caution
    }

    pub fn groups(&self) -> impl Iterator<Item = &Group> {
        self.groups.iter()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    NatMed(NatMed),
    /// A French turn: key::ENGLISH_ONLY first, then any English records found (possibly none). Never a translation.
    EnglishOnly(Found),
    /// A French turn that named a plant: key::ENGLISH_ONLY, then the same answer as `NatMed`, caution key included.
    EnglishOnlyNatMed(NatMed),
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
