//! One turn, in the fixed order: crisis gate on the full text, input bound, pack check, natural medicine by name only, retrieval, optional id selection, code
//! assembly, number gate, fixed no answer screen. The crisis gate runs before any retrieval or selector call and before the pack is consulted.
use crate::pack::{Pack, Record};
use crate::{key, numgate, Answer, Block, Candidate, Found, Selector};
use arrowbridge::gates::packsafety::crisis_lines_default;
use arrowbridge::gates::urgent::{urgent_reply, Distress};

pub const MAX_CHARS: usize = 2000;
const MAX_BLOCKS: usize = 4;

pub fn answer(pack: Option<&Pack>, question: &str, lang: &str, selector: Option<&dyn Selector>) -> Answer {
    answer_after(None, pack, question, lang, selector)
}

/// `prior` is the previous question of this session, kept in memory by the caller for one turn only and never stored, so the gate's walk back
/// ("just kidding" after an urgent message) and prior turn ingestion branches still fire.
pub fn answer_after(prior: Option<&str>, pack: Option<&Pack>, question: &str, lang: &str, selector: Option<&dyn Selector>) -> Answer {
    // The crisis gate sees the full text at any length; the bound comes after it.
    let turns: Vec<&str> = prior.into_iter().chain([question]).collect();
    if let Some(r) = urgent_reply(&turns, lang, Distress::Available) {
        return Answer::Crisis { line: r.line, floor: if r.self_harm { crisis_lines_default(lang) } else { Vec::new() } };
    }
    if question.chars().count() > MAX_CHARS {
        return Answer::TooLong;
    }
    let Some(pack) = pack else { return Answer::PackUnavailable };
    let found = find(pack, question, selector).filter(numgate::passes);
    if lang.starts_with("fr") {
        let mut f = found.unwrap_or(Found { blocks: Vec::new(), chrome: Vec::new() });
        f.chrome.insert(0, key::ENGLISH_ONLY);
        return Answer::EnglishOnly(f);
    }
    found.map_or(Answer::NoAnswer, Answer::Blocks)
}

fn find(pack: &Pack, question: &str, selector: Option<&dyn Selector>) -> Option<Found> {
    let plants = pack.named_plants(question);
    if !plants.is_empty() {
        let mut blocks = Vec::new();
        for s in plants.iter().flat_map(|p| &p.sources) {
            let h = pack.host(&s.url)?;
            blocks.push(Block {
                quote: s.quote.clone(),
                url: s.url.clone(),
                retrieved: s.fetched.clone(),
                credit: h.credit.clone(),
                disclaimer: h.disclaimer.clone(),
                context: None,
                context_url: None,
                label: s.traditional.then_some(key::TRADITIONAL),
            });
        }
        return Some(Found { blocks, chrome: vec![key::NATMED_CAUTION] });
    }
    let candidates = pack.retrieve(question);
    if candidates.is_empty() {
        return None;
    }
    let mut chosen = selected(pack, question, &candidates, selector);
    if chosen.is_empty() {
        chosen = candidates;
    }
    chosen.truncate(MAX_BLOCKS);
    let recs: Vec<&Record> = chosen.iter().map(|&i| &pack.records[i]).collect();
    let mut blocks = Vec::new();
    for r in &recs {
        let h = pack.host(&r.url)?;
        blocks.push(Block {
            quote: r.quote.clone(),
            url: r.url.clone(),
            retrieved: r.retrieved.clone(),
            credit: h.credit.clone(),
            disclaimer: h.disclaimer.clone(),
            context: Some(r.context.clone()),
            context_url: Some(r.context_url.clone()),
            label: None,
        });
    }
    let mut chrome = Vec::new();
    if recs.iter().any(|r| r.topic == "preservation") {
        chrome.push(key::FOOD_SAFETY);
    }
    if recs.iter().any(|r| r.topic == "game_fish" || r.topic == "trapping") {
        chrome.push(key::PROVINCIAL_RULES);
    }
    Some(Found { blocks, chrome })
}

/// The selector's ids intersected with the candidates, first mention wins. Anything else it returns is dropped.
fn selected(pack: &Pack, question: &str, candidates: &[usize], selector: Option<&dyn Selector>) -> Vec<usize> {
    let Some(sel) = selector else { return Vec::new() };
    let cands: Vec<Candidate> = candidates.iter().map(|&i| Candidate { id: &pack.records[i].id, quote: &pack.records[i].quote }).collect();
    let mut out: Vec<usize> = Vec::new();
    for id in sel.select(question, &cands) {
        if let Some(&i) = candidates.iter().find(|&&i| pack.records[i].id == id) {
            if !out.contains(&i) {
                out.push(i);
            }
        }
    }
    out
}
