//! One turn, in the fixed order: crisis gate on the full text, input bound, pack check, natural medicine by name only, retrieval, optional id selection, code
//! assembly, number gate, fixed no answer screen. The crisis gate runs before any retrieval or selector call and before the pack is consulted.
use crate::pack::{Kind, Pack, Plant, Record};
use crate::{key, numgate, Answer, Block, Candidate, Entry, Found, Group, NatMed, Selector, Warnings};
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
    let hit = find(pack, question, selector).filter(|h| match h {
        Hit::NatMed(n) => numgate::passes_natmed(n),
        Hit::Topic(f) => numgate::passes(f),
    });
    let fr = lang.starts_with("fr");
    match hit {
        Some(Hit::NatMed(n)) if fr => Answer::EnglishOnlyNatMed(n),
        Some(Hit::NatMed(n)) => Answer::NatMed(n),
        topic if fr => {
            let mut f = match topic {
                Some(Hit::Topic(f)) => f,
                _ => Found { blocks: Vec::new(), chrome: Vec::new() },
            };
            f.chrome.insert(0, key::ENGLISH_ONLY);
            Answer::EnglishOnly(f)
        }
        Some(Hit::Topic(f)) => Answer::Blocks(f),
        None => Answer::NoAnswer,
    }
}

enum Hit {
    Topic(Found),
    NatMed(NatMed),
}

/// One plant's group: its records of each mark in stored order, so warnings, then background, then uses whatever the stored order of the marks.
/// Nothing is capped. None (so the whole answer is replaced) when a host is unknown or the plant holds no warning.
fn group(pack: &Pack, p: &Plant) -> Option<Group> {
    let of = |k: Kind| -> Option<Vec<Entry>> {
        p.sources
            .iter()
            .filter(|s| s.kind == k)
            .map(|s| {
                let h = pack.host(&s.url)?;
                Some(Entry {
                    quote: s.quote.clone(),
                    url: s.url.clone(),
                    retrieved: s.fetched.clone(),
                    credit: h.credit.clone(),
                    disclaimer: h.disclaimer.clone(),
                    label: s.traditional.then_some(key::TRADITIONAL),
                })
            })
            .collect()
    };
    let mut warnings = of(Kind::Warning)?.into_iter();
    Some(Group {
        plant: p.name.clone(),
        warnings: Warnings { first: warnings.next()?, rest: warnings.collect() },
        background: of(Kind::Background)?,
        uses: of(Kind::Use)?,
    })
}

fn find(pack: &Pack, question: &str, selector: Option<&dyn Selector>) -> Option<Hit> {
    let plants = pack.named_plants(question);
    if !plants.is_empty() {
        let groups = plants.iter().map(|p| group(pack, p)).collect::<Option<Vec<_>>>()?;
        return Some(Hit::NatMed(NatMed { caution: key::NATMED_CAUTION, groups }));
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
        });
    }
    let mut chrome = Vec::new();
    if recs.iter().any(|r| r.topic == "preservation") {
        chrome.push(key::FOOD_SAFETY);
    }
    if recs.iter().any(|r| r.topic == "game_fish" || r.topic == "trapping") {
        chrome.push(key::PROVINCIAL_RULES);
    }
    Some(Hit::Topic(Found { blocks, chrome }))
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashSet;

    const NCCIH: &str = "https://www.nccih.nih.gov/fixture/page";

    fn line(id: &str, name: &str, sources: &[(&str, &str)]) -> String {
        let s: Vec<_> = sources.iter().map(|(q, k)| json!({"quote": q, "url": NCCIH, "fetched": "2026-11-14", "traditional": false, "kind": k})).collect();
        json!({"plant_id": id, "common_name": name, "latin_name": format!("{name} latinum"), "aliases": [], "sources": s}).to_string()
    }

    /// A two plant pack held in memory, so a test can hand it stored orders and urls the loader would refuse.
    fn two_plants() -> Pack {
        let a = line("garlic", "Garlic", &[("garlic warning one", "warning"), ("garlic warning two", "warning"), ("garlic background one", "background"), ("garlic use one", "use"), ("garlic use two", "use")]);
        let b = line("cranberry", "Cranberry", &[("cranberry warning one", "warning"), ("cranberry background one", "background"), ("cranberry use one", "use")]);
        let hosts = json!({"www.nccih.nih.gov": {"credit": "credit", "disclaimer": "disclaimer"}}).to_string();
        let h = |l: &str| crate::integrity::sha256_hex(l.as_bytes());
        let yes = [("garlic", h(&a)), ("cranberry", h(&b))];
        let yes: Vec<(&str, &str)> = yes.iter().map(|(i, x)| (*i, x.as_str())).collect();
        let files = vec![("hosts.json".to_string(), hosts.into_bytes()), (crate::pack::NATMED_FILE.to_string(), format!("{a}\n{b}\n").into_bytes())];
        Pack::from_files(files, &HashSet::new(), &yes).unwrap()
    }

    fn natmed(pack: &Pack) -> Option<NatMed> {
        match find(pack, "garlic and cranberry", None)? {
            Hit::NatMed(n) => Some(n),
            Hit::Topic(_) => None,
        }
    }

    /// A group read through its one path: (mark letter, quote) in the order given.
    fn read(g: &Group) -> Vec<(char, &str)> {
        g.entries().map(|(k, e)| (match k { Kind::Warning => 'w', Kind::Background => 'b', Kind::Use => 'u' }, e.quote())).collect()
    }

    /// Stored orders the loader would refuse: the answer must still come out in the fixed order, stable inside each mark.
    #[test]
    fn a_plant_stored_out_of_order_in_memory_is_still_ordered_stably_by_kind() {
        let mut pack = two_plants();
        // scramble: reverse each plant's sources (uses first, warnings last), then rotate one
        for p in &mut pack.plants {
            p.sources.reverse();
            p.sources.rotate_left(1);
        }
        let n = natmed(&pack).unwrap();
        assert_eq!(n.caution(), key::NATMED_CAUTION);
        let g: Vec<&Group> = n.groups().collect();
        assert_eq!(g.iter().map(|g| g.plant()).collect::<Vec<_>>(), ["Garlic", "Cranberry"]);
        assert_eq!(
            read(g[0]),
            [('w', "garlic warning two"), ('w', "garlic warning one"), ('b', "garlic background one"), ('u', "garlic use one"), ('u', "garlic use two")]
        );
        assert_eq!(read(g[1]), [('w', "cranberry warning one"), ('b', "cranberry background one"), ('u', "cranberry use one")]);
    }

    /// If any record of any named plant cannot be built, the whole answer goes, never a plant or a use without its warnings.
    #[test]
    fn a_record_with_an_unknown_host_replaces_the_whole_answer_not_just_itself() {
        for (plant, source) in [(0, 0), (0, 4), (1, 1)] {
            let mut pack = two_plants();
            assert!(natmed(&pack).is_some());
            pack.plants[plant].sources[source].url = "https://unknown.example/page".into();
            assert!(natmed(&pack).is_none(), "{plant} {source}");
            assert_eq!(answer(Some(&pack), "garlic and cranberry", "en", None), Answer::NoAnswer);
        }
    }

    /// A plant held with no warning is never drawn, and nothing else of the answer is drawn either.
    #[test]
    fn a_plant_with_no_warning_in_memory_replaces_the_whole_answer() {
        let mut pack = two_plants();
        pack.plants[1].sources.retain(|s| s.kind != Kind::Warning);
        assert!(natmed(&pack).is_none());
    }
}
