//! The natural medicine record mark: loader refusals and the fixed order of what is shown. Every sentence is invented placeholder text.
mod common;
use common::*;
use packanswer::integrity::Unavailable;
use packanswer::pack::SOURCE_KEYS;
use packanswer::{answer, Answer, Kind, NatMed, Pack};
use serde_json::{json, Value};
use std::collections::HashSet;

const GARLIC: [(&str, &str); 5] = [
    ("garlic warning one", "warning"),
    ("garlic warning two", "warning"),
    ("garlic background one", "background"),
    ("garlic use one", "use"),
    ("garlic use two", "use"),
];
const CRANBERRY: [(&str, &str); 3] = [("cranberry warning one", "warning"), ("cranberry background one", "background"), ("cranberry use one", "use")];

fn src(q: &str, k: &str) -> Value {
    json!({"quote": q, "url": NCCIH, "fetched": "2026-11-14", "traditional": false, "kind": k})
}

fn full_line(id: &str, common: &str, latin: &str, aliases: &[&str], sources: &[(&str, &str)]) -> String {
    let s: Vec<_> = sources.iter().map(|(q, k)| src(q, k)).collect();
    json!({"plant_id": id, "common_name": common, "latin_name": latin, "aliases": aliases, "sources": s}).to_string()
}

fn line(id: &str, name: &str, sources: &[(&str, &str)]) -> String {
    full_line(id, name, &format!("{name} latinum"), &[], sources)
}

fn garlic() -> String {
    line("garlic", "Garlic", &GARLIC)
}

fn cranberry() -> String {
    line("cranberry", "Cranberry", &CRANBERRY)
}

/// The default fixture pack with its natural medicine file replaced by these lines; every plant of the fixtures is on the yes list.
fn open_lines(name: &str, lines: &[String]) -> Result<Pack, Unavailable> {
    let mut f = default_files();
    f[6].1 = lines.join("\n") + "\n";
    let (dir, pin) = write_pack(name, &f);
    open_with(&dir, &pin, &HashSet::new(), &["garlic", "cranberry", "ginger", "onion"])
}

fn why(r: Result<Pack, Unavailable>) -> &'static str {
    r.err().expect("the pack must be refused").0
}

fn natmed(p: &Pack, q: &str, lang: &str) -> NatMed {
    match (answer(Some(p), q, lang, None), lang) {
        (Answer::NatMed(n), "en") | (Answer::EnglishOnlyNatMed(n), "fr") => n,
        (a, _) => panic!("{a:?}"),
    }
}

/// Everything shown, in order: (plant, section letter, quote).
fn shown(n: &NatMed) -> Vec<(String, char, String)> {
    let mut out = Vec::new();
    for g in n.groups() {
        for (k, e) in g.entries() {
            out.push((g.plant().to_string(), match k { Kind::Warning => 'w', Kind::Background => 'b', Kind::Use => 'u' }, e.quote().to_string()));
        }
    }
    out
}

#[test]
fn the_good_fixture_loads() {
    assert!(open_lines("k-good", &[garlic(), cranberry()]).is_ok());
}

// the key list and the old format refusal
#[test]
fn the_source_key_list_is_exactly_quote_url_fetched_traditional_kind() {
    assert_eq!(SOURCE_KEYS, ["quote", "url", "fetched", "traditional", "kind"]);
}

#[test]
fn an_old_format_pack_with_no_kind_is_refused_whole() {
    let old = garlic().replace(",\"kind\":\"warning\"", "").replace(",\"kind\":\"background\"", "").replace(",\"kind\":\"use\"", "");
    assert!(!old.contains("kind"));
    assert_eq!(why(open_lines("k-old", &[old, cranberry()])), "natmed keys");
}

#[test]
fn a_sixth_source_key_is_refused_whole() {
    let more = garlic().replacen("\"kind\":\"warning\"", "\"kind\":\"warning\",\"notes\":\"x\"", 1);
    assert_eq!(why(open_lines("k-six", &[more, cranberry()])), "natmed keys");
}

// the closed value type
#[test]
fn kind_is_exactly_one_of_three_words_and_anything_else_refuses_the_pack() {
    for (i, bad) in [json!(null), json!(""), json!("Warning"), json!("WARNING"), json!(" warning"), json!("warning "), json!("warning\n"), json!(1), json!(true), json!(["warning"]), json!({"k": "warning"}), json!("caution"), json!("uses")]
        .into_iter()
        .enumerate()
    {
        let mut v: Value = serde_json::from_str(&garlic()).unwrap();
        v["sources"][0]["kind"] = bad.clone();
        assert_eq!(why(open_lines(&format!("k-bad{i}"), &[v.to_string()])), "kind", "{bad}");
    }
}

#[test]
fn each_of_the_three_words_is_accepted() {
    for (i, k) in ["warning", "background", "use"].into_iter().enumerate() {
        let mut v: Value = serde_json::from_str(&line("garlic", "Garlic", &[("garlic warning one", "warning")])).unwrap();
        v["sources"].as_array_mut().unwrap().push(src("tail", k));
        assert!(open_lines(&format!("k-ok{i}"), &[v.to_string()]).is_ok(), "{k}");
    }
}

// zero warnings
#[test]
fn a_plant_with_no_warning_record_is_refused_whole() {
    for (i, s) in [vec![("only use", "use")], vec![("a background", "background"), ("a use", "use")], vec![("only background", "background")]].into_iter().enumerate() {
        assert_eq!(why(open_lines(&format!("k-nowarn{i}"), &[garlic(), line("cranberry", "Cranberry", &s)])), "plant without a warning");
    }
    assert_eq!(why(open_lines("k-nosrc", &[line("garlic", "Garlic", &[])])), "plant without a warning");
}

// stored order
#[test]
fn a_kind_that_steps_back_in_the_stored_order_is_refused_whole() {
    let steps: [[(&str, &str); 3]; 4] = [
        [("w", "warning"), ("u", "use"), ("w2", "warning")],
        [("w", "warning"), ("u", "use"), ("b", "background")],
        [("w", "warning"), ("b", "background"), ("w2", "warning")],
        [("b", "background"), ("w", "warning"), ("u", "use")],
    ];
    for (i, s) in steps.iter().enumerate() {
        assert!(open_lines(&format!("k-ord{i}"), &[line("garlic", "Garlic", s)]).is_err(), "{s:?}");
    }
    assert_eq!(why(open_lines("k-ord-x", &[line("garlic", "Garlic", &steps[0])])), "kind order");
}

// the render tests: one plant, two plants
#[test]
fn one_plant_is_its_warnings_then_background_then_uses_under_its_own_heading() {
    let p = open_lines("k-one", &[garlic(), cranberry()]).unwrap();
    let n = natmed(&p, "tell me about garlic", "en");
    let want: Vec<(String, char, String)> = GARLIC.iter().map(|(q, k)| ("Garlic".to_string(), k.chars().next().unwrap(), q.to_string())).collect();
    assert_eq!(shown(&n), want);
    assert_eq!(n.groups().count(), 1);
    assert_eq!(n.caution(), packanswer::key::NATMED_CAUTION);
}

#[test]
fn two_plants_are_one_group_each_under_its_own_heading_and_never_interleave() {
    let p = open_lines("k-two", &[garlic(), cranberry()]).unwrap();
    // asked in the other order: the groups follow the pack's stored plant order
    let n = natmed(&p, "cranberry and garlic please", "en");
    assert_eq!(n.groups().count(), 2);
    let s = shown(&n);
    let quotes: Vec<&str> = s.iter().map(|x| x.2.as_str()).collect();
    assert_eq!(
        quotes,
        [
            "garlic warning one",
            "garlic warning two",
            "garlic background one",
            "garlic use one",
            "garlic use two",
            "cranberry warning one",
            "cranberry background one",
            "cranberry use one"
        ]
    );
    let heads: Vec<&str> = s.iter().map(|x| x.0.as_str()).collect();
    assert_eq!(heads, ["Garlic", "Garlic", "Garlic", "Garlic", "Garlic", "Cranberry", "Cranberry", "Cranberry"]);
    // inside each group no use sits above a background or a warning, and no background above a warning
    for g in n.groups() {
        let rank: Vec<u8> = s.iter().filter(|x| x.0 == g.plant()).map(|x| "wbu".find(x.1).unwrap() as u8).collect();
        assert!(rank[0] == 0 && rank.windows(2).all(|w| w[0] <= w[1]), "{rank:?}");
    }
}

// no cap
#[test]
fn warnings_are_never_truncated_for_one_plant_or_two() {
    let many: Vec<(String, &str)> = (0..12).map(|i| (format!("long warning {}", ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"][i]), "warning")).collect();
    let many: Vec<(&str, &str)> = many.iter().map(|(q, k)| (q.as_str(), *k)).collect();
    let mut all = many.clone();
    all.extend(CRANBERRY.iter().skip(1));
    let p = open_lines("k-many", &[line("garlic", "Garlic", &all), cranberry()]).unwrap();
    let warnings = |n: &NatMed| shown(n).iter().filter(|x| x.1 == 'w').count();
    assert_eq!(warnings(&natmed(&p, "garlic", "en")), 12);
    let both = natmed(&p, "garlic cranberry", "en");
    assert_eq!(warnings(&both), 13);
    assert_eq!(shown(&both).len(), 12 + 2 + 3);
}

// a screen cannot receive a context to hide behind an expand control: the entry type has no such field, so only the French and English
// variants and the caution key remain to be checked here
#[test]
fn the_caution_key_is_in_the_answer_in_english_and_in_french_as_its_own_variant() {
    let p = open_lines("k-chrome", &[garlic(), cranberry()]).unwrap();
    assert_eq!(natmed(&p, "garlic", "en").caution(), packanswer::key::NATMED_CAUTION);
    assert_eq!(natmed(&p, "garlic", "fr").caution(), packanswer::key::NATMED_CAUTION);
    assert!(matches!(answer(Some(&p), "garlic", "fr", None), Answer::EnglishOnlyNatMed(_)));
    assert!(matches!(answer(Some(&p), "garlic", "en", None), Answer::NatMed(_)));
    // a topic answer is still the flat form and carries no caution key
    assert!(matches!(answer(Some(&p), "water", "en", None), Answer::Blocks(_)));
}

// all or nothing
#[test]
fn if_the_answer_cannot_be_shown_whole_nothing_of_it_is_shown() {
    // a heading with a number no source states fails the number gate: the whole answer is replaced, not the heading alone
    let p = open_lines("k-all", &[garlic(), line("cranberry", "Cranberry 7", &CRANBERRY)]).unwrap();
    assert_eq!(answer(Some(&p), "garlic cranberry 7", "en", None), Answer::NoAnswer);
    assert!(matches!(answer(Some(&p), "garlic", "en", None), Answer::NatMed(_)));
}

// repeated key and any other spelling than the pack writes
#[test]
fn a_record_with_kind_written_twice_is_refused_whole() {
    let twice = garlic().replacen("\"kind\":\"warning\"", "\"kind\":\"use\",\"kind\":\"warning\"", 1);
    assert_eq!(why(open_lines("k-twice", &[twice, cranberry()])), "not its own rewrite");
    let same = garlic().replacen("\"kind\":\"warning\"", "\"kind\":\"warning\",\"kind\":\"warning\"", 1);
    assert_eq!(why(open_lines("k-twice2", &[same, cranberry()])), "not its own rewrite");
    let spaced = garlic().replacen("\"kind\":\"warning\"", "\"kind\": \"warning\"", 1);
    assert_eq!(why(open_lines("k-space", &[spaced, cranberry()])), "not its own rewrite");
}

#[test]
fn a_line_that_parses_the_same_but_is_spelled_differently_is_refused_even_at_equal_length() {
    // a control character written with an upper case hex escape: same length as the pack's lower case spelling, other bytes
    let low = line("garlic", "Garlic", &[("garlic warning one\u{1f}", "warning")]);
    assert!(low.contains("\\u001f"));
    assert!(open_lines("k-lower", &[low.clone()]).is_ok());
    let upper = low.replace("\\u001f", "\\u001F");
    assert_eq!(upper.len(), low.len());
    assert_eq!(why(open_lines("k-upper", &[upper])), "not its own rewrite");
}

// blank values
#[test]
fn a_blank_warning_quote_is_refused() {
    for (i, q) in ["", " ", "  \t", "\u{200b}", "\u{200b}\u{200c}\u{200d}\u{feff}", "\u{a0}", "..."].into_iter().enumerate() {
        let mut v: Value = serde_json::from_str(&garlic()).unwrap();
        v["sources"][0]["quote"] = q.into();
        assert_eq!(why(open_lines(&format!("k-blank{i}"), &[v.to_string()])), "natmed source", "{q:?}");
    }
}

#[test]
fn a_blank_fetched_value_is_refused() {
    for (i, f) in ["", " ", "\t"].into_iter().enumerate() {
        let mut v: Value = serde_json::from_str(&garlic()).unwrap();
        v["sources"][1]["fetched"] = f.into();
        assert_eq!(why(open_lines(&format!("k-fetch{i}"), &[v.to_string()])), "natmed source", "{f:?}");
    }
}

#[test]
fn an_empty_natural_medicine_file_is_refused_whole() {
    for (i, body) in ["", "\n", "\n\n  \n"].into_iter().enumerate() {
        let mut f = default_files();
        f[6].1 = body.to_string();
        let (dir, pin) = write_pack(&format!("k-empty{i}"), &f);
        assert_eq!(why(open_with(&dir, &pin, &HashSet::new(), &["garlic"])), "empty natural medicine file", "{body:?}");
    }
}

// the approval hash
#[test]
fn one_changed_mark_changes_the_line_hash_and_the_plant_is_dropped() {
    let (dir, pin) = {
        let mut f = default_files();
        f[6].1 = garlic() + "\n";
        write_pack("k-yes", &f)
    };
    let good = open_with(&dir, &pin, &HashSet::new(), &["garlic"]).unwrap();
    assert_eq!(shown(&natmed(&good, "garlic", "en")).len(), 5);
    // the yes entry stays the old hash; one use becomes background in the file
    let old_hash = packanswer::integrity::sha256_hex(garlic().as_bytes());
    let mut f = default_files();
    f[6].1 = garlic().replacen("\"kind\":\"use\"", "\"kind\":\"background\"", 1) + "\n";
    let (dir2, pin2) = write_pack("k-yes2", &f);
    let flipped = Pack::open(&dir2, &pin2, &HashSet::new(), &[("garlic", old_hash.as_str())]).unwrap();
    assert_eq!(answer(Some(&flipped), "garlic", "en", None), Answer::NoAnswer);
}

// one key list for loader and converter
#[test]
fn the_loader_and_the_converter_share_one_source_key_list_pinned_by_the_ignored_real_pack_test() {
    // tests/real_v2.rs compares `packconv keys` with SOURCE_KEYS; here the list itself is pinned
    assert_eq!(SOURCE_KEYS.len(), 5);
    assert_eq!(SOURCE_KEYS[4], "kind");
}

// one vector file of mark orders and name pairs; a copy of it can sit beside the converter's tests, so a compare of the two copies shows any drift
#[test]
fn every_vector_of_the_shared_file_loads_or_refuses_as_it_says() {
    let word = |c: &str| match c { "w" => "warning", "b" => "background", _ => "use" };
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/order_vectors.tsv")).unwrap();
    let (mut orders, mut names) = (0, 0);
    for (i, l) in text.lines().enumerate().filter(|(_, l)| !l.starts_with('#')) {
        let cols: Vec<&str> = l.split('\t').collect();
        if cols[0] == "name" {
            // two plants, each "common|latin|alias|alias"; the pair loads or the whole pack is refused
            let plant = |id: &str, spec: &str| {
                let spec = spec.replace("{zwsp}", "\u{200b}");
                let n: Vec<&str> = spec.split('|').collect();
                full_line(id, n[0], n[1], &n[2..], &[("a warning", "warning")])
            };
            let r = open_lines(&format!("k-name{i}"), &[plant("garlic", cols[1]), plant("onion", cols[2])]);
            assert_eq!(r.is_ok(), cols[3] == "ok", "{l}");
            if cols[3] == "no" {
                assert!(["shared plant name", "empty plant name"].contains(&why(r)), "{l}");
            }
            names += 1;
        } else {
            let s: Vec<(String, &str)> = cols[0].split(' ').enumerate().map(|(j, c)| (format!("record {j}"), word(c))).collect();
            let s: Vec<(&str, &str)> = s.iter().map(|(q, k)| (q.as_str(), *k)).collect();
            assert_eq!(open_lines(&format!("k-vec{i}"), &[line("garlic", "Garlic", &s)]).is_ok(), cols[1] == "ok", "{l}");
            orders += 1;
        }
    }
    assert_eq!((orders, names), (16, 18));
}

// no shared name: a common name, a latin name or an alias that is another plant's name
#[test]
fn two_plants_with_one_common_name_are_refused_at_load_even_when_neither_is_approved() {
    let twin = line("garlic2", "garlic", &[("twin warning one", "warning")]);
    assert_eq!(why(open_lines("k-twin", &[garlic(), twin.clone()])), "shared plant name");
    // neither on the yes list: still refused, so a hold or a missing yes cannot hide the clash
    let mut f = default_files();
    f[6].1 = format!("{}\n{}\n", garlic(), twin);
    let (dir, pin) = write_pack("k-twin2", &f);
    assert_eq!(why(open_with(&dir, &pin, &HashSet::new(), &[])), "shared plant name");
}

// three plants, and background counts too
#[test]
fn three_plants_are_three_groups_each_holding_only_its_own_records_and_nothing_is_dropped() {
    let (dir, pin) = {
        let mut f = default_files();
        f[6].1 = [garlic(), cranberry(), line("ginger", "Ginger", &[("ginger warning one", "warning"), ("ginger background one", "background"), ("ginger use one", "use")])].join("\n") + "\n";
        write_pack("k-three", &f)
    };
    let p = open_with(&dir, &pin, &HashSet::new(), &["garlic", "cranberry", "ginger"]).unwrap();
    let n = natmed(&p, "ginger, cranberry and garlic", "en");
    assert_eq!(n.groups().map(|g| g.plant()).collect::<Vec<_>>(), ["Garlic", "Cranberry", "Ginger"]);
    for g in n.groups() {
        let own = g.plant().to_lowercase();
        assert!(shown(&n).iter().filter(|x| x.0 == g.plant()).all(|x| x.2.starts_with(&own)), "{}", g.plant());
    }
    let counts: Vec<(usize, usize, usize)> = n
        .groups()
        .map(|g| {
            let c = |k| g.entries().filter(|(m, _)| *m == k).count();
            (c(Kind::Warning), c(Kind::Background), c(Kind::Use))
        })
        .collect();
    assert_eq!(counts, [(2, 1, 2), (1, 1, 1), (1, 1, 1)]);
}

// ids and encoding
#[test]
fn a_duplicate_plant_id_and_invalid_utf8_stay_refused() {
    assert_eq!(why(open_lines("k-dup", &[garlic(), garlic()])), "duplicate id");
    let mut files: Vec<(String, Vec<u8>)> = default_files().into_iter().map(|(n, c)| (n.to_string(), c.into_bytes())).collect();
    files[6].1.extend_from_slice(b"\xff\n");
    assert_eq!(Pack::from_files(files, &HashSet::new(), &[]).err().unwrap().0, "utf8");
}
