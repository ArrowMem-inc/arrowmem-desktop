//! The converter and the loader against each other, and against the REAL content/v2, from checkouts outside this repo. Ignored by default; nothing from
//! the real content is copied here. Run: PACKCONV_BIN=<packconv binary> PACKANSWER_V2_DIR=<content/v2> PACKANSWER_HELD_TSV=<held list kept outside every
//! repo> cargo test --test real_v2 -- --ignored
use packanswer::integrity::sha256_hex;
use packanswer::pack::{self, Pack, HOSTS_KEYS, NATMED_KEYS, RECORD_KEYS, SOURCE_KEYS, TOPICS};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn env(k: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(k).unwrap_or_else(|| panic!("{k} is not set")))
}

fn packconv(args: &[&Path]) -> (bool, String) {
    let o = Command::new(env("PACKCONV_BIN")).args(args).output().unwrap();
    (o.status.success(), String::from_utf8_lossy(&o.stdout).to_string())
}

fn held() -> HashSet<String> {
    fs::read_to_string(env("PACKANSWER_HELD_TSV")).unwrap().lines().map(|l| l.split('\t').nth(1).unwrap().to_string()).collect()
}

#[test]
#[ignore]
fn t26_the_converter_key_lists_equal_the_loaders() {
    let (ok, out) = packconv(&[Path::new("keys")]);
    assert!(ok);
    let want = format!(
        "topics {}\nrecord {}\nnatmed {}\nsource {}\nhosts {}\n",
        TOPICS.join(","),
        RECORD_KEYS.join(","),
        NATMED_KEYS.join(","),
        SOURCE_KEYS.join(","),
        HOSTS_KEYS.join(",")
    );
    assert_eq!(out, want);
}

#[test]
#[ignore]
fn the_converted_real_v2_verifies_and_loads_and_a_held_id_is_refused_at_every_stage() {
    let tmp = Path::new(env!("CARGO_TARGET_TMPDIR")).join("real-v2");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    // hosts file with stand in words, one entry per host the content names
    let content = env("PACKANSWER_V2_DIR");
    let mut hosts = serde_json::Map::new();
    for e in fs::read_dir(&content).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "jsonl") {
            for l in fs::read_to_string(&p).unwrap().lines() {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                let urls: Vec<String> = match v["sources"].as_array() {
                    Some(s) => s.iter().map(|s| s["url"].as_str().unwrap().to_string()).collect(),
                    None => vec![v["source_url"].as_str().unwrap().into(), v["context_url"].as_str().unwrap().into()],
                };
                for u in urls {
                    hosts.insert(pack::host_of(&u).unwrap().to_string(), serde_json::json!({"credit": "stand in", "disclaimer": "stand in"}));
                }
            }
        }
    }
    let hosts_path = tmp.join("hosts.json");
    fs::write(&hosts_path, serde_json::Value::Object(hosts).to_string()).unwrap();
    let held_path = env("PACKANSWER_HELD_TSV");
    let out = tmp.join("pack");
    // without a person file the two real Cranberry entries clash on one id and the build refuses
    assert!(!packconv(&[Path::new("pack"), &content, &hosts_path, Path::new("-"), &tmp.join("pack0"), &held_path]).0);
    // a person file, FIXTURE ids only (the real ids are the person's): one id per Cranberry line, bound by the SHA-256 of its raw line
    let natmed = fs::read_to_string(content.join("natural_medicine.jsonl")).unwrap();
    let mut person = serde_json::Map::new();
    let cranberries = natmed.lines().filter(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["common_name"] == "Cranberry");
    for (i, l) in cranberries.enumerate() {
        person.insert(format!("fixture_cranberry_{i}"), serde_json::json!({"entry_sha256": sha256_hex(l.as_bytes()), "aliases": [], "traditional_quotes": []}));
    }
    assert_eq!(person.len(), 2);
    let person_path = tmp.join("person.json");
    fs::write(&person_path, serde_json::Value::Object(person).to_string()).unwrap();
    let (ok, report) = packconv(&[Path::new("pack"), &content, &hosts_path, &person_path, &out, &held_path]);
    assert!(ok, "{report}");
    // the pinning gate is a machine check, `packconv gate-report`: exactly one PIN line equal to the pin and exactly one HELD line
    // equal to the fleet list count. The pin here is the hash of the staged manifest, not read from the report, so the check is not circular.
    let pin = sha256_hex(&fs::read(out.join("PACK.sha256")).unwrap());
    let report_path = tmp.join("report.txt");
    fs::write(&report_path, &report).unwrap();
    assert!(packconv(&[Path::new("gate-report"), &report_path, Path::new(pin.as_str()), &held_path]).0);
    // falsify the gate on the real report: a wrong pin, a list of another length, a second PIN line
    assert!(!packconv(&[Path::new("gate-report"), &report_path, Path::new(sha256_hex(b"other").as_str()), &held_path]).0);
    let short = tmp.join("short.tsv");
    fs::write(&short, "x\tfixture_one\ty\n").unwrap();
    assert!(!packconv(&[Path::new("gate-report"), &report_path, Path::new(pin.as_str()), &short]).0);
    let forged = tmp.join("forged.txt");
    fs::write(&forged, format!("{report}PIN\t{pin}\n")).unwrap();
    assert!(!packconv(&[Path::new("gate-report"), &forged, Path::new(pin.as_str()), &held_path]).0);
    // each PLANT line names its shipped line hash and its entry_sha256; the entry hash is the hash of a v2 line
    let v2_lines: HashSet<String> = natmed.lines().map(|l| sha256_hex(l.as_bytes())).collect();
    let plants: Vec<Vec<&str>> = report.lines().filter_map(|l| l.strip_prefix("PLANT\t")).map(|l| l.split('\t').collect()).collect();
    assert!(!plants.is_empty() && plants.iter().all(|c| c.len() == 3 && v2_lines.contains(c[2])));
    let ginger_hash = plants.iter().find(|c| c[0] == "ginger").unwrap()[1].to_string();
    let yes = [("ginger", ginger_hash.as_str())];
    assert!(packconv(&[Path::new("verify-pkg"), &out, Path::new(pin.as_str()), &held_path]).0);

    let held = held();
    assert_eq!(held.len(), 32);
    let pack = Pack::open(&out, &pin, &held, &yes).expect("the converted real v2 must load");
    assert_eq!(pack.record_count(), 1826);
    assert!(pack.record_ids().all(|id| !held.contains(id)));
    assert!(matches!(packanswer::answer(Some(&pack), "tell me about ginger", "en", None), packanswer::Answer::Blocks(_)));

    // falsify at the loader: any one real id on the held list refuses the whole pack
    let one: HashSet<String> = [pack.record_ids().next().unwrap().to_string()].into();
    assert_eq!(Pack::open(&out, &pin, &one, &yes).err().unwrap().0, "held record");
    // falsify at the converter and at verify-pkg: a list holding one real id
    let one_path = tmp.join("one.tsv");
    fs::write(&one_path, format!("x\t{}\ty\n", pack.record_ids().next().unwrap())).unwrap();
    assert!(!packconv(&[Path::new("pack"), &content, &hosts_path, &person_path, &tmp.join("pack2"), &one_path]).0);
    assert!(!packconv(&[Path::new("verify-pkg"), &out, Path::new("-"), &one_path]).0);
}

/// A pack the converter built, with the yes list taken by machine from the PLANT lines of its own report. Run: PACKANSWER_BUILT_DIR=<pack folder>
/// PACKANSWER_BUILT_REPORT=<its report> PACKANSWER_HELD_TSV=<held list> cargo test --test real_v2 -- --ignored built_pack
#[test]
#[ignore]
fn a_built_pack_loads_and_every_plant_draws_warnings_then_background_then_uses() {
    let dir = env("PACKANSWER_BUILT_DIR");
    let pin = sha256_hex(&fs::read(dir.join("PACK.sha256")).unwrap());
    let report = fs::read_to_string(env("PACKANSWER_BUILT_REPORT")).unwrap();
    let plants: Vec<Vec<&str>> = report.lines().filter_map(|l| l.strip_prefix("PLANT\t")).map(|l| l.split('\t').collect()).collect();
    let yes: Vec<(&str, &str)> = plants.iter().map(|c| (c[0], c[1])).collect();
    let pack = Pack::open(&dir, &pin, &held(), &yes).expect("the built pack must load");
    // a plant is named by its whole common name (aliases come only from a person file, none here)
    let file = fs::read_to_string(dir.join(pack::NATMED_FILE)).unwrap();
    let name = |id: &str| {
        let v = file.lines().map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()).find(|v| v["plant_id"] == id).unwrap();
        v["common_name"].as_str().unwrap().to_string()
    };
    for (id, _) in &yes {
        let a = packanswer::answer(Some(&pack), &format!("tell me about {}", name(id)), "en", None);
        let packanswer::Answer::NatMed(n) = a else { panic!("{id}: {a:?}") };
        assert_eq!((n.groups().count(), n.caution()), (1, packanswer::key::NATMED_CAUTION), "{id}");
        let marks: Vec<packanswer::Kind> = n.groups().next().unwrap().entries().map(|(k, _)| k).collect();
        let count = |k| marks.iter().filter(|m| **m == k).count();
        eprintln!("ORDER {id}: {} warnings, {} background, {} uses", count(packanswer::Kind::Warning), count(packanswer::Kind::Background), count(packanswer::Kind::Use));
        assert!(marks.first() == Some(&packanswer::Kind::Warning) && marks.windows(2).all(|w| w[0] <= w[1]), "{id}");
    }
}
