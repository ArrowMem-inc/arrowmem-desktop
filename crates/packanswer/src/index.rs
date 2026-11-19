//! Deterministic BM25 (k1 1.2, b 0.75) over a pack's text. No embeddings, no second model. The idf is the non negative form ln(1 + (N - df + 0.5) / (df + 0.5)).
use std::collections::{BTreeSet, HashMap};

const K1: f64 = 1.2;
const B: f64 = 0.75;

fn fold(c: char) -> char {
    match c {
        '\u{e0}'..='\u{e5}' => 'a',
        '\u{e7}' => 'c',
        '\u{e8}'..='\u{eb}' => 'e',
        '\u{ec}'..='\u{ef}' => 'i',
        '\u{f1}' => 'n',
        '\u{f2}'..='\u{f6}' => 'o',
        '\u{f9}'..='\u{fc}' => 'u',
        '\u{fd}' | '\u{ff}' => 'y',
        _ => c,
    }
}

/// Lowercase, accent folded (Latin 1), split on anything not alphanumeric.
pub fn tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        if c.is_alphanumeric() {
            cur.extend(c.to_lowercase().map(fold));
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

pub struct Index {
    tf: Vec<HashMap<String, u32>>,
    len: Vec<f64>,
    df: HashMap<String, u32>,
    avg: f64,
}

impl Index {
    pub fn new(docs: impl Iterator<Item = String>) -> Index {
        let mut tf = Vec::new();
        let mut len = Vec::new();
        let mut df: HashMap<String, u32> = HashMap::new();
        for d in docs {
            let toks = tokens(&d);
            len.push(toks.len() as f64);
            let mut m: HashMap<String, u32> = HashMap::new();
            for t in toks {
                *m.entry(t).or_insert(0) += 1;
            }
            for t in m.keys() {
                *df.entry(t.clone()).or_insert(0) += 1;
            }
            tf.push(m);
        }
        let avg = if len.is_empty() { 0.0 } else { len.iter().sum::<f64>() / len.len() as f64 };
        Index { tf, len, df, avg }
    }

    /// Every document with a positive score, best first; equal scores in document order.
    pub fn rank(&self, query: &str) -> Vec<usize> {
        // Sorted terms: float addition is order sensitive, so a fixed order keeps one question on one ranking.
        let terms: BTreeSet<String> = tokens(query).into_iter().collect();
        let n = self.tf.len() as f64;
        let mut scored: Vec<(f64, usize)> = Vec::new();
        for (i, m) in self.tf.iter().enumerate() {
            let mut score = 0.0;
            for t in &terms {
                let (Some(&f), Some(&df)) = (m.get(t), self.df.get(t)) else { continue };
                let (f, df) = (f64::from(f), f64::from(df));
                let idf = (1.0 + (n - df + 0.5) / (df + 0.5)).ln();
                score += idf * f * (K1 + 1.0) / (f + K1 * (1.0 - B + B * self.len[i] / self.avg));
            }
            if score > 0.0 {
                scored.push((score, i));
            }
        }
        scored.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
        scored.into_iter().map(|(_, i)| i).collect()
    }
}
