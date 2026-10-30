//! The typed pairing code, version 1: eight Crockford base32 characters that CARRY this computer's private address,
//! so a phone with no camera can find it. It is NOT a credential and NOT the proof of the pairing (the six digits
//! typed on this computer are). The check bits are a CRC for typing mistakes, nothing more.
//!
//! 40 bits, most significant first: version 4 | range 2 | host 24 | crc 10. Range 0 = 192.168.x.y, 1 = 10.x.y.z,
//! 2 = 172.16-31.x.y, 3 = reserved. The port is always 8788 and is never in the code: a computer on another port
//! offers no code. The phone side is `PairCode.kt`; both are held to `fixtures/pair_code_vectors.json`, made by an
//! independent Python reference.
use std::net::Ipv4Addr;

const ALPHA: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const VERSION: u64 = 1;
/// The only port a code can stand for.
pub const CODE_PORT: u16 = 8788;

/// CRC-10, polynomial 0x233 (x^10 + x^9 + x^5 + x^4 + x + 1), start 0, MSB first, no reflection, no final xor,
/// over the 30 bits version|range|host.
fn crc10(bits30: u64) -> u64 {
    let mut reg: u64 = 0;
    for i in (0..30).rev() {
        let bit = (bits30 >> i) & 1;
        let top = (reg >> 9) & 1;
        reg = (reg << 1) & 0x3FF;
        if top ^ bit == 1 {
            reg ^= 0x233;
        }
    }
    reg
}

/// The code for a private address, grouped as `ABCD-EFGH`, or None when the address is not RFC 1918 or the
/// computer's port is not the default (a code never carries a port).
pub fn encode(ip: Ipv4Addr, port: u16) -> Option<String> {
    if port != CODE_PORT {
        return None;
    }
    let [a, b, c, d] = ip.octets();
    let (range, host): (u64, u64) = match (a, b) {
        (192, 168) => (0, u64::from(c) << 8 | u64::from(d)),
        (10, _) => (1, u64::from(b) << 16 | u64::from(c) << 8 | u64::from(d)),
        (172, 16..=31) => (2, u64::from(b - 16) << 16 | u64::from(c) << 8 | u64::from(d)),
        _ => return None,
    };
    let top = VERSION << 26 | range << 24 | host;
    let v = top << 10 | crc10(top);
    let s: String = (0..8).map(|i| ALPHA[((v >> (5 * (7 - i))) & 31) as usize] as char).collect();
    Some(format!("{}-{}", &s[..4], &s[4..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("fixtures/pair_code_vectors.json")).unwrap()
    }

    #[test]
    fn every_good_vector_of_the_independent_python_reference_is_reproduced() {
        let v = vectors();
        let good = v["good"].as_array().unwrap();
        assert!(good.len() >= 10);
        for g in good {
            let ip: Ipv4Addr = g["ip"].as_str().unwrap().parse().unwrap();
            assert_eq!(encode(ip, 8788).as_deref(), g["shown"].as_str(), "{ip}");
        }
    }

    #[test]
    fn no_code_for_another_port_or_for_a_non_private_address() {
        assert_eq!(encode("192.168.1.24".parse().unwrap(), 8789), None);
        for ip in ["100.64.0.1", "8.8.8.8", "127.0.0.1", "169.254.1.1", "172.15.0.1", "172.32.0.1", "192.169.0.1"] {
            assert_eq!(encode(ip.parse().unwrap(), 8788), None, "{ip}");
        }
    }

    /// The reference's refused codes are exactly the codes this encoder can never produce, and a decoder of our own
    /// (written here only to prove the round trip) accepts every address of the three ranges.
    #[test]
    fn no_bad_vector_is_ever_produced_and_the_range_edges_are_distinct() {
        let v = vectors();
        let bad: std::collections::HashSet<String> =
            v["bad"].as_array().unwrap().iter().map(|b| b["code"].as_str().unwrap().to_string()).collect();
        let mut seen = std::collections::HashSet::new();
        for a in ["192.168.0.0", "192.168.255.255", "10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255", "10.1.2.3"] {
            let shown = encode(a.parse().unwrap(), 8788).unwrap();
            let plain = shown.replace('-', "");
            assert_eq!(plain.len(), 8);
            assert!(!bad.contains(&plain), "{a}");
            assert!(seen.insert(shown), "two addresses gave one code");
        }
    }

    #[test]
    fn the_crc_is_the_documented_one() {
        assert_eq!(crc10(0), 0);
        assert_eq!(crc10(1), 0x233);
    }

    /// Mutant guard: a code made with another polynomial must differ from the reference on a known address.
    #[test]
    fn a_different_polynomial_would_be_caught_by_the_vectors() {
        let shown = encode("192.168.50.140".parse().unwrap(), 8788).unwrap();
        assert_eq!(shown, "200C-MCVZ");
    }
}
