//! Password rules per NIST SP 800-63B-4 (§4.1) and the passphrase generator.

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::error::{Code, Error, Result};

pub const MIN_LEN: usize = 15;
pub const MAX_LEN: usize = 1024;

const BLOCKLIST: &str = include_str!("../data/blocklist.txt");
const WORDS: &str = include_str!("../data/eff_words.txt");

/// NFC normalization before hashing.
pub fn normalize(password: &str) -> Zeroizing<String> {
    Zeroizing::new(password.nfc().collect())
}

fn weak(msg: &str) -> Error {
    Error::new(Code::WeakPassword, msg)
}

/// Checks a new password. `context` contains context-specific words (email and its parts,
/// name, vault name); "nepomuk" is always included.
pub fn check(password: &str, context: &[&str]) -> Result<()> {
    let p = normalize(password);
    let len = p.chars().count();
    if len < MIN_LEN {
        return Err(weak(&format!(
            "the password must have at least {MIN_LEN} characters"
        )));
    }
    if len > MAX_LEN {
        return Err(weak(&format!(
            "the password must have at most {MAX_LEN} characters"
        )));
    }
    if p.chars().any(|c| c.is_control()) {
        return Err(weak("the password contains control characters"));
    }
    let lower = Zeroizing::new(p.to_lowercase());
    let compact: Zeroizing<String> =
        Zeroizing::new(lower.chars().filter(|c| !c.is_whitespace()).collect());
    let listed = BLOCKLIST
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .any(|l| l == lower.as_str() || l == compact.as_str());
    if listed {
        return Err(weak(
            "the password is on the list of commonly used passwords",
        ));
    }
    let distinct: std::collections::BTreeSet<char> = lower.chars().collect();
    if distinct.len() < 4 {
        return Err(weak("the password is too repetitive"));
    }
    // Context-specific words: remove them and require the rest to still be substantial.
    let mut words: Vec<String> = vec!["nepomuk".into()];
    for c in context {
        let c = c.to_lowercase();
        words.push(c.clone());
        for part in c.split(['@', '.', '-', '_', '+', ' ']) {
            if part.chars().count() >= 3 {
                words.push(part.to_string());
            }
        }
    }
    words.sort_by_key(|w| std::cmp::Reverse(w.len()));
    let mut rest = Zeroizing::new(compact.to_string());
    for w in &words {
        if !w.is_empty() {
            *rest = rest.replace(w.as_str(), "");
        }
    }
    let rest_distinct: std::collections::BTreeSet<char> = rest.chars().collect();
    if rest.chars().count() < 8 || rest_distinct.len() < 4 {
        return Err(weak(
            "the password is based on your name, email or the vault name",
        ));
    }
    Ok(())
}

/// Returns a warning (not a block) for passwords that look low in entropy.
pub fn warning(password: &str) -> Option<String> {
    let p = normalize(password);
    let classes = [
        p.chars().any(|c| c.is_lowercase()),
        p.chars().any(|c| c.is_uppercase()),
        p.chars().any(|c| c.is_ascii_digit()),
        p.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    let words = p
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .count();
    if p.chars().count() < 20 && classes <= 1 && words <= 2 {
        Some("the password looks easy to guess; consider `nepomuk passgen`".into())
    } else {
        None
    }
}

fn wordlist() -> Vec<&'static str> {
    WORDS
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .collect()
}

/// A passphrase of `n` words from the EFF large wordlist (6 words ≈ 77 bits).
pub fn passgen(n: usize) -> Zeroizing<String> {
    let words = wordlist();
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        // Rejection sampling for an unbiased index.
        let limit = u32::MAX - (u32::MAX % words.len() as u32);
        let idx = loop {
            let r = u32::from_le_bytes(crate::crypto::random_bytes::<4>());
            if r < limit {
                break r as usize % words.len();
            }
        };
        out.push(words[idx]);
    }
    Zeroizing::new(out.join("-"))
}

pub fn passgen_bits(n: usize) -> f64 {
    n as f64 * (wordlist().len() as f64).log2()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        assert!(check("short", &[]).is_err());
        assert!(check("correcthorsebatterystaple", &[]).is_err());
        assert!(check("aaaaaaaaaaaaaaaaaaaa", &[]).is_err());
        assert!(check("jane.doe@example.com1", &["jane.doe@example.com"]).is_err());
        assert!(check("nepomuknepomuk123", &[]).is_err());
        assert!(check("vivid-otter-cabinet-plume", &["jane@example.com"]).is_ok());
        assert!(check("žluťoučký kůň úpěl", &[]).is_ok());
    }

    #[test]
    fn generator() {
        let p = passgen(6);
        assert!(p.split('-').count() >= 6);
        assert!(passgen_bits(6) > 77.0);
        assert_eq!(wordlist().len(), 7776);
    }
}
