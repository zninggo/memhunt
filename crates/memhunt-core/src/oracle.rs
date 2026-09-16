use crate::report::Confidence;

/// A hit validator: decides whether a decrypted plaintext prefix looks like a real plaintext.
/// Oracles are deliberately cheap — they run once per candidate key window.
pub trait Oracle: Sync + Send {
    fn name(&self) -> &'static str;
    fn verify(&self, plaintext_head: &[u8]) -> bool;
    fn confidence(&self) -> Confidence;
}

/// Plaintext decodes as UTF-8 with a printable-character majority.
pub struct Utf8Oracle;

impl Oracle for Utf8Oracle {
    fn name(&self) -> &'static str {
        "utf8"
    }

    fn verify(&self, plaintext_head: &[u8]) -> bool {
        // Tolerate zero padding: strip trailing NULs before validating.
        let head = strip_trailing_zeros(plaintext_head);
        if head.is_empty() {
            return false;
        }
        match std::str::from_utf8(head) {
            Ok(s) => {
                let printable = s
                    .chars()
                    .filter(|c| !c.is_control() || *c == '\n' || *c == '\r' || *c == '\t')
                    .count();
                printable * 10 >= s.chars().count() * 9
            }
            Err(_) => false,
        }
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
}

/// Plaintext starts a JSON document (`{` or `[`) and the prefix stays inside
/// the JSON-safe character set. Full-document parsing is done post-hit.
pub struct JsonOracle;

impl Oracle for JsonOracle {
    fn name(&self) -> &'static str {
        "json"
    }

    fn verify(&self, plaintext_head: &[u8]) -> bool {
        // Structural prefix constraints: a JSON object is `{"`, an array
        // starts with a value character. Random data that merely begins
        // with `{` must not pass (common false positive on IV scans).
        let structurally_valid = match plaintext_head.first() {
            Some(b'{') => plaintext_head.get(1) == Some(&b'"'),
            Some(b'[') => plaintext_head.get(1).is_some_and(|c| {
                c.is_ascii_digit() || matches!(c, b'"' | b'[' | b'{' | b' ' | b'\t')
            }),
            _ => false,
        };
        if !structurally_valid {
            return false;
        }
        std::str::from_utf8(plaintext_head).is_ok_and(|s| {
            s.chars()
                .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t')
        })
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }
}

/// Plaintext contains a known fragment (e.g. a request parameter name).
pub struct KnownPlaintextOracle {
    pub fragment: Vec<u8>,
}

impl Oracle for KnownPlaintextOracle {
    fn name(&self) -> &'static str {
        "known"
    }

    fn verify(&self, plaintext_head: &[u8]) -> bool {
        plaintext_head
            .windows(self.fragment.len().max(1))
            .any(|w| w == self.fragment.as_slice())
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }
}

fn strip_trailing_zeros(data: &[u8]) -> &[u8] {
    let mut end = data.len();
    while end > 0 && data[end - 1] == 0 {
        end -= 1;
    }
    &data[..end]
}

/// Runs every oracle, returns the name + confidence of the best match, or None.
pub fn best_match(
    oracles: &[Box<dyn Oracle>],
    plaintext_head: &[u8],
) -> Option<(&'static str, Confidence)> {
    oracles
        .iter()
        .filter(|o| o.verify(plaintext_head))
        .map(|o| (o.name(), o.confidence()))
        .max_by_key(|(_, c)| c.rank())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_accepts_printable_text() {
        let o = Utf8Oracle;
        assert!(o.verify(b"{\"user\":\"admin\",\"token\":\"a"));
        assert!(o.verify(b"hello\0\0\0\0\0\0\0\0\0\0\0"));
        assert!(!o.verify(&[0xff, 0xfe, 0x00, 0x01, 0x02, 0x03, 0x04]));
        assert!(!o.verify(&[0u8; 16]));
    }

    #[test]
    fn json_requires_object_or_array_start() {
        let o = JsonOracle;
        assert!(o.verify(b"{\"ok\":true"));
        assert!(o.verify(b"[1,2,3"));
        assert!(!o.verify(b"hello world"));
        assert!(!o.verify(&[0x7b, 0xff, 0xfe]));
        // Real-world false positive seen on an IV scan: `{` followed by
        // random bytes that happen to decode as UTF-8.
        assert!(!o.verify(b"{611\xd8\xb1,?\n\xca\xbfZv~i2"));
        assert!(!o.verify(b"{611"));
        assert!(!o.verify(b"[]")); // no value start after '['
    }

    #[test]
    fn known_matches_fragment() {
        let o = KnownPlaintextOracle {
            fragment: b"password".to_vec(),
        };
        assert!(o.verify(b"user=admin&password=x"));
        assert!(!o.verify(b"user=admin"));
    }

    #[test]
    fn best_match_picks_highest_confidence() {
        let oracles: Vec<Box<dyn Oracle>> = vec![Box::new(Utf8Oracle), Box::new(JsonOracle)];
        let m = best_match(&oracles, b"{\"a\":1}");
        assert_eq!(m, Some(("json", Confidence::High)));
    }
}
