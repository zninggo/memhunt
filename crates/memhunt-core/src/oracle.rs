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

/// Plaintext decodes as UTF-16LE with mostly-printable Latin/BMP characters.
///
/// Windows and Java applications keep strings as UTF-16LE in memory, so dumps
/// from `ReadProcessMemory` / JVM processes decrypt to UTF-16LE text that the
/// `utf8` oracle cannot see. Every other byte is a NUL for ASCII-range text —
/// a strong structural signature on its own.
pub struct Utf16LeOracle;

impl Oracle for Utf16LeOracle {
    fn name(&self) -> &'static str {
        "utf16le"
    }

    fn verify(&self, plaintext_head: &[u8]) -> bool {
        // UTF-16LE strings naturally end with a 0x00 high byte, so stripping
        // trailing zeros would eat half a code unit. Strip only full 0x0000
        // units (2 bytes at a time), then require an even byte count.
        let mut end = plaintext_head.len();
        while end >= 4 && plaintext_head[end - 2] == 0 && plaintext_head[end - 1] == 0 {
            end -= 2;
        }
        let head = &plaintext_head[..end];
        if head.len() < 8 || !head.len().is_multiple_of(2) {
            return false;
        }
        let units: Vec<u16> = head
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        // ASCII-range text dominates real-world UTF-16LE plaintexts: every
        // unit < 0x80, i.e. byte pairs (char, 0x00). Require >= 3/4 of units
        // to be printable ASCII to cut false positives, and no lone NUL unit.
        let printable = units.iter().filter(|&&u| (0x20..0x7f).contains(&u)).count();
        if printable * 4 < units.len() * 3 {
            return false;
        }
        // Reject all-NUL or single repeated char (padding artifacts).
        units.iter().any(|&u| u != 0) && units.iter().any(|&u| u != units[0])
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
}

/// Plaintext starts with the gzip magic bytes `1f 8b 08` (deflate stream).
///
/// Compressed request bodies are a common plaintext shape in modern web
/// APIs; the 3-byte magic plus the reserved-flag nibble being zero makes
/// accidental matches vanishingly rare.
pub struct GzipOracle;

impl Oracle for GzipOracle {
    fn name(&self) -> &'static str {
        "gzip"
    }

    fn verify(&self, plaintext_head: &[u8]) -> bool {
        // gzip header: magic 1f 8b, CM=8 (deflate), FLG must have the
        // reserved bits (bit 5..7) clear.
        match plaintext_head.first() {
            Some(0x1f) => {}
            _ => return false,
        }
        if plaintext_head.get(1) != Some(&0x8b) {
            return false;
        }
        if plaintext_head.get(2) != Some(&0x08) {
            return false;
        }
        match plaintext_head.get(3) {
            Some(flg) => flg & 0xe0 == 0,
            None => false,
        }
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }
}

/// Plaintext starts like an unencrypted protobuf message whose first field is
/// a length-delimited payload (common wire shape for signed/encrypted inner
/// payloads).
///
/// Detection is a heuristic on the first varint tag: tag byte with wire type
/// 2 (length-delimited) and field number 1..=15, followed by a plausible
/// varint length that fits within the head. This is intentionally loose —
/// protobuf has no magic number — so it is rated Medium.
pub struct ProtobufOracle;

impl ProtobufOracle {
    /// Read a varint from `data`, returning (value, bytes consumed).
    fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
        let mut value: u64 = 0;
        let mut shift = 0u32;
        for (i, &b) in data.iter().enumerate().take(10) {
            value |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Some((value, i + 1));
            }
            shift += 7;
        }
        None
    }
}

impl Oracle for ProtobufOracle {
    fn name(&self) -> &'static str {
        "protobuf"
    }

    fn verify(&self, plaintext_head: &[u8]) -> bool {
        // First byte: field 1..=15, wire type 2 (length-delimited).
        let Some(&tag) = plaintext_head.first() else {
            return false;
        };
        if tag & 0x07 != 0x02 || tag >> 3 == 0 || tag >> 3 > 15 {
            return false;
        }
        // Then a length varint that fits inside the head.
        let Some((len, consumed)) = Self::read_varint(&plaintext_head[1..]) else {
            return false;
        };
        let len = len as usize;
        let available = plaintext_head.len().saturating_sub(1 + consumed);
        len > 0 && len <= available
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
}

fn strip_trailing_zeros(data: &[u8]) -> &[u8] {
    let mut end = data.len();
    while end > 0 && data[end - 1] == 0 {
        end -= 1;
    }
    &data[..end]
}

/// Parse an oracle spec string (`utf8,json,known:password`) into oracle
/// instances. Shared by the CLI and the MCP server.
pub fn parse_spec(spec: &str) -> Result<Vec<Box<dyn Oracle>>, String> {
    let mut oracles: Vec<Box<dyn Oracle>> = Vec::new();
    for part in spec.split(',') {
        match part.trim() {
            "utf8" => oracles.push(Box::new(Utf8Oracle)),
            "json" => oracles.push(Box::new(JsonOracle)),
            "gzip" => oracles.push(Box::new(GzipOracle)),
            "utf16le" | "utf16" => oracles.push(Box::new(Utf16LeOracle)),
            "protobuf" => oracles.push(Box::new(ProtobufOracle)),
            spec if spec.starts_with("known:") => {
                oracles.push(Box::new(KnownPlaintextOracle {
                    fragment: spec.as_bytes()["known:".len()..].to_vec(),
                }));
            }
            "" => {}
            other => {
                return Err(format!(
                "unknown oracle '{other}' (utf8 | utf16le | json | gzip | protobuf | known:<text>)"
            ))
            }
        }
    }
    if oracles.is_empty() {
        return Err("no oracle enabled".into());
    }
    Ok(oracles)
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
