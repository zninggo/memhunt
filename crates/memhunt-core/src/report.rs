use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn rank(self) -> u8 {
        match self {
            Confidence::Low => 0,
            Confidence::Medium => 1,
            Confidence::High => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Ecb,
    Cbc,
    Ctr,
    Gcm,
}

/// One plausible IV location found by the IV scan pass.
///
/// Multiple candidates are kept for weak oracles (e.g. `utf8` alone), ordered
/// by descending confidence. Consumers should treat a non-unique top candidate
/// as "best effort", and prefer higher-confidence entries.
#[derive(Debug, Clone, Serialize)]
pub struct IvCandidate {
    pub iv_hex: String,
    pub iv_offset: usize,
    pub confidence: Confidence,
    /// The oracle that matched this candidate's decrypted plaintext.
    pub matched_by: String,
    /// First 16 bytes of the candidate's plaintext (best guess), for eyeballing.
    pub block0_utf8: Option<String>,
    pub block0_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    pub algo: String,
    pub mode: Mode,
    pub key_hex: String,
    pub key_offset: usize,
    pub iv_hex: Option<String>,
    pub iv_offset: Option<usize>,
    pub nonce_hex: Option<String>,
    pub padding: Option<String>,
    pub plaintext_utf8: Option<String>,
    pub plaintext_hex: String,
    pub matched_by: String,
    pub confidence: Confidence,
    /// All plausible IV candidates from the IV scan, best first. Populated
    /// only when an IV scan ran for a CBC hit; empty for ECB/fixed-IV hits.
    pub iv_candidates: Vec<IvCandidate>,
}

/// Statistics of one scan run.
#[derive(Debug, Clone, Serialize)]
pub struct ScanStats {
    pub dump_size: usize,
    pub candidates_tried: u64,
    pub duration_ms: u128,
    pub candidates_per_sec: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub hits: Vec<Hit>,
    pub stats: ScanStats,
}
