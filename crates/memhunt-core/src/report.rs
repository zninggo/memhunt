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
}

#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    pub algo: String,
    pub mode: Mode,
    pub key_hex: String,
    pub key_offset: usize,
    pub iv_hex: Option<String>,
    pub iv_offset: Option<usize>,
    pub padding: Option<String>,
    pub plaintext_utf8: Option<String>,
    pub plaintext_hex: String,
    pub matched_by: String,
    pub confidence: Confidence,
}

/// Statistics of one scan run.
#[derive(Debug, Clone, Serialize)]
pub struct ScanStats {
    pub dump_size: usize,
    pub candidates_tried: u64,
    pub duration_ms: u128,
    pub candidates_per_sec: u64,
}

pub struct ScanResult {
    pub hits: Vec<Hit>,
    pub stats: ScanStats,
}
