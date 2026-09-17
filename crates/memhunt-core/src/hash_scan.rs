//! Hash / HMAC matching in memory dumps.
//!
//! Two distinct searches, both driven by a known target digest:
//!
//! 1. **Preimage windows**: find any window in the dump whose digest equals
//!    the target — i.e. the plaintext whose hash you captured, still resident
//!    (e.g. a password, token, or request body that was hashed by the app).
//!    Scan every alignment and byte length in a configurable range (defaults:
//!    8..=128 bytes), plus the common fixed lengths used by signatures.
//!
//! 2. **HMAC keys**: find any window that, used as an HMAC key over a known
//!    message, yields the target MAC. This recovers the *secret* rather than
//!    the message.
//!
//! Both are embarrassingly parallel and run over `rayon`.

use crate::report::ScanStats;
use hmac::SimpleHmac;
use rayon::prelude::*;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// A hash algorithm usable for preimage/HMAC matching.
pub trait Hasher: Sync + Send {
    fn name(&self) -> &'static str;
    fn output_len(&self) -> usize;
    /// Hash `data` into `out` (exactly `output_len` bytes).
    fn hash_into(&self, data: &[u8], out: &mut [u8]);
    /// HMAC with `key` over `data`, into `out`.
    fn hmac_into(&self, key: &[u8], data: &[u8], out: &mut [u8]);
}

macro_rules! hasher_impl {
    ($name:ident, $digest:ty, $label:literal, $out_len:expr) => {
        pub struct $name;

        impl Hasher for $name {
            fn name(&self) -> &'static str {
                $label
            }
            fn output_len(&self) -> usize {
                $out_len
            }
            fn hash_into(&self, data: &[u8], out: &mut [u8]) {
                use digest::Digest;
                out.copy_from_slice(&<$digest>::digest(data));
            }
            fn hmac_into(&self, key: &[u8], data: &[u8], out: &mut [u8]) {
                use digest::{FixedOutput, KeyInit, Update};
                let mut mac = SimpleHmac::<$digest>::new_from_slice(key).unwrap();
                mac.update(data);
                let tag = mac.finalize_fixed();
                out.copy_from_slice(&tag);
            }
        }
    };
}

hasher_impl!(Md5Hasher, md5::Md5, "md5", 16);
hasher_impl!(Sha1Hasher, sha1::Sha1, "sha1", 20);
hasher_impl!(Sha256Hasher, sha2::Sha256, "sha256", 32);
hasher_impl!(Sm3Hasher, sm3::Sm3, "sm3", 32);

/// Which hash algorithms to run, parsed from a CLI spec.
#[derive(Debug, Clone)]
pub enum HashAlgoSpec {
    Md5,
    Sha1,
    Sha256,
    Sm3,
}

impl HashAlgoSpec {
    pub fn parse(spec: &str) -> Result<Vec<Self>, String> {
        let mut algos = Vec::new();
        for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match part {
                "md5" => algos.push(Self::Md5),
                "sha1" => algos.push(Self::Sha1),
                "sha256" => algos.push(Self::Sha256),
                "sm3" => algos.push(Self::Sm3),
                other => {
                    return Err(format!(
                        "unknown hash algo '{other}' (md5 | sha1 | sha256 | sm3)"
                    ))
                }
            }
        }
        if algos.is_empty() {
            return Err("no hash algo specified".into());
        }
        Ok(algos)
    }

    pub fn hasher(&self) -> Box<dyn Hasher> {
        match self {
            Self::Md5 => Box::new(Md5Hasher),
            Self::Sha1 => Box::new(Sha1Hasher),
            Self::Sha256 => Box::new(Sha256Hasher),
            Self::Sm3 => Box::new(Sm3Hasher),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sm3 => "sm3",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HashHit {
    pub algo: String,
    /// `preimage` = a dump window whose digest equals the target.
    /// `hmac_key` = a dump window that HMACs the known message to the target.
    pub kind: String,
    pub offset: usize,
    pub length: usize,
    pub match_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HashScanResult {
    pub hits: Vec<HashHit>,
    pub stats: ScanStats,
}

/// Range of window lengths for preimage search.
#[derive(Debug, Clone, Copy)]
pub struct LengthRange {
    pub min: usize,
    pub max: usize,
}

impl Default for LengthRange {
    fn default() -> Self {
        Self { min: 8, max: 128 }
    }
}

#[derive(Debug, Clone, Default)]
pub struct HashScanConfig {
    pub lengths: LengthRange,
    pub max_hits: usize,
}

/// Find dump windows whose digest equals `target_digest`.
pub fn scan_preimages(
    dump: &[u8],
    target_digest: &[u8],
    algos: &[HashAlgoSpec],
    config: &HashScanConfig,
) -> Result<HashScanResult, String> {
    if target_digest.is_empty() {
        return Err("target digest is empty".into());
    }
    let start = Instant::now();
    let tried = AtomicU64::new(0);
    let mut hits: Vec<HashHit> = Vec::new();

    for algo in algos {
        let hasher = algo.hasher();
        if target_digest.len() != hasher.output_len() {
            return Err(format!(
                "target digest length {} does not match {} output length {}",
                target_digest.len(),
                hasher.name(),
                hasher.output_len()
            ));
        }
        let found: Vec<HashHit> = (config.lengths.min..=config.lengths.max)
            .into_par_iter()
            .flat_map_iter(|len| {
                let mut out = vec![0u8; hasher.output_len()];
                let hasher = &hasher;
                let tried = &tried;
                dump.windows(len)
                    .enumerate()
                    .filter_map(move |(offset, win)| {
                        tried.fetch_add(1, Ordering::Relaxed);
                        hasher.hash_into(win, &mut out);
                        if out == target_digest {
                            Some(HashHit {
                                algo: hasher.name().to_string(),
                                kind: "preimage".to_string(),
                                offset,
                                length: len,
                                match_hex: hex::encode(win),
                            })
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        hits.extend(found);
        if config.max_hits > 0 && hits.len() >= config.max_hits {
            hits.truncate(config.max_hits);
            break;
        }
    }

    let duration_ms = start.elapsed().as_millis();
    let tried_count = tried.load(Ordering::Relaxed);
    let secs = (duration_ms.max(1)) as f64 / 1000.0;
    Ok(HashScanResult {
        hits,
        stats: ScanStats {
            dump_size: dump.len(),
            candidates_tried: tried_count,
            duration_ms,
            candidates_per_sec: (tried_count as f64 / secs) as u64,
        },
    })
}

/// Find dump windows that, as HMAC keys over `known_message`, produce the
/// target MAC — recovering the secret key.
pub fn scan_hmac_keys(
    digest_algo: &HashAlgoSpec,
    known_message: &[u8],
    target_mac: &[u8],
    dump: &[u8],
    config: &HashScanConfig,
) -> Result<HashScanResult, String> {
    let hasher = digest_algo.hasher();
    if target_mac.len() != hasher.output_len() {
        return Err(format!(
            "target MAC length {} does not match {} output length {}",
            target_mac.len(),
            hasher.name(),
            hasher.output_len()
        ));
    }
    let start = Instant::now();
    let tried = AtomicU64::new(0);

    // HMAC accepts any key length; scan the common ones and the range.
    let mut lengths: Vec<usize> = (config.lengths.min..=config.lengths.max).collect();
    for fixed in [16, 24, 32, 64] {
        if !lengths.contains(&fixed) {
            lengths.push(fixed);
        }
    }

    let hits: Vec<HashHit> = lengths
        .into_par_iter()
        .flat_map_iter(|len| {
            let mut out = vec![0u8; hasher.output_len()];
            let hasher = &hasher;
            let tried = &tried;
            dump.windows(len)
                .enumerate()
                .filter_map(move |(offset, key_win)| {
                    tried.fetch_add(1, Ordering::Relaxed);
                    hasher.hmac_into(key_win, known_message, &mut out);
                    if out == target_mac {
                        Some(HashHit {
                            algo: hasher.name().to_string(),
                            kind: "hmac_key".to_string(),
                            offset,
                            length: len,
                            match_hex: hex::encode(key_win),
                        })
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect();

    let duration_ms = start.elapsed().as_millis();
    let tried_count = tried.load(Ordering::Relaxed);
    let secs = (duration_ms.max(1)) as f64 / 1000.0;
    Ok(HashScanResult {
        hits,
        stats: ScanStats {
            dump_size: dump.len(),
            candidates_tried: tried_count,
            duration_ms,
            candidates_per_sec: (tried_count as f64 / secs) as u64,
        },
    })
}
