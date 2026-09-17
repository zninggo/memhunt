//! Oracle-driven block-cipher key hunting over a memory dump.
//!
//! Search strategies per candidate key window:
//! - ECB: decrypt the first blocks of the ciphertext, validate with oracles.
//! - CBC: decrypt blocks 1..n (which do not depend on the IV), validate.
//!   On a hit, a second pass scans the dump for the IV.
//! - CTR: decrypt the first two keystream blocks with an explicit counter,
//!   validate with oracles, then fully decrypt on a hit.
//! - GCM: with a tag, verify the ciphertext/tag pair deterministically;
//!   without a tag, use the same oracle path as CTR.
//!
//! The engine is cipher-agnostic: it operates on [`BlockCipher`] trait
//! objects, so AES (cipher 0.4 family) and DES/3DES/SM4 (cipher 0.5 family)
//! share one code path. Block size comes from the cipher (8 for DES family,
//! 16 for AES/SM4), and CBC IV length always equals the block size.
//!
//! Only the first `VERIFY_BLOCKS` blocks are decrypted during candidate
//! validation; full decryption happens once per hit.

use crate::cipher_adapter::BlockCipher;
use crate::oracle::{best_match, Oracle};
use crate::report::{Confidence, Hit, IvCandidate, Mode, ScanResult, ScanStats};
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

const VERIFY_BLOCKS: usize = 2;

#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Which cipher families/variants to try.
    pub ciphers: Vec<CipherChoice>,
    /// Cipher mode selected by `--cipher` tokens.
    pub mode: CipherMode,
    /// Stop after this many hits (0 = unlimited).
    pub max_hits: usize,
    /// After a CBC hit, scan the dump for the IV.
    pub scan_iv: bool,
    /// Use a fixed IV instead of scanning (skips CBC-without-IV limitations).
    pub fixed_iv: Option<Vec<u8>>,
    /// Initial counter block for CTR, or 12-byte nonce for GCM.
    pub nonce: Option<Vec<u8>>,
    /// GCM authentication tag; enables deterministic zero-false-positive hunting.
    pub tag: Option<Vec<u8>>,
    /// Additional authenticated data for GCM tag verification.
    pub aad: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    Block,
    Ctr,
    Gcm,
}

#[derive(Debug, Clone)]
pub struct CipherSelection {
    pub ciphers: Vec<CipherChoice>,
    pub mode: CipherMode,
}

/// A cipher to hunt with, as a CLI-friendly enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CipherChoice {
    Aes128,
    Aes192,
    Aes256,
    Des,
    TdesEde3,
    Sm4,
}

impl CipherChoice {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Aes128 => "aes-128",
            Self::Aes192 => "aes-192",
            Self::Aes256 => "aes-256",
            Self::Des => "des",
            Self::TdesEde3 => "3des-ede3",
            Self::Sm4 => "sm4",
        }
    }

    pub fn is_aes(&self) -> bool {
        matches!(self, Self::Aes128 | Self::Aes192 | Self::Aes256)
    }

    /// Parse a cipher list. Tokens may select CTR or GCM with a `-ctr` or
    /// `-gcm` suffix; all tokens must select the same mode.
    pub fn parse_list(spec: &str) -> Result<CipherSelection, String> {
        let mut out = Vec::new();
        let mut mode = None;
        for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let lower = part.to_ascii_lowercase();
            let (token, token_mode) = if let Some(token) = lower.strip_suffix("-ctr") {
                (token, CipherMode::Ctr)
            } else if let Some(token) = lower.strip_suffix("-gcm") {
                (token, CipherMode::Gcm)
            } else {
                (lower.as_str(), CipherMode::Block)
            };
            if let Some(mode) = mode {
                if mode != token_mode {
                    return Err("cipher list cannot mix modes".into());
                }
            } else {
                mode = Some(token_mode);
            }
            match token {
                "aes-128" | "aes128" => out.push(Self::Aes128),
                "aes-192" | "aes192" => out.push(Self::Aes192),
                "aes-256" | "aes256" => out.push(Self::Aes256),
                "aes" => out.extend([Self::Aes128, Self::Aes192, Self::Aes256]),
                "des" if token_mode == CipherMode::Block => out.push(Self::Des),
                "3des" | "3des-ede3" | "tdes" if token_mode == CipherMode::Block => {
                    out.push(Self::TdesEde3)
                }
                "sm4" if token_mode == CipherMode::Block => out.push(Self::Sm4),
                "all" if token_mode == CipherMode::Block => out.extend(Self::all()),
                other => {
                    return Err(format!(
                        "unknown cipher '{other}' (aes-128 | aes-192 | aes-256 | des | 3des | sm4 | all | aes-<size>-ctr | aes-<size>-gcm)"
                    ))
                }
            }
        }
        if out.is_empty() {
            return Err("no cipher specified".into());
        }
        if token_mode_requires_aes(mode.unwrap_or(CipherMode::Block))
            && out.iter().any(|choice| !choice.is_aes())
        {
            return Err("CTR and GCM support AES keys only".into());
        }
        out.sort();
        out.dedup();
        Ok(CipherSelection {
            ciphers: out,
            mode: mode.unwrap_or(CipherMode::Block),
        })
    }

    pub fn all() -> [Self; 6] {
        [
            Self::Aes128,
            Self::Aes192,
            Self::Aes256,
            Self::Des,
            Self::TdesEde3,
            Self::Sm4,
        ]
    }

    fn adapter(&self) -> Box<dyn BlockCipher> {
        match self {
            Self::Aes128 => Box::new(crate::cipher_adapter::aes128()),
            Self::Aes192 => Box::new(crate::cipher_adapter::aes192()),
            Self::Aes256 => Box::new(crate::cipher_adapter::aes256()),
            Self::Des => Box::new(crate::cipher_adapter::des()),
            Self::TdesEde3 => Box::new(crate::cipher_adapter::tdes_ede3()),
            Self::Sm4 => Box::new(crate::cipher_adapter::sm4()),
        }
    }
}

fn token_mode_requires_aes(mode: CipherMode) -> bool {
    mode != CipherMode::Block
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            ciphers: vec![
                CipherChoice::Aes128,
                CipherChoice::Aes192,
                CipherChoice::Aes256,
            ],
            mode: CipherMode::Block,
            max_hits: 0,
            scan_iv: true,
            fixed_iv: Option::None,
            nonce: Option::None,
            tag: Option::None,
            aad: Option::None,
        }
    }
}

/// Split ciphertext into blocks; errors when empty or not block-aligned.
fn split_blocks(ciphertext: &[u8], block: usize) -> Result<Vec<&[u8]>, String> {
    if ciphertext.is_empty() {
        return Err("ciphertext is empty".into());
    }
    if !ciphertext.len().is_multiple_of(block) {
        return Err(format!(
            "ciphertext length {} is not a multiple of the block size ({})",
            ciphertext.len(),
            block
        ));
    }
    Ok(ciphertext.chunks_exact(block).collect())
}

fn strip_pkcs7(plaintext: &mut Vec<u8>) -> bool {
    let Some(&n) = plaintext.last() else {
        return false;
    };
    if n as usize == 0 || n as usize > plaintext.len() || n as usize > 255 {
        return false;
    }
    let n = n as usize;
    if plaintext[plaintext.len() - n..]
        .iter()
        .all(|&b| b == n as u8)
    {
        plaintext.truncate(plaintext.len() - n);
        true
    } else {
        false
    }
}

fn strip_zero(plaintext: &mut Vec<u8>) -> bool {
    while plaintext.last() == Some(&0) {
        plaintext.pop();
    }
    true
}

fn to_utf8(bytes: &[u8]) -> Option<String> {
    std::str::from_utf8(bytes).ok().map(|s| s.to_string())
}

/// 0..=1000 score of how "plaintext-like" a block is: valid UTF-8 and mostly
/// printable. Tie-breaker when ranking IV candidates under a weak oracle.
fn block0_plausibility(block: &[u8]) -> u32 {
    let Ok(s) = std::str::from_utf8(block) else {
        return 0;
    };
    if s.is_empty() {
        return 0;
    }
    let printable = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\r' || *c == '\t')
        .count();
    ((printable as u64 * 1000) / s.chars().count() as u64) as u32
}

fn validate_config(config: &ScanConfig) -> Result<(), String> {
    match config.mode {
        CipherMode::Block => {
            if config.nonce.is_some() {
                return Err("nonce is only valid for CTR or GCM".into());
            }
            if config.tag.is_some() {
                return Err("tag is only valid for GCM".into());
            }
            if config.aad.is_some() {
                return Err("aad is only valid for GCM".into());
            }
        }
        CipherMode::Ctr => {
            if config.fixed_iv.is_some() {
                return Err("use --nonce, not --iv, for CTR".into());
            }
            if config.tag.is_some() {
                return Err("tag is only valid for GCM".into());
            }
            if config.aad.is_some() {
                return Err("aad is only valid for GCM".into());
            }
            let nonce = config.nonce.as_deref().ok_or("nonce is required for CTR")?;
            if nonce.len() != 16 {
                return Err("CTR nonce must be a 16-byte initial counter block".into());
            }
        }
        CipherMode::Gcm => {
            if config.fixed_iv.is_some() {
                return Err("use --nonce, not --iv, for GCM".into());
            }
            let nonce = config.nonce.as_deref().ok_or("nonce is required for GCM")?;
            if nonce.len() != 12 {
                return Err("GCM nonce must be 12 bytes".into());
            }
            if let Some(tag) = config.tag.as_deref() {
                if tag.len() != 16 {
                    return Err("GCM tag must be 16 bytes".into());
                }
            } else if config.aad.is_some() {
                return Err("GCM aad requires a tag".into());
            }
        }
    }
    if config.mode != CipherMode::Block && config.ciphers.iter().any(|choice| !choice.is_aes()) {
        return Err("CTR and GCM support AES keys only".into());
    }
    Ok(())
}

/// Scan a dump for keys that decrypt `ciphertext` into oracle-valid plaintext.
pub fn scan(
    dump: &[u8],
    ciphertext: &[u8],
    oracles: &[Box<dyn Oracle>],
    config: &ScanConfig,
) -> Result<ScanResult, String> {
    validate_config(config)?;
    if (config.mode != CipherMode::Gcm || config.tag.is_none()) && oracles.is_empty() {
        return Err("no oracle specified".into());
    }

    let start = Instant::now();
    let tried = AtomicU64::new(0);
    let stop = AtomicBool::new(false);
    let mut all_hits: Vec<Hit> = Vec::new();

    for choice in &config.ciphers {
        let cipher = choice.adapter();
        let block = cipher.block_len();
        let key_len = cipher.key_len();
        if dump.len() < key_len {
            continue;
        }
        let algo = cipher.algo().to_string();

        let hits = if config.mode == CipherMode::Block {
            let blocks = split_blocks(ciphertext, block)?;
            let iv = config
                .fixed_iv
                .as_ref()
                .map(|iv| {
                    let arr: &[u8] = iv;
                    if arr.len() != block {
                        return Err(format!(
                            "fixed IV length {} does not match {} block size {}",
                            arr.len(),
                            algo,
                            block
                        ));
                    }
                    Ok(arr.to_vec())
                })
                .transpose()?;

            hunt(
                dump,
                &blocks,
                block,
                cipher.as_ref(),
                oracles,
                config,
                &algo,
                iv,
                &tried,
                &stop,
            )
        } else {
            if ciphertext.is_empty() {
                return Err("ciphertext is empty".into());
            }
            hunt_stream(
                dump,
                ciphertext,
                block,
                cipher.as_ref(),
                oracles,
                config,
                &algo,
                &tried,
                &stop,
            )
        };
        all_hits.extend(hits);
        if config.max_hits > 0 && all_hits.len() >= config.max_hits {
            all_hits.truncate(config.max_hits);
            break;
        }
    }

    let duration_ms = start.elapsed().as_millis();
    let tried = tried.load(Ordering::Relaxed);
    let secs = (duration_ms.max(1)) as f64 / 1000.0;
    Ok(ScanResult {
        stats: ScanStats {
            dump_size: dump.len(),
            candidates_tried: tried,
            duration_ms,
            candidates_per_sec: (tried as f64 / secs) as u64,
        },
        hits: all_hits,
    })
}

/// One plausible-IV candidate kept compact for the parallel scan.
struct IvRawCandidate {
    offset: usize,
    iv: Vec<u8>,
    b0: Vec<u8>,
    name: &'static str,
    confidence: Confidence,
    plaus: u32,
}

/// A ranked IV candidate (offset, raw IV bytes, its decrypted block 0, the
/// matching oracle and its confidence), best first.
type IvHit = (usize, Vec<u8>, Vec<u8>, &'static str, Confidence);

const IV_CANDIDATES_MAX: usize = 8;

/// Number of plausible-IV candidates kept (best first) from an IV scan pass.
fn find_iv(
    dump: &[u8],
    dec0: &[u8],
    tail: &[u8],
    block: usize,
    oracles: &[Box<dyn Oracle>],
) -> Vec<IvHit> {
    let mut candidates: Vec<IvRawCandidate> = dump
        .par_windows(block)
        .enumerate()
        .filter_map(|(offset, iv)| {
            let b0: Vec<u8> = dec0[..block]
                .iter()
                .zip(iv.iter())
                .map(|(d, i)| d ^ i)
                .collect();
            let mut full = b0.clone();
            full.extend_from_slice(tail);
            let matched = best_match(oracles, &full)?;
            let plaus = block0_plausibility(&b0);
            Some(IvRawCandidate {
                offset,
                iv: iv.to_vec(),
                b0,
                name: matched.0,
                confidence: matched.1,
                plaus,
            })
        })
        .collect();
    // confidence desc, block-0 plausibility desc, offset asc
    candidates.sort_by(|a, b| {
        b.confidence
            .rank()
            .cmp(&a.confidence.rank())
            .then(b.plaus.cmp(&a.plaus).then(a.offset.cmp(&b.offset)))
    });
    candidates
        .into_iter()
        .take(IV_CANDIDATES_MAX)
        .map(|c| (c.offset, c.iv, c.b0, c.name, c.confidence))
        .collect()
}

fn increment_counter(counter: &mut [u8; 16]) {
    let value = u128::from_be_bytes(*counter);
    *counter = value.wrapping_add(1).to_be_bytes();
}

fn increment_counter32(counter: &mut [u8; 16]) {
    let value = u32::from_be_bytes(counter[12..].try_into().expect("counter suffix"));
    counter[12..].copy_from_slice(&value.wrapping_add(1).to_be_bytes());
}

fn gcm_j0(nonce: &[u8]) -> [u8; 16] {
    let mut counter = [0u8; 16];
    counter[..12].copy_from_slice(nonce);
    counter[15] = 1;
    counter
}

fn stream_decrypt(
    cipher: &dyn BlockCipher,
    key: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
    mode: CipherMode,
) -> Option<Vec<u8>> {
    let mut counter = match mode {
        CipherMode::Ctr => nonce.try_into().ok()?,
        CipherMode::Gcm => gcm_j0(nonce),
        CipherMode::Block => return None,
    };
    if mode == CipherMode::Gcm {
        increment_counter32(&mut counter);
    }

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks(16) {
        let mut keystream = counter;
        if !cipher.encrypt_with_key(key, &mut keystream) {
            return None;
        }
        plaintext.extend(
            chunk
                .iter()
                .zip(keystream)
                .map(|(byte, key_byte)| byte ^ key_byte),
        );
        match mode {
            CipherMode::Ctr => increment_counter(&mut counter),
            CipherMode::Gcm => increment_counter32(&mut counter),
            CipherMode::Block => return None,
        }
    }
    Some(plaintext)
}

fn decrypt_gcm_tagged(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    use aes_gcm::{
        aead::{consts::U12, AeadInPlace, KeyInit},
        AesGcm, Nonce, Tag,
    };

    let nonce = Nonce::<U12>::from_slice(nonce);
    let tag = Tag::from_slice(tag);
    let mut plaintext = ciphertext.to_vec();
    let result = match key.len() {
        16 => aes_gcm::Aes128Gcm::new_from_slice(key)
            .ok()?
            .decrypt_in_place_detached(nonce, aad, &mut plaintext, tag),
        24 => AesGcm::<aes::Aes192, U12>::new_from_slice(key)
            .ok()?
            .decrypt_in_place_detached(nonce, aad, &mut plaintext, tag),
        32 => aes_gcm::Aes256Gcm::new_from_slice(key)
            .ok()?
            .decrypt_in_place_detached(nonce, aad, &mut plaintext, tag),
        _ => return None,
    };
    result.ok()?;
    Some(plaintext)
}

#[allow(clippy::too_many_arguments)]
fn hunt_stream(
    dump: &[u8],
    ciphertext: &[u8],
    block: usize,
    cipher: &dyn BlockCipher,
    oracles: &[Box<dyn Oracle>],
    config: &ScanConfig,
    algo: &str,
    tried: &AtomicU64,
    stop: &AtomicBool,
) -> Vec<Hit> {
    let key_len = cipher.key_len();
    let nonce = config.nonce.as_deref().unwrap_or_default();
    let mode = match config.mode {
        CipherMode::Ctr => Mode::Ctr,
        CipherMode::Gcm => Mode::Gcm,
        CipherMode::Block => return Vec::new(),
    };
    let verify_len = (VERIFY_BLOCKS * block).min(ciphertext.len());
    let tag = config.tag.as_deref();
    let aad = config.aad.as_deref().unwrap_or_default();

    dump.par_windows(key_len)
        .enumerate()
        .filter(|_| !stop.load(Ordering::Relaxed))
        .filter_map(|(offset, key)| {
            tried.fetch_add(1, Ordering::Relaxed);

            if config.mode == CipherMode::Gcm {
                if let Some(tag) = tag {
                    let plaintext = decrypt_gcm_tagged(key, nonce, ciphertext, tag, aad)?;
                    return Some(finalize_stream_hit(
                        algo,
                        mode,
                        key,
                        offset,
                        nonce,
                        plaintext,
                        "gcm-tag",
                        Confidence::High,
                    ));
                }
            }

            let head = stream_decrypt(cipher, key, &ciphertext[..verify_len], nonce, config.mode)?;
            let (name, confidence) = best_match(oracles, &head)?;
            let plaintext = stream_decrypt(cipher, key, ciphertext, nonce, config.mode)?;
            Some(finalize_stream_hit(
                algo, mode, key, offset, nonce, plaintext, name, confidence,
            ))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn finalize_stream_hit(
    algo: &str,
    mode: Mode,
    key: &[u8],
    key_offset: usize,
    nonce: &[u8],
    plaintext: Vec<u8>,
    matched_by: &str,
    confidence: Confidence,
) -> Hit {
    Hit {
        algo: algo.to_string(),
        mode,
        key_hex: hex::encode(key),
        key_offset,
        iv_hex: None,
        iv_offset: None,
        nonce_hex: Some(hex::encode(nonce)),
        padding: None,
        plaintext_utf8: to_utf8(&plaintext),
        plaintext_hex: hex::encode(plaintext),
        matched_by: matched_by.to_string(),
        confidence,
        iv_candidates: Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn hunt(
    dump: &[u8],
    blocks: &[&[u8]],
    block: usize,
    cipher: &dyn BlockCipher,
    oracles: &[Box<dyn Oracle>],
    config: &ScanConfig,
    algo: &str,
    fixed_iv: Option<Vec<u8>>,
    tried: &AtomicU64,
    stop: &AtomicBool,
) -> Vec<Hit> {
    let n_blocks = blocks.len();
    let key_len = cipher.key_len();

    dump.par_windows(key_len)
        .enumerate()
        .filter(|_| !stop.load(Ordering::Relaxed))
        .filter_map(|(offset, key)| {
            tried.fetch_add(1, Ordering::Relaxed);

            // ---- ECB: verify against head blocks ----
            let mut head: Vec<Vec<u8>> = blocks
                .iter()
                .take(VERIFY_BLOCKS)
                .map(|b| b.to_vec())
                .collect();
            for b in &mut head {
                if !cipher.decrypt_with_key(key, b) {
                    return None;
                }
            }
            let head_flat: Vec<u8> = head.concat();
            if let Some((name, conf)) = best_match(oracles, &head_flat) {
                let mut plaintext: Vec<Vec<u8>> = blocks.iter().map(|b| b.to_vec()).collect();
                for b in &mut plaintext {
                    cipher.decrypt_with_key(key, b);
                }
                let mut pt = plaintext.concat();
                return Some(finalize_hit(
                    algo,
                    Mode::Ecb,
                    key,
                    offset,
                    None,
                    None,
                    Vec::new(),
                    &mut pt,
                    name,
                    conf,
                ));
            }

            // ---- CBC: verify blocks 1..n (IV-independent) ----
            let cbc_verifiable: Vec<&[u8]> =
                blocks.iter().skip(1).take(VERIFY_BLOCKS).copied().collect();
            let cbc_head: Option<Vec<u8>> = if !cbc_verifiable.is_empty() {
                let mut head: Vec<Vec<u8>> = cbc_verifiable.iter().map(|b| b.to_vec()).collect();
                for b in &mut head {
                    if !cipher.decrypt_with_key(key, b) {
                        return None;
                    }
                }
                // XOR with the preceding ciphertext block
                for i in 0..head.len() {
                    let prev = blocks[i];
                    for j in 0..block {
                        head[i][j] ^= prev[j];
                    }
                }
                Some(head.concat())
            } else if let Some(iv) = &fixed_iv {
                // single-block ciphertext: only verifiable with a known IV
                let mut b0 = blocks[0].to_vec();
                if !cipher.decrypt_with_key(key, &mut b0) {
                    return None;
                }
                for j in 0..block {
                    b0[j] ^= iv[j];
                }
                Some(b0)
            } else {
                None
            };

            if let Some(cbc_head) = cbc_head {
                if let Some((name, conf)) = best_match(oracles, &cbc_head) {
                    // blocks 1..n decrypt IV-independently
                    let mut tail: Vec<Vec<u8>> =
                        blocks.iter().skip(1).map(|b| b.to_vec()).collect();
                    for b in &mut tail {
                        cipher.decrypt_with_key(key, b);
                    }
                    for i in 0..tail.len() {
                        let prev = blocks[i];
                        for j in 0..block {
                            tail[i][j] ^= prev[j];
                        }
                    }

                    // Resolve block 0 via fixed IV or an IV scan pass.
                    let verified_tail: Vec<u8> = tail
                        .iter()
                        .take(VERIFY_BLOCKS)
                        .flat_map(|b| b.as_slice().iter().copied())
                        .collect();
                    let (iv_hex, iv_offset, head_block, iv_candidates) = match &fixed_iv {
                        Some(iv) => {
                            let mut b0 = blocks[0].to_vec();
                            cipher.decrypt_with_key(key, &mut b0);
                            for j in 0..block {
                                b0[j] ^= iv[j];
                            }
                            (Some(hex::encode(iv)), None, b0, Vec::new())
                        }
                        None if config.scan_iv && dump.len() >= block => {
                            let mut b0 = blocks[0].to_vec();
                            cipher.decrypt_with_key(key, &mut b0);
                            let cands = find_iv(dump, &b0, &verified_tail, block, oracles);
                            let iv_candidates = cands
                                .iter()
                                .map(|(off, iv, first, name, conf)| IvCandidate {
                                    iv_hex: hex::encode(iv),
                                    iv_offset: *off,
                                    confidence: *conf,
                                    block0_utf8: to_utf8(first),
                                    block0_hex: hex::encode(first),
                                    matched_by: name.to_string(),
                                })
                                .collect();
                            match cands.into_iter().next() {
                                Some((iv_off, iv, first, _n, _c)) => {
                                    (Some(hex::encode(iv)), Some(iv_off), first, iv_candidates)
                                }
                                None => (None, None, vec![b'?'; block], iv_candidates),
                            }
                        }
                        None => (None, None, vec![b'?'; block], Vec::new()),
                    };

                    let mut pt = head_block;
                    pt.extend(tail.iter().flat_map(|b| b.as_slice()));
                    let _ = n_blocks;
                    return Some(finalize_hit(
                        algo,
                        Mode::Cbc,
                        key,
                        offset,
                        iv_hex,
                        iv_offset,
                        iv_candidates,
                        &mut pt,
                        name,
                        conf,
                    ));
                }
            }

            None
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn finalize_hit(
    algo: &str,
    mode: Mode,
    key: &[u8],
    key_offset: usize,
    iv_hex: Option<String>,
    iv_offset: Option<usize>,
    iv_candidates: Vec<IvCandidate>,
    plaintext: &mut Vec<u8>,
    matched_by: &str,
    confidence: Confidence,
) -> Hit {
    let padding = if strip_pkcs7(plaintext) {
        Some("pkcs7".to_string())
    } else if strip_zero(plaintext) {
        Some("zero".to_string())
    } else {
        None
    };
    Hit {
        algo: algo.to_string(),
        mode,
        key_hex: hex::encode(key),
        key_offset,
        iv_hex,
        iv_offset,
        nonce_hex: None,
        padding,
        plaintext_utf8: to_utf8(plaintext),
        plaintext_hex: hex::encode(plaintext),
        matched_by: matched_by.to_string(),
        confidence,
        iv_candidates,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle::{JsonOracle, Utf8Oracle};
    use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};

    // NIST SP 800-38A F.1.1 / F.2.1 vectors (decryption direction)
    const KEY128: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    const PT: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
    ];
    const CT_ECB: [u8; 16] = [
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef,
        0x97,
    ];
    const IV: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const CT_CBC: [u8; 16] = [
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19,
        0x7d,
    ];

    fn oracles() -> Vec<Box<dyn Oracle>> {
        vec![Box::new(Utf8Oracle), Box::new(JsonOracle)]
    }

    #[test]
    fn split_blocks_rejects_bad_lengths() {
        assert!(split_blocks(&[], 16).is_err());
        assert!(split_blocks(&[0u8; 15], 16).is_err());
        assert_eq!(split_blocks(&[0u8; 32], 16).unwrap().len(), 2);
    }

    #[test]
    fn pkcs7_strip() {
        let mut v = vec![b'a', b'b', 2, 2];
        assert!(strip_pkcs7(&mut v));
        assert_eq!(v, vec![b'a', b'b']);
        let mut bad = vec![b'a', b'b', 5, 2];
        assert!(!strip_pkcs7(&mut bad));
    }

    #[test]
    fn nist_ecb_roundtrip() {
        let cipher = aes::Aes128::new_from_slice(&KEY128).unwrap();
        let mut block = CT_ECB;
        cipher.decrypt_block(GenericArray::from_mut_slice(&mut block));
        assert_eq!(block, PT);
    }

    #[test]
    fn nist_cbc_roundtrip() {
        let cipher = aes::Aes128::new_from_slice(&KEY128).unwrap();
        let mut block = CT_CBC;
        cipher.decrypt_block(GenericArray::from_mut_slice(&mut block));
        for j in 0..16 {
            block[j] ^= IV[j];
        }
        assert_eq!(block, PT);
    }

    #[test]
    fn finds_ecb_key_at_offset() {
        let plaintext = b"{\"user\":\"admin\",\"token\":\"abc123\"}";
        let cipher = aes::Aes128::new_from_slice(&KEY128).unwrap();
        let mut padded = plaintext.to_vec();
        let pad = 16 - padded.len() % 16;
        padded.extend(std::iter::repeat_n(pad as u8, pad));
        let mut ct: Vec<[u8; 16]> = padded.as_chunks::<16>().0.to_vec();
        for b in &mut ct {
            cipher.encrypt_block(GenericArray::from_mut_slice(b));
        }
        let ciphertext: Vec<u8> = ct.concat();

        let mut dump = vec![0x41u8; 4096];
        let key_offset = 2048;
        dump[key_offset..key_offset + 16].copy_from_slice(&KEY128);

        let result = scan(&dump, &ciphertext, &oracles(), &ScanConfig::default()).unwrap();
        assert!(result.hits.iter().any(|h| {
            h.mode == Mode::Ecb
                && h.key_offset == key_offset
                && h.plaintext_utf8.as_deref() == Some(std::str::from_utf8(plaintext).unwrap())
        }));
    }

    #[test]
    fn rejects_non_block_ciphertext() {
        let dump = vec![0u8; 64];
        assert!(scan(&dump, &[0u8; 10], &oracles(), &ScanConfig::default()).is_err());
    }

    #[test]
    fn parse_list_accepts_stream_tokens() {
        let selection = CipherChoice::parse_list("aes-128-ctr").unwrap();
        assert_eq!(selection.mode, CipherMode::Ctr);
        assert_eq!(selection.ciphers, vec![CipherChoice::Aes128]);

        let selection = CipherChoice::parse_list("aes-gcm").unwrap();
        assert_eq!(selection.mode, CipherMode::Gcm);
        assert_eq!(
            selection.ciphers,
            vec![
                CipherChoice::Aes128,
                CipherChoice::Aes192,
                CipherChoice::Aes256
            ]
        );
        assert!(CipherChoice::parse_list("aes-128-ctr,aes-128-gcm").is_err());
    }

    #[test]
    fn nist_ctr_roundtrip() {
        let nonce: [u8; 16] = [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
            0xfe, 0xff,
        ];
        let ciphertext: [u8; 32] = [
            0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d,
            0xb6, 0xce, 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b,
            0xb9, 0xff, 0xfd, 0xff,
        ];
        let expected: [u8; 32] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51,
        ];
        let cipher = crate::cipher_adapter::aes128();
        let plaintext =
            stream_decrypt(&cipher, &KEY128, &ciphertext, &nonce, CipherMode::Ctr).unwrap();
        assert_eq!(plaintext, expected);
    }

    #[test]
    fn gcm_aad_requires_tag() {
        let dump = vec![0u8; 4096];
        let config = ScanConfig {
            ciphers: vec![CipherChoice::Aes128],
            mode: CipherMode::Gcm,
            nonce: Some(vec![0u8; 12]),
            aad: Some(Vec::new()),
            ..ScanConfig::default()
        };
        let error = scan(&dump, &[0u8; 16], &oracles(), &config).unwrap_err();
        assert_eq!(error, "GCM aad requires a tag");
    }

    #[test]
    fn nist_gcm_tag_verification() {
        assert_eq!(
            decrypt_gcm_tagged(
                &[
                    0xc9, 0x39, 0xcc, 0x13, 0x39, 0x7c, 0x1d, 0x37, 0xde, 0x6a, 0xe0, 0xe1, 0xcb,
                    0x7c, 0x42, 0x3c,
                ],
                &[0xb3, 0xd8, 0xcc, 0x01, 0x7c, 0xbb, 0x89, 0xb3, 0x9e, 0x0f, 0x67, 0xe2,],
                &[
                    0x93, 0xfe, 0x7d, 0x9e, 0x9b, 0xfd, 0x10, 0x34, 0x8a, 0x56, 0x06, 0xe5, 0xca,
                    0xfa, 0x73, 0x54,
                ],
                &[
                    0x00, 0x32, 0xa1, 0xdc, 0x85, 0xf1, 0xc9, 0x78, 0x69, 0x25, 0xa2, 0xe7, 0x1d,
                    0x82, 0x72, 0xdd,
                ],
                &[
                    0x24, 0x82, 0x56, 0x02, 0xbd, 0x12, 0xa9, 0x84, 0xe0, 0x09, 0x2d, 0x3e, 0x44,
                    0x8e, 0xda, 0x5f,
                ],
            ),
            Some(
                [
                    0xc3, 0xb3, 0xc4, 0x1f, 0x11, 0x3a, 0x31, 0xb7, 0x3d, 0x9a, 0x5c, 0xd4, 0x32,
                    0x10, 0x30, 0x69,
                ]
                .to_vec(),
            )
        );

        assert_eq!(
            decrypt_gcm_tagged(
                &[
                    0x92, 0xe1, 0x1d, 0xcd, 0xaa, 0x86, 0x6f, 0x5c, 0xe7, 0x90, 0xfd, 0x24, 0x50,
                    0x1f, 0x92, 0x50, 0x9a, 0xac, 0xf4, 0xcb, 0x8b, 0x13, 0x39, 0xd5, 0x0c, 0x9c,
                    0x12, 0x40, 0x93, 0x5d, 0xd0, 0x8b,
                ],
                &[0xac, 0x93, 0xa1, 0xa6, 0x14, 0x52, 0x99, 0xbd, 0xe9, 0x02, 0xf2, 0x1a,],
                &[
                    0x89, 0x95, 0xae, 0x2e, 0x6d, 0xf3, 0xdb, 0xf9, 0x6f, 0xac, 0x7b, 0x71, 0x37,
                    0xba, 0xe6, 0x7f,
                ],
                &[
                    0xec, 0xa5, 0xaa, 0x77, 0xd5, 0x1d, 0x4a, 0x0a, 0x14, 0xd9, 0xc5, 0x1e, 0x1d,
                    0xa4, 0x74, 0xab,
                ],
                &[
                    0x1e, 0x08, 0x89, 0x01, 0x6f, 0x67, 0x60, 0x1c, 0x8e, 0xbe, 0xa4, 0x94, 0x3b,
                    0xc2, 0x3a, 0xd6,
                ],
            ),
            Some(
                [
                    0x2d, 0x71, 0xbc, 0xfa, 0x91, 0x4e, 0x4a, 0xc0, 0x45, 0xb2, 0xaa, 0x60, 0x95,
                    0x5f, 0xad, 0x24,
                ]
                .to_vec(),
            )
        );
    }

    #[test]
    fn gcm_192_key_size_is_supported() {
        use aes_gcm::aead::{consts::U12, AeadInPlace, KeyInit};

        let key = [0x33u8; 24];
        let nonce = [0x44u8; 12];
        let plaintext = b"{\"aes\":192}".to_vec();
        let mut ciphertext = plaintext.clone();
        let cipher = aes_gcm::AesGcm::<aes::Aes192, U12>::new_from_slice(&key).unwrap();
        let tag = cipher
            .encrypt_in_place_detached(nonce.as_slice().into(), b"", &mut ciphertext)
            .unwrap();
        assert_eq!(
            decrypt_gcm_tagged(&key, &nonce, &ciphertext, tag.as_slice(), b""),
            Some(plaintext)
        );
    }
}
