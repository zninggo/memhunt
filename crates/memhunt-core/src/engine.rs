//! Oracle-driven AES key hunting over a memory dump.
//!
//! Two search strategies per candidate key window (no IV required):
//! - ECB: decrypt the first blocks of the ciphertext, validate with oracles.
//! - CBC: decrypt blocks 1..n (which do not depend on the IV), validate.
//!   On a hit, a second pass scans the dump for the IV.
//!
//! Only the first `VERIFY_BLOCKS` blocks are decrypted during candidate
//! validation; full decryption happens once per hit.

use crate::oracle::{best_match, Oracle};
use crate::report::{Confidence, Hit, Mode, ScanResult, ScanStats};
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

const BLOCK: usize = 16;
const VERIFY_BLOCKS: usize = 2;

#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// AES key sizes to try, in bytes (16/24/32).
    pub key_sizes: Vec<usize>,
    /// Stop after this many hits (0 = unlimited).
    pub max_hits: usize,
    /// After a CBC hit, scan the dump for the IV.
    pub scan_iv: bool,
    /// Use a fixed IV instead of scanning (skips CBC-without-IV limitations).
    pub fixed_iv: Option<[u8; BLOCK]>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            key_sizes: vec![16, 24, 32],
            max_hits: 0,
            scan_iv: true,
            fixed_iv: None,
        }
    }
}

/// Split ciphertext into blocks; errors when empty or not block-aligned.
fn split_blocks(ciphertext: &[u8]) -> Result<Vec<&[u8; BLOCK]>, String> {
    if ciphertext.is_empty() {
        return Err("ciphertext is empty".into());
    }
    if !ciphertext.len().is_multiple_of(BLOCK) {
        return Err(format!(
            "ciphertext length {} is not a multiple of the AES block size (16)",
            ciphertext.len()
        ));
    }
    Ok(ciphertext.as_chunks::<BLOCK>().0.iter().collect())
}

fn strip_pkcs7(plaintext: &mut Vec<u8>) -> bool {
    let Some(&n) = plaintext.last() else {
        return false;
    };
    if n as usize == 0 || n as usize > plaintext.len() || n as usize > BLOCK {
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

/// Scan a dump for AES keys that decrypt `ciphertext` into oracle-valid plaintext.
pub fn scan(
    dump: &[u8],
    ciphertext: &[u8],
    oracles: &[Box<dyn Oracle>],
    config: &ScanConfig,
) -> Result<ScanResult, String> {
    let blocks = split_blocks(ciphertext)?;
    if oracles.is_empty() {
        return Err("no oracle specified".into());
    }

    let start = Instant::now();
    let tried = AtomicU64::new(0);
    let stop = AtomicBool::new(false);
    let mut all_hits: Vec<Hit> = Vec::new();

    for &key_len in &config.key_sizes {
        if key_len != 16 && key_len != 24 && key_len != 32 {
            return Err(format!("invalid AES key size {key_len} bytes"));
        }
        if dump.len() < key_len {
            continue;
        }
        let algo = format!("aes-{}", key_len * 8);
        let hits: Vec<Hit> = match key_len {
            16 => hunt::<aes::Aes128>(
                dump, &blocks, oracles, config, &algo, key_len, &tried, &stop,
            ),
            24 => hunt::<aes::Aes192>(
                dump, &blocks, oracles, config, &algo, key_len, &tried, &stop,
            ),
            _ => hunt::<aes::Aes256>(
                dump, &blocks, oracles, config, &algo, key_len, &tried, &stop,
            ),
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

#[allow(clippy::too_many_arguments)]
fn hunt<C>(
    dump: &[u8],
    blocks: &Vec<&[u8; BLOCK]>,
    oracles: &[Box<dyn Oracle>],
    config: &ScanConfig,
    algo: &str,
    key_len: usize,
    tried: &AtomicU64,
    stop: &AtomicBool,
) -> Vec<Hit>
where
    C: KeyInit + BlockDecrypt + Sync + Send,
{
    dump.par_windows(key_len)
        .enumerate()
        .filter(|_| !stop.load(Ordering::Relaxed))
        .filter_map(|(offset, key)| {
            tried.fetch_add(1, Ordering::Relaxed);
            let cipher = C::new_from_slice(key).ok()?;

            // ---- ECB: verify against head blocks ----
            let mut head: Vec<[u8; BLOCK]> =
                blocks.iter().take(VERIFY_BLOCKS).map(|b| **b).collect();
            for b in &mut head {
                cipher.decrypt_block(GenericArray::from_mut_slice(b));
            }
            let head_flat: Vec<u8> = head.concat();
            if let Some((name, conf)) = best_match(oracles, &head_flat) {
                let mut plaintext: Vec<[u8; BLOCK]> = blocks.iter().map(|b| **b).collect();
                for b in &mut plaintext {
                    cipher.decrypt_block(GenericArray::from_mut_slice(b));
                }
                let mut pt = plaintext.concat();
                return Some(finalize_hit(
                    algo,
                    Mode::Ecb,
                    key,
                    offset,
                    None,
                    None,
                    &mut pt,
                    name,
                    conf,
                ));
            }

            // ---- CBC: verify blocks 1..n (IV-independent) ----
            let cbc_verifiable: Vec<&[u8; BLOCK]> =
                blocks.iter().skip(1).take(VERIFY_BLOCKS).copied().collect();
            let cbc_head: Option<Vec<u8>> = if !cbc_verifiable.is_empty() {
                let mut head: Vec<[u8; BLOCK]> = cbc_verifiable.iter().map(|b| **b).collect();
                for b in &mut head {
                    cipher.decrypt_block(GenericArray::from_mut_slice(b));
                }
                // XOR with the preceding ciphertext block
                for i in 0..head.len() {
                    let prev = blocks[i]; // block before the (i+1)-th ciphertext block
                    for j in 0..BLOCK {
                        head[i][j] ^= prev[j];
                    }
                }
                Some(head.concat())
            } else if let Some(iv) = config.fixed_iv {
                // single-block ciphertext: only verifiable with a known IV
                let mut b0 = *blocks[0];
                cipher.decrypt_block(GenericArray::from_mut_slice(&mut b0));
                for j in 0..BLOCK {
                    b0[j] ^= iv[j];
                }
                Some(b0.to_vec())
            } else {
                None
            };

            if let Some(cbc_head) = cbc_head {
                if let Some((name, conf)) = best_match(oracles, &cbc_head) {
                    // blocks 1..n decrypt IV-independently
                    let mut tail: Vec<[u8; BLOCK]> = blocks.iter().skip(1).map(|b| **b).collect();
                    for b in &mut tail {
                        cipher.decrypt_block(GenericArray::from_mut_slice(b));
                    }
                    for i in 0..tail.len() {
                        let prev = blocks[i];
                        for j in 0..BLOCK {
                            tail[i][j] ^= prev[j];
                        }
                    }

                    // Resolve block 0 via fixed IV or an IV scan pass.
                    let (iv_hex, iv_offset, head_block) = match config.fixed_iv {
                        Some(iv) => {
                            let mut b0 = *blocks[0];
                            cipher.decrypt_block(GenericArray::from_mut_slice(&mut b0));
                            for j in 0..BLOCK {
                                b0[j] ^= iv[j];
                            }
                            (Some(hex::encode(iv)), None, b0.to_vec())
                        }
                        None if config.scan_iv && dump.len() >= BLOCK => {
                            let mut b0 = *blocks[0];
                            cipher.decrypt_block(GenericArray::from_mut_slice(&mut b0));
                            match find_iv(dump, &b0, oracles) {
                                Some((iv_off, iv, first)) => {
                                    (Some(hex::encode(iv)), Some(iv_off), first.to_vec())
                                }
                                None => (None, None, vec![b'?'; BLOCK]),
                            }
                        }
                        None => (None, None, vec![b'?'; BLOCK]),
                    };

                    let mut pt = head_block;
                    pt.extend(tail.concat());
                    return Some(finalize_hit(
                        algo,
                        Mode::Cbc,
                        key,
                        offset,
                        iv_hex,
                        iv_offset,
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

/// Scan the dump for 16-byte windows that, XORed with the pre-IV first
/// decryption, yield oracle-valid plaintext. All candidates are collected
/// (weak oracles produce false positives on random data), then ranked:
/// higher oracle confidence first, lower offset first.
fn find_iv(
    dump: &[u8],
    dec0: &[u8; BLOCK],
    oracles: &[Box<dyn Oracle>],
) -> Option<(usize, [u8; BLOCK], [u8; BLOCK])> {
    let mut candidates: Vec<(usize, [u8; BLOCK], [u8; BLOCK], u8)> = dump
        .par_windows(BLOCK)
        .enumerate()
        .filter_map(|(offset, iv)| {
            let mut first = [0u8; BLOCK];
            for j in 0..BLOCK {
                first[j] = dec0[j] ^ iv[j];
            }
            best_match(oracles, &first)
                .map(|(_, c)| (offset, iv.try_into().unwrap(), first, c.rank()))
        })
        .collect();
    candidates.sort_by(|a, b| b.3.cmp(&a.3).then(a.0.cmp(&b.0)));
    candidates
        .into_iter()
        .next()
        .map(|(offset, iv, first, _)| (offset, iv, first))
}

#[allow(clippy::too_many_arguments)]
fn finalize_hit(
    algo: &str,
    mode: Mode,
    key: &[u8],
    key_offset: usize,
    iv_hex: Option<String>,
    iv_offset: Option<usize>,
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
        padding,
        plaintext_utf8: to_utf8(plaintext),
        plaintext_hex: hex::encode(plaintext),
        matched_by: matched_by.to_string(),
        confidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle::{JsonOracle, Utf8Oracle};
    use aes::cipher::BlockEncrypt;

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
        assert!(split_blocks(&[]).is_err());
        assert!(split_blocks(&[0u8; 15]).is_err());
        assert_eq!(split_blocks(&[0u8; 32]).unwrap().len(), 2);
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
        for j in 0..BLOCK {
            block[j] ^= IV[j];
        }
        assert_eq!(block, PT);
    }

    #[test]
    fn finds_ecb_key_at_offset() {
        // Encrypt a readable plaintext so the oracles can validate the hit.
        let plaintext = b"{\"user\":\"admin\",\"token\":\"abc123\"}";
        let cipher = aes::Aes128::new_from_slice(&KEY128).unwrap();
        let mut padded = plaintext.to_vec();
        let pad = BLOCK - padded.len() % BLOCK;
        padded.extend(std::iter::repeat_n(pad as u8, pad));
        let mut ct: Vec<[u8; 16]> = padded.as_chunks::<BLOCK>().0.to_vec();
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
}
