use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use memhunt_core::{scan, CipherChoice, CipherMode, JsonOracle, Oracle, ScanConfig, Utf8Oracle};
use std::time::Instant;

const KEY: [u8; 16] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];
const KEY256: [u8; 32] = [
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
];
const CTR_COUNTER: [u8; 16] = [
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
];
const GCM_AAD: &[u8] = b"memhunt-aad";
const GCM_NONCE: [u8; 12] = [
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b,
];
const IV: [u8; 16] = [
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
];
const PLAINTEXT: &[u8] = b"{\"user\":\"admin\",\"role\":\"superuser\",\"exp\":1750000000}";
const KEY_OFFSET: usize = 150_000;
const IV_OFFSET: usize = 150_100;
const DUMP_SIZE: usize = 256 * 1024;

/// Offset/IV for the larger (release-only) throughput smoke.
const SMOKE_KEY_OFFSET: usize = 600_000;
const SMOKE_IV_OFFSET: usize = 600_100;
const SMOKE_DUMP_SIZE: usize = 1024 * 1024;

fn oracles() -> Vec<Box<dyn Oracle>> {
    vec![Box::new(Utf8Oracle), Box::new(JsonOracle)]
}

/// Deterministic pseudo-random dump filler (xorshift64*).
fn make_dump_size(size: usize) -> Vec<u8> {
    let mut state = 0x9E3779B97F4A7C15u64;
    let mut dump = Vec::with_capacity(size);
    while dump.len() < size {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let bytes = state.wrapping_mul(0x2545F4914F6CDD1D).to_le_bytes();
        dump.extend_from_slice(&bytes);
    }
    dump.truncate(size);
    dump
}

fn make_dump() -> Vec<u8> {
    make_dump_size(DUMP_SIZE)
}

fn pkcs7(data: &[u8]) -> Vec<u8> {
    let pad = 16 - data.len() % 16;
    let mut v = data.to_vec();
    v.extend(std::iter::repeat_n(pad as u8, pad));
    v
}

fn encrypt_ecb(plaintext: &[u8]) -> Vec<u8> {
    let cipher = aes::Aes128::new_from_slice(&KEY).unwrap();
    let padded = pkcs7(plaintext);
    padded
        .as_chunks::<16>()
        .0
        .iter()
        .flat_map(|c| {
            let mut b: [u8; 16] = *c;
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut b));
            b
        })
        .collect()
}

fn encrypt_cbc(plaintext: &[u8], iv: &[u8; 16]) -> Vec<u8> {
    let cipher = aes::Aes128::new_from_slice(&KEY).unwrap();
    let padded = pkcs7(plaintext);
    let mut prev = *iv;
    padded
        .as_chunks::<16>()
        .0
        .iter()
        .flat_map(|c| {
            let mut b: [u8; 16] = *c;
            for j in 0..16 {
                b[j] ^= prev[j];
            }
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut b));
            prev = b;
            b
        })
        .collect()
}

fn dump_with_key_and_iv() -> Vec<u8> {
    dump_with_key_and_iv_offsets(DUMP_SIZE, KEY_OFFSET, IV_OFFSET)
}

fn dump_with_key_and_iv_offsets(size: usize, key_off: usize, iv_off: usize) -> Vec<u8> {
    let mut dump = make_dump_size(size);
    dump[key_off..key_off + 16].copy_from_slice(&KEY);
    dump[iv_off..iv_off + 16].copy_from_slice(&IV);
    dump
}

fn encrypt_ctr(plaintext: &[u8]) -> Vec<u8> {
    let cipher = aes::Aes128::new_from_slice(&KEY).unwrap();
    let mut counter = CTR_COUNTER;
    plaintext
        .chunks(16)
        .flat_map(|chunk| {
            let mut keystream = counter;
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut keystream));
            let value = u128::from_be_bytes(counter);
            counter = value.wrapping_add(1).to_be_bytes();
            chunk
                .iter()
                .zip(keystream)
                .map(|(byte, key)| byte ^ key)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn encrypt_gcm_128(plaintext: &[u8]) -> (Vec<u8>, [u8; 16]) {
    use aes_gcm::aead::{AeadInPlace, KeyInit};

    let cipher = aes_gcm::Aes128Gcm::new_from_slice(&KEY).unwrap();
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(GCM_NONCE.as_slice().into(), b"", &mut ciphertext)
        .unwrap();
    (ciphertext, tag.as_slice().try_into().unwrap())
}

fn encrypt_gcm_256(plaintext: &[u8], aad: &[u8]) -> (Vec<u8>, [u8; 16]) {
    use aes_gcm::aead::{AeadInPlace, KeyInit};

    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&KEY256).unwrap();
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(GCM_NONCE.as_slice().into(), aad, &mut ciphertext)
        .unwrap();
    (ciphertext, tag.as_slice().try_into().unwrap())
}

fn dump_with_key(key: &[u8], offset: usize) -> Vec<u8> {
    let mut dump = make_dump_size(64 * 1024);
    dump[offset..offset + key.len()].copy_from_slice(key);
    dump
}

#[test]
fn end_to_end_ecb_hit() {
    let dump = dump_with_key_and_iv();
    let ciphertext = encrypt_ecb(PLAINTEXT);

    let result = scan(&dump, &ciphertext, &oracles(), &ScanConfig::default()).unwrap();
    let hit = result
        .hits
        .iter()
        .find(|h| h.key_offset == KEY_OFFSET && h.mode == memhunt_core::Mode::Ecb)
        .expect("expected ECB hit at planted key offset");
    assert_eq!(
        hit.plaintext_utf8.as_deref(),
        Some(std::str::from_utf8(PLAINTEXT).unwrap())
    );
    assert_eq!(hit.padding.as_deref(), Some("pkcs7"));
    assert_eq!(hit.matched_by, "json");
    assert_eq!(hit.confidence, memhunt_core::Confidence::High);
}

#[test]
fn end_to_end_cbc_hit_with_iv_scan() {
    let dump = dump_with_key_and_iv();
    let ciphertext = encrypt_cbc(PLAINTEXT, &IV);

    let result = scan(&dump, &ciphertext, &oracles(), &ScanConfig::default()).unwrap();
    let hit = result
        .hits
        .iter()
        .find(|h| h.key_offset == KEY_OFFSET && h.mode == memhunt_core::Mode::Cbc)
        .expect("expected CBC hit at planted key offset");
    assert_eq!(hit.iv_offset, Some(IV_OFFSET));
    assert_eq!(hit.iv_hex.as_deref(), Some(hex::encode(IV).as_str()));
    assert_eq!(
        hit.plaintext_utf8.as_deref(),
        Some(std::str::from_utf8(PLAINTEXT).unwrap())
    );
}

#[test]
fn end_to_end_single_block_cbc_with_fixed_iv() {
    let dump = dump_with_key_and_iv();
    // zero-padded single-block plaintext, encrypted manually (no pkcs7)
    let mut pt = b"hello".to_vec();
    pt.resize(16, 0);
    let cipher = aes::Aes128::new_from_slice(&KEY).unwrap();
    let mut block: [u8; 16] = pt.as_slice().try_into().unwrap();
    for j in 0..16 {
        block[j] ^= IV[j];
    }
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
    let ciphertext = block.to_vec();
    assert_eq!(ciphertext.len(), 16);

    let config = ScanConfig {
        fixed_iv: Some(IV.to_vec()),
        ..ScanConfig::default()
    };
    let result = scan(&dump, &ciphertext, &oracles(), &config).unwrap();
    let hit = result
        .hits
        .iter()
        .find(|h| h.key_offset == KEY_OFFSET && h.mode == memhunt_core::Mode::Cbc)
        .expect("expected CBC hit with fixed IV");
    assert_eq!(hit.plaintext_utf8.as_deref(), Some("hello"));
    assert_eq!(hit.padding.as_deref(), Some("zero"));
}

#[test]
fn no_high_confidence_hits_on_random_data() {
    let dump = make_dump();
    let ciphertext = encrypt_ecb(PLAINTEXT); // key is NOT planted in this dump

    let json_only: Vec<Box<dyn Oracle>> = vec![Box::new(JsonOracle)];
    let result = scan(&dump, &ciphertext, &json_only, &ScanConfig::default()).unwrap();
    assert!(
        result.hits.is_empty(),
        "unexpected hits on random dump: {:?}",
        result.hits.iter().map(|h| &h.key_hex).collect::<Vec<_>>()
    );
}

/// Reproduce handover bug 2b: a `known:<fragment>` whose fragment lies in a
/// later plaintext block (block 1, not block 0) must no longer defeat the IV
/// pass — it must return a decoded block 0 (a candidate), not 16 '?'.
///
/// With only a `known:` oracle and the fragment outside block 0, the oracle
/// cannot rank block-0 content (it matches every window's shared tail), so the
/// result is genuinely ambiguous; the honest contract is "no longer fails".
#[test]
fn known_fragment_in_later_block_still_finds_iv() {
    // "doctor" starts at byte 22 => inside block 1 (bytes 16..32).
    let fragment = b"doctor";
    let mut pt = b"{\"greet\":\"".to_vec();
    pt.extend(std::iter::repeat_n(b'x', 22 - pt.len())); // pad to byte 22
    pt.extend_from_slice(fragment);
    pt.extend_from_slice(b"\",\"ok\":true}");
    assert_eq!(&pt[22..22 + 6], fragment);
    assert!(
        !pt[0..16].windows(6).any(|w| w == fragment),
        "fragment must be in block 1+"
    );

    let ciphertext = encrypt_cbc(&pt, &IV);
    let dump = dump_with_key_and_iv();
    let oracles: Vec<Box<dyn Oracle>> = vec![Box::new(memhunt_core::KnownPlaintextOracle {
        fragment: fragment.to_vec(),
    })];
    let result = scan(&dump, &ciphertext, &oracles, &ScanConfig::default()).unwrap();
    let hit = result
        .hits
        .iter()
        .find(|h| h.key_offset == KEY_OFFSET && h.mode == memhunt_core::Mode::Cbc)
        .expect("expected CBC hit at planted key");
    // Bug 2b symptom: the IV pass must no longer return the "all '?'" failure.
    assert!(
        hit.iv_candidates.iter().any(|c| c.iv_offset == IV_OFFSET)
            || (!hit.plaintext_utf8.is_none()
                && !hit
                    .plaintext_utf8
                    .as_deref()
                    .unwrap_or("")
                    .starts_with(&"?".repeat(16))),
        "block 0 must be decoded (found IV or at least a non-'?' candidate): plaintext={:?}",
        hit.plaintext_utf8
    );
    assert!(
        !hit.iv_candidates.is_empty(),
        "IV scan must return candidates"
    );
}

/// Handover bug 1 (exit-code): a no-hit scan must exit 1, not 0. The library
/// `scan` has no exit code, so this is enforced at the CLI layer; here we just
/// assert the scan reports zero hits on an unrelated ciphertext.
#[test]
fn no_hits_when_ciphertext_uses_unknown_key() {
    let dump = make_dump();
    let ciphertext = encrypt_ecb(PLAINTEXT); // key is NOT planted
    let result = scan(&dump, &ciphertext, &oracles(), &ScanConfig::default()).unwrap();
    assert!(
        result.hits.is_empty(),
        "expected no hits: {:?}",
        result.hits.iter().map(|h| &h.key_hex).collect::<Vec<_>>()
    );
}

/// Throughput smoke (release-only, see [#ignore] note above).
#[test]
#[ignore = "1 MiB in debug is too slow for CI; run with --release -- --ignored"]
fn throughput_smoke_1mib() {
    let dump = dump_with_key_and_iv_offsets(SMOKE_DUMP_SIZE, SMOKE_KEY_OFFSET, SMOKE_IV_OFFSET);
    let ciphertext = encrypt_ecb(PLAINTEXT);
    let start = Instant::now();
    let result = scan(&dump, &ciphertext, &oracles(), &ScanConfig::default()).unwrap();
    let secs = start.elapsed().as_secs_f64();
    assert!(!result.hits.is_empty());
    eprintln!(
        "throughput: {} MiB scanned in {:.2}s ({:.1} MiB/s)",
        SMOKE_DUMP_SIZE as f64 / (1024.0 * 1024.0),
        secs,
        SMOKE_DUMP_SIZE as f64 / (1024.0 * 1024.0) / secs
    );
}

#[test]
fn sm4_cbc_end_to_end() {
    use sm4::cipher::{BlockCipherEncrypt, KeyInit};
    let sm4_key: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let sm4_iv: [u8; 16] = [0xa0; 16];
    // >= 48 bytes of JSON: the verified head (blocks 1..2 = bytes 16..47)
    // is a contiguous clean-JSON region for the json oracle to validate,
    // so the unique IV is pinned without padding noise in the tail.
    let pt = b"{\"user\":\"admin\",\"role\":\"sm4-test\",\"ok\":true,\"n\":1}";
    assert!(pt.len() > 32);
    let padded = pkcs7(pt);
    let cipher = sm4::Sm4::new_from_slice(&sm4_key).unwrap();
    let mut prev = sm4_iv;
    let mut ct: Vec<u8> = Vec::new();
    for c in padded.as_chunks::<16>().0 {
        let mut b: [u8; 16] = *c;
        for j in 0..16 {
            b[j] ^= prev[j];
        }
        cipher.encrypt_block((&mut b).into());
        prev = b;
        ct.extend_from_slice(&b);
    }

    let mut dump = make_dump();
    let key_off = 120_000;
    let iv_off = 120_100;
    dump[key_off..key_off + 16].copy_from_slice(&sm4_key);
    dump[iv_off..iv_off + 16].copy_from_slice(&sm4_iv);

    let config = ScanConfig {
        ciphers: vec![memhunt_core::CipherChoice::Sm4],
        ..ScanConfig::default()
    };
    let result = scan(&dump, &ct, &oracles(), &config).unwrap();
    let hit = result
        .hits
        .iter()
        .find(|h| h.key_offset == key_off && h.mode == memhunt_core::Mode::Cbc)
        .expect("expected SM4 CBC hit at planted key");
    assert_eq!(hit.algo, "sm4");
    assert_eq!(hit.iv_offset, Some(iv_off));
    assert_eq!(
        hit.plaintext_utf8.as_deref(),
        Some(std::str::from_utf8(pt).unwrap())
    );
}

#[test]
fn des_cbc_end_to_end() {
    use des::cipher::{BlockCipherEncrypt, KeyInit};
    let key: [u8; 8] = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37];
    let iv: [u8; 8] = [0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f];
    let pt = b"{\"user\":\"admin\"}"; // 16 bytes = 2 DES blocks, JSON so iv pins
    let cipher = des::Des::new_from_slice(&key).unwrap();
    let mut prev = iv;
    let mut ct: Vec<u8> = Vec::new();
    for c in pt.as_chunks::<8>().0 {
        let mut b: [u8; 8] = *c;
        for j in 0..8 {
            b[j] ^= prev[j];
        }
        cipher.encrypt_block((&mut b).into());
        prev = b;
        ct.extend_from_slice(&b);
    }

    let mut dump = make_dump();
    let key_off = 130_000;
    let iv_off = 130_100;
    dump[key_off..key_off + 8].copy_from_slice(&key);
    dump[iv_off..iv_off + 8].copy_from_slice(&iv);

    let config = ScanConfig {
        ciphers: vec![memhunt_core::CipherChoice::Des],
        ..ScanConfig::default()
    };
    let result = scan(&dump, &ct, &oracles(), &config).unwrap();
    let hit = result
        .hits
        .iter()
        .find(|h| h.key_offset == key_off && h.mode == memhunt_core::Mode::Cbc)
        .expect("expected DES CBC hit at planted key");
    assert_eq!(hit.algo, "des");
    assert_eq!(
        hit.iv_offset,
        Some(iv_off),
        "IV must be pinned by json oracle"
    );
}

#[test]
fn end_to_end_ctr_hit() {
    let key_offset = 30_000;
    let dump = dump_with_key(&KEY, key_offset);
    let ciphertext = encrypt_ctr(PLAINTEXT);
    let config = ScanConfig {
        ciphers: vec![CipherChoice::Aes128],
        mode: CipherMode::Ctr,
        nonce: Some(CTR_COUNTER.to_vec()),
        ..ScanConfig::default()
    };

    let result = scan(&dump, &ciphertext, &oracles(), &config).unwrap();
    let hit = result
        .hits
        .iter()
        .find(|h| h.key_offset == key_offset && h.mode == memhunt_core::Mode::Ctr)
        .expect("expected CTR hit at planted key");
    assert_eq!(hit.algo, "aes-128");
    assert_eq!(
        hit.nonce_hex.as_deref(),
        Some(hex::encode(CTR_COUNTER).as_str())
    );
    assert_eq!(hit.padding, None);
    assert_eq!(
        hit.plaintext_utf8.as_deref(),
        Some(std::str::from_utf8(PLAINTEXT).unwrap())
    );
}

#[test]
fn end_to_end_gcm_hit_with_tag() {
    let key_offset = 30_100;
    let dump = dump_with_key(&KEY256, key_offset);
    let (ciphertext, tag) = encrypt_gcm_256(PLAINTEXT, GCM_AAD);
    let config = ScanConfig {
        ciphers: vec![CipherChoice::Aes256],
        mode: CipherMode::Gcm,
        nonce: Some(GCM_NONCE.to_vec()),
        tag: Some(tag.to_vec()),
        aad: Some(GCM_AAD.to_vec()),
        ..ScanConfig::default()
    };

    let result = scan(&dump, &ciphertext, &Vec::new(), &config).unwrap();
    let hit = result
        .hits
        .iter()
        .find(|h| h.key_offset == key_offset && h.mode == memhunt_core::Mode::Gcm)
        .expect("expected GCM hit at planted key");
    assert_eq!(hit.algo, "aes-256");
    assert_eq!(hit.matched_by, "gcm-tag");
    assert_eq!(hit.confidence, memhunt_core::Confidence::High);
    assert_eq!(
        hit.nonce_hex.as_deref(),
        Some(hex::encode(GCM_NONCE).as_str())
    );
    assert_eq!(hit.padding, None);
    assert_eq!(
        hit.plaintext_utf8.as_deref(),
        Some(std::str::from_utf8(PLAINTEXT).unwrap())
    );
}

#[test]
fn end_to_end_gcm_hit_without_tag_uses_oracle() {
    let key_offset = 30_200;
    let dump = dump_with_key(&KEY, key_offset);
    let (ciphertext, _) = encrypt_gcm_128(PLAINTEXT);
    let config = ScanConfig {
        ciphers: vec![CipherChoice::Aes128],
        mode: CipherMode::Gcm,
        nonce: Some(GCM_NONCE.to_vec()),
        ..ScanConfig::default()
    };

    let result = scan(&dump, &ciphertext, &oracles(), &config).unwrap();
    let hit = result
        .hits
        .iter()
        .find(|h| h.key_offset == key_offset && h.mode == memhunt_core::Mode::Gcm)
        .expect("expected GCM oracle hit at planted key");
    assert_eq!(hit.matched_by, "json");
    assert_eq!(hit.confidence, memhunt_core::Confidence::High);
    assert_eq!(hit.padding, None);
    assert_eq!(
        hit.plaintext_utf8.as_deref(),
        Some(std::str::from_utf8(PLAINTEXT).unwrap())
    );
}

#[test]
fn gcm_random_data_with_tag_yields_no_hits() {
    let dump = make_dump_size(4096);
    let ciphertext = [0x77u8; 67];
    let tag = [0x88u8; 16];
    let config = ScanConfig {
        ciphers: vec![CipherChoice::Aes128],
        mode: CipherMode::Gcm,
        nonce: Some(GCM_NONCE.to_vec()),
        tag: Some(tag.to_vec()),
        ..ScanConfig::default()
    };

    let result = scan(&dump, &ciphertext, &Vec::new(), &config).unwrap();
    assert!(result.hits.is_empty(), "unexpected hits: {:?}", result.hits);
}
