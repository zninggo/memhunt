use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use memhunt_core::{scan, JsonOracle, Oracle, ScanConfig, Utf8Oracle};
use std::time::Instant;

const KEY: [u8; 16] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];
const IV: [u8; 16] = [
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
];
const PLAINTEXT: &[u8] = b"{\"user\":\"admin\",\"role\":\"superuser\",\"exp\":1750000000}";
const KEY_OFFSET: usize = 600_000;
const IV_OFFSET: usize = 600_100;
const DUMP_SIZE: usize = 1024 * 1024;

fn oracles() -> Vec<Box<dyn Oracle>> {
    vec![Box::new(Utf8Oracle), Box::new(JsonOracle)]
}

/// Deterministic pseudo-random dump filler (xorshift64*).
fn make_dump() -> Vec<u8> {
    let mut state = 0x9E3779B97F4A7C15u64;
    let mut dump = Vec::with_capacity(DUMP_SIZE);
    while dump.len() < DUMP_SIZE {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let bytes = state.wrapping_mul(0x2545F4914F6CDD1D).to_le_bytes();
        dump.extend_from_slice(&bytes);
    }
    dump.truncate(DUMP_SIZE);
    dump
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
    let mut dump = make_dump();
    dump[KEY_OFFSET..KEY_OFFSET + 16].copy_from_slice(&KEY);
    dump[IV_OFFSET..IV_OFFSET + 16].copy_from_slice(&IV);
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
        fixed_iv: Some(IV),
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

#[test]
fn throughput_smoke_1mib() {
    let dump = dump_with_key_and_iv();
    let ciphertext = encrypt_ecb(PLAINTEXT);
    let start = Instant::now();
    let result = scan(&dump, &ciphertext, &oracles(), &ScanConfig::default()).unwrap();
    let secs = start.elapsed().as_secs_f64();
    assert!(!result.hits.is_empty());
    eprintln!(
        "throughput: {} MiB scanned in {:.2}s ({:.1} MiB/s)",
        DUMP_SIZE as f64 / (1024.0 * 1024.0),
        secs,
        DUMP_SIZE as f64 / (1024.0 * 1024.0) / secs
    );
}
