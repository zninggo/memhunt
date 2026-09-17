//! CLI-level tests for the exit-code contract (handover bug 1):
//! `0` hit found, `1` no hit, `2` error.
//!
//! These spawn the built binary (`CARGO_BIN_EXE_memhunt`) end-to-end so the
//! documented exit codes are enforced against the real CLI, not just the lib.
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use std::process::Command;

const KEY: [u8; 16] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];
const PLAINTEXT: &[u8] = b"hunt-the-key!!!!";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_memhunt")
}

/// Plant `KEY` in a deterministic small dump and return a temp path + ECB
/// ciphertext of PLAINTEXT (openssl-free, so tests run anywhere).
fn make_fixture() -> (std::path::PathBuf, String) {
    let mut dump = vec![0u8; 4096];
    dump[2048..2048 + 16].copy_from_slice(&KEY);
    let fixt_dir = std::env::temp_dir().join(format!("memhunt_clitest_{}", std::process::id()));
    std::fs::create_dir_all(&fixt_dir).unwrap();
    let dump_path = fixt_dir.join("dump.bin");
    std::fs::write(&dump_path, &dump).unwrap();

    let mut block: [u8; 16] = PLAINTEXT.try_into().unwrap();
    let cipher = aes::Aes128::new_from_slice(&KEY).unwrap();
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
    (dump_path, hex::encode(block))
}

fn run(dump: &str, ct: &str, oracle: &str) -> std::process::Output {
    Command::new(bin())
        .args([
            "scan", dump, "--oracle", oracle, "--target", ct, "--cipher", "aes-128",
        ])
        .output()
        .unwrap()
}

#[test]
fn exit_code_0_on_hit() {
    let (dump, ct) = make_fixture();
    let out = run(dump.to_str().unwrap(), &ct, "utf8");
    assert_eq!(out.status.code(), Some(0), "hit must exit 0");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("aes-128"),
        "output should name the algo"
    );
    let _ = std::fs::remove_dir_all(dump.parent().unwrap());
}

#[test]
fn exit_code_1_on_no_hit() {
    let (dump, _) = make_fixture();
    // Ciphertext encrypted with a key that is NOT planted => no hit.
    let other_ct = hex::encode([0xabu8; 16]);
    let out = run(dump.to_str().unwrap(), &other_ct, "utf8");
    assert_eq!(out.status.code(), Some(1), "no-hit must exit 1");
    let _ = std::fs::remove_dir_all(dump.parent().unwrap());
}

#[test]
fn exit_code_2_on_missing_dump() {
    let out = run(
        "/definitely/not/a/dump.bin",
        &hex::encode([0u8; 16]),
        "utf8",
    );
    assert_eq!(out.status.code(), Some(2), "missing dump must exit 2");
}

#[test]
fn exit_code_2_on_bad_encoding() {
    // Hex-valid-looking target that fails block alignment => error.
    let out = run(
        "/tmp/any.bin",
        &"00".repeat(15), // 15 bytes, not a multiple of 16
        "utf8",
    );
    assert_eq!(out.status.code(), Some(2), "malformed target must exit 2");
}
