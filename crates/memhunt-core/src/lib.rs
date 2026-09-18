//! memhunt-core: oracle-driven key hunting over memory dumps.
//!
//! Given a process/core dump and a ciphertext (or a digest), slide a window
//! over every byte offset, try each window as a key, and keep candidates whose
//! decryption validates against pluggable oracles (utf8 / json / known
//! plaintext / gzip / protobuf magic). CBC is verified through blocks 1..n,
//! which do not depend on the IV; the IV itself is located in a second pass.
//!
//! Cipher coverage: AES-128/192/256, DES, 3DES-EDE3, SM4 (block-cipher key
//! hunting); MD5/SHA-1/SHA-256/SM3 (preimage and HMAC-key hunting); AES key
//! schedule structure detection (no ciphertext required).

pub mod cipher_adapter;
pub mod engine;
pub mod hash_scan;
pub mod keysched;
pub mod oracle;
pub mod report;

pub use cipher_adapter::BlockCipher;
pub use engine::{scan, CipherChoice, CipherMode, CipherSelection, ScanConfig};
pub use hash_scan::{
    scan_hmac_keys, scan_preimages, HashAlgoSpec, HashScanConfig, HashScanResult, LengthRange,
};
pub use keysched::{scan_key_schedules, KeyScheduleHit, KeyScheduleResult};
pub use oracle::{
    best_match, GzipOracle, JsonOracle, KnownPlaintextOracle, Oracle, ProtobufOracle,
    Utf16LeOracle, Utf8Oracle,
};
pub use report::{Confidence, Hit, Mode, ScanResult, ScanStats};
