//! memhunt-core: oracle-driven AES key hunting over memory dumps.
//!
//! Given a process/core dump and a ciphertext, slide a window over every byte
//! offset, try each window as an AES key, and keep candidates whose decrypted
//! head validates against pluggable oracles (utf8 / json / known-plaintext).
//! CBC is verified through blocks 1..n, which do not depend on the IV; the IV
//! itself is located in a second pass over the dump.

pub mod engine;
pub mod oracle;
pub mod report;

pub use engine::{scan, ScanConfig};
pub use oracle::{best_match, JsonOracle, KnownPlaintextOracle, Oracle, Utf8Oracle};
pub use report::{Confidence, Hit, Mode, ScanResult, ScanStats};
