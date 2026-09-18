//! Version-bridging block-cipher adapter.
//!
//! The RustCrypto ecosystem is mid-migration: `aes 0.8` sits on `cipher 0.4`
//! (generic-array) while `des 0.9`/`sm4 0.6` sit on `cipher 0.5`
//! (hybrid-array). Their `KeyInit`/`BlockDecrypt` traits are incompatible, so
//! memhunt-core defines its own minimal [`BlockCipher`] trait and implements it
//! once per (crate, version) pair. The engine only ever sees this trait, so
//! new ciphers — whatever array ecosystem they live in — plug in with one impl.

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};

/// A block cipher that can be keyed from raw bytes and decrypt single blocks,
/// independent of which `cipher` crate version it originates from.
pub trait BlockCipher: Sync + Send {
    /// Human-readable algorithm id (e.g. `aes-128`, `des`, `sm4`).
    fn algo(&self) -> &'static str;
    /// Key length in bytes.
    fn key_len(&self) -> usize;
    /// Block length in bytes.
    fn block_len(&self) -> usize;
    /// Re-key with `key` (exactly `key_len` bytes) and decrypt `block`
    /// in place. Returns false when the key is rejected.
    fn decrypt_with_key(&self, key: &[u8], block: &mut [u8]) -> bool;
    /// Re-key with `key` (exactly `key_len` bytes) and encrypt `block`
    /// in place. Returns false when the key is rejected.
    fn encrypt_with_key(&self, key: &[u8], block: &mut [u8]) -> bool;
}

/// Cipher 0.4 family (`aes 0.8`): 16-byte blocks, GenericArray-based.
pub struct AesAdapter<C> {
    algo: &'static str,
    key_len: usize,
    _phantom: std::marker::PhantomData<C>,
}

impl<C> AesAdapter<C> {
    pub fn new(algo: &'static str, key_len: usize) -> Self {
        Self {
            algo,
            key_len,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<C: KeyInit + BlockDecrypt + BlockEncrypt + Sync + Send> BlockCipher for AesAdapter<C> {
    fn algo(&self) -> &'static str {
        self.algo
    }
    fn key_len(&self) -> usize {
        self.key_len
    }
    fn block_len(&self) -> usize {
        16 // AES block size is always 16
    }
    fn decrypt_with_key(&self, key: &[u8], block: &mut [u8]) -> bool {
        let Ok(cipher) = C::new_from_slice(key) else {
            return false;
        };
        let Some(b) = block.get_mut(..16) else {
            return false;
        };
        cipher.decrypt_block(GenericArray::from_mut_slice(b));
        true
    }

    fn encrypt_with_key(&self, key: &[u8], block: &mut [u8]) -> bool {
        let Ok(cipher) = C::new_from_slice(key) else {
            return false;
        };
        let Some(b) = block.get_mut(..16) else {
            return false;
        };
        cipher.encrypt_block(GenericArray::from_mut_slice(b));
        true
    }
}

/// AES-128 adapter.
pub fn aes128() -> AesAdapter<aes::Aes128> {
    AesAdapter::new("aes-128", 16)
}
/// AES-192 adapter.
pub fn aes192() -> AesAdapter<aes::Aes192> {
    AesAdapter::new("aes-192", 24)
}
/// AES-256 adapter.
pub fn aes256() -> AesAdapter<aes::Aes256> {
    AesAdapter::new("aes-256", 32)
}

/// Cipher 0.5 family (`des 0.9`, `sm4 0.6`): hybrid-array-based.
pub struct Cipher05Adapter<C> {
    algo: &'static str,
    key_len: usize,
    block_len: usize,
    _phantom: std::marker::PhantomData<C>,
}

impl<C> Cipher05Adapter<C> {
    pub fn new(algo: &'static str, key_len: usize, block_len: usize) -> Self {
        Self {
            algo,
            key_len,
            block_len,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<C> BlockCipher for Cipher05Adapter<C>
where
    C: sm4::cipher::KeyInit
        + sm4::cipher::BlockCipherDecrypt
        + sm4::cipher::BlockCipherEncrypt
        + Sync
        + Send,
{
    fn algo(&self) -> &'static str {
        self.algo
    }
    fn key_len(&self) -> usize {
        self.key_len
    }
    fn block_len(&self) -> usize {
        self.block_len
    }
    fn decrypt_with_key(&self, key: &[u8], block: &mut [u8]) -> bool {
        let Ok(cipher) = C::new_from_slice(key) else {
            return false;
        };
        let Some(b) = block.get_mut(..self.block_len) else {
            return false;
        };
        // Zero-copy: borrow the block bytes as an Array view, decrypt in place.
        let Ok(buf) = <&mut sm4::cipher::Array<u8, C::BlockSize>>::try_from(b) else {
            return false;
        };
        cipher.decrypt_block(buf);
        true
    }

    fn encrypt_with_key(&self, key: &[u8], block: &mut [u8]) -> bool {
        let Ok(cipher) = C::new_from_slice(key) else {
            return false;
        };
        let Some(b) = block.get_mut(..self.block_len) else {
            return false;
        };
        let Ok(buf) = <&mut sm4::cipher::Array<u8, C::BlockSize>>::try_from(b) else {
            return false;
        };
        cipher.encrypt_block(buf);
        true
    }
}

/// DES (single): 8-byte key, 8-byte block.
pub fn des() -> Cipher05Adapter<des::Des> {
    Cipher05Adapter::new("des", 8, 8)
}
/// 3DES-EDE3: 24-byte key, 8-byte block.
pub fn tdes_ede3() -> Cipher05Adapter<des::TdesEde3> {
    Cipher05Adapter::new("3des-ede3", 24, 8)
}
/// SM4 (国密): 16-byte key, 16-byte block.
pub fn sm4() -> Cipher05Adapter<sm4::Sm4> {
    Cipher05Adapter::new("sm4", 16, 16)
}

/// A pure stream cipher (no block structure): keyed keystream generation.
/// ChaCha20 (IETF) and XChaCha20 both have 32-byte keys; the "block" is a
/// 64-byte keystream chunk, but for hunting purposes only the keystream
/// XOR matters, so `block_len` is unused by the engine's stream path.
pub trait StreamCipherAdapter: Sync + Send {
    fn algo(&self) -> &'static str;
    fn key_len(&self) -> usize;
    fn nonce_len(&self) -> usize;
    /// XOR `data` with the keystream generated from (key, nonce).
    fn xor_keystream(&self, key: &[u8], nonce: &[u8], data: &mut [u8]) -> bool;
}

/// ChaCha20 (IETF, 12-byte nonce) keystream adapter.
pub fn chacha20() -> ChaChaAdapter {
    ChaChaAdapter {
        algo: "chacha20",
        nonce_len: 12,
    }
}

/// XChaCha20 (24-byte nonce) keystream adapter.
pub fn xchacha20() -> ChaChaAdapter {
    ChaChaAdapter {
        algo: "xchacha20",
        nonce_len: 24,
    }
}

pub struct ChaChaAdapter {
    algo: &'static str,
    nonce_len: usize,
}

impl StreamCipherAdapter for ChaChaAdapter {
    fn algo(&self) -> &'static str {
        self.algo
    }
    fn key_len(&self) -> usize {
        32
    }
    fn nonce_len(&self) -> usize {
        self.nonce_len
    }
    fn xor_keystream(&self, key: &[u8], nonce: &[u8], data: &mut [u8]) -> bool {
        use chacha20::cipher::StreamCipher;
        if key.len() != 32 || nonce.len() != self.nonce_len {
            return false;
        }
        // ChaCha20 and XChaCha20 are distinct concrete types (`.new()`
        // returns different types), so branch explicitly and apply in place.
        match self.nonce_len {
            12 => {
                use chacha20::cipher::KeyIvInit;
                let Ok(n) = chacha20::Nonce::try_from(nonce) else {
                    return false;
                };
                let Ok(mut c) = chacha20::ChaCha20::new_from_slices(key, n.as_ref()) else {
                    return false;
                };
                c.apply_keystream(data);
            }
            24 => {
                use chacha20::cipher::KeyIvInit;
                let Ok(n) = chacha20::XNonce::try_from(nonce) else {
                    return false;
                };
                let Ok(mut c) = chacha20::XChaCha20::new_from_slices(key, n.as_ref()) else {
                    return false;
                };
                c.apply_keystream(data);
            }
            _ => return false,
        }
        true
    }
}
