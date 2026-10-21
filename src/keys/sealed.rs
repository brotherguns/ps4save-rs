//! Sealed key (iv) parse / verify / encrypt / decrypt.

use std::path::Path;

use crate::crypto::{aes_decrypt_cbc_cts, aes_encrypt_cbc_cts, hmac_sha256};
use crate::error::{Error, Result};
use crate::keys::common::CommonKeys;
use crate::keys::sizes::*;

/// On-disk sealed key blob (`pfsSKKey`), 0x60 bytes.
#[derive(Debug, Clone)]
pub struct SealedKey {
    pub version: u16,
    pub iv: [u8; 16],
    pub data: [u8; MKEY_SIZE],
    pub hash: [u8; HASH_SIZE],
}

impl SealedKey {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < SEALED_KEY_SIZE {
            return Err(Error::InvalidLength {
                what: "sealed key",
                expected: SEALED_KEY_SIZE,
                got: buf.len(),
            });
        }
        if &buf[0..8] != SEALED_KEY_MAGIC {
            return Err(Error::InvalidSealedKeyMagic);
        }
        let version = u16::from_le_bytes([buf[8], buf[9]]);
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&buf[0x10..0x20]);
        let mut data = [0u8; MKEY_SIZE];
        data.copy_from_slice(&buf[0x20..0x40]);
        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(&buf[0x40..0x60]);
        Ok(Self {
            version,
            iv,
            data,
            hash,
        })
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let buf = std::fs::read(path)?;
        Self::parse(&buf)
    }

    pub fn to_bytes(&self) -> [u8; SEALED_KEY_SIZE] {
        let mut out = [0u8; SEALED_KEY_SIZE];
        out[0..8].copy_from_slice(SEALED_KEY_MAGIC);
        out[8..10].copy_from_slice(&self.version.to_le_bytes());
        // bytes 0x0A..0x10 are padding/reserved (zero)
        out[0x10..0x20].copy_from_slice(&self.iv);
        out[0x20..0x40].copy_from_slice(&self.data);
        out[0x40..0x60].copy_from_slice(&self.hash);
        out
    }
}

/// Decrypt sealed key → mkey (32 bytes).
pub fn decrypt_sealed_key(common: &CommonKeys, key: &SealedKey) -> Result<[u8; MKEY_SIZE]> {
    let enc_key = common
        .sealed_enc_key(key.version)
        .ok_or_else(|| Error::MissingKey(format!("sealed_key_enc_key_{}", key.version)))?;
    let sign_key = common
        .sealed_sign_key(key.version)
        .ok_or_else(|| Error::MissingKey(format!("sealed_key_sign_key_{}", key.version)))?;

    let cover = key.to_bytes();
    let computed = hmac_sha256(sign_key, &cover[..SEALED_KEY_COVER_SIZE]);
    if computed != key.hash {
        return Err(Error::InvalidSealedKeyDigest);
    }

    let mut iv = key.iv;
    let mut mkey = [0u8; MKEY_SIZE];
    aes_decrypt_cbc_cts(enc_key, Some(&mut iv), &key.data, &mut mkey)?;
    Ok(mkey)
}

/// Build a sealed key from plaintext mkey (for encryption / re-wrapping).
pub fn encrypt_sealed_key(
    common: &CommonKeys,
    version: u16,
    iv: [u8; 16],
    mkey: &[u8; MKEY_SIZE],
) -> Result<SealedKey> {
    if version == 0 {
        return Err(Error::UnsupportedVersion(version));
    }
    let enc_key = common
        .sealed_enc_key(version)
        .ok_or_else(|| Error::MissingKey(format!("sealed_key_enc_key_{}", version)))?;
    let sign_key = common
        .sealed_sign_key(version)
        .ok_or_else(|| Error::MissingKey(format!("sealed_key_sign_key_{}", version)))?;

    let mut iv_mut = iv;
    let mut data = [0u8; MKEY_SIZE];
    aes_encrypt_cbc_cts(enc_key, Some(&mut iv_mut), mkey, &mut data)?;

    let mut key = SealedKey {
        version,
        iv,
        data,
        hash: [0u8; HASH_SIZE],
    };
    let cover = key.to_bytes();
    key.hash = hmac_sha256(sign_key, &cover[..SEALED_KEY_COVER_SIZE]);
    Ok(key)
}
