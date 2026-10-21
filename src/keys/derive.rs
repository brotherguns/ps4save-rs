//! Key derivation matching pkg_pfs_tool keymgr.c.

use crate::crypto::{aes_decrypt_cbc_cts, hmac_sha256, sha256};
use crate::error::{Error, Result};
use crate::keys::sizes::*;
use crate::keys::title::TitleKeyset;

/// Passcode → image_key (index 1), matching `gen_specific_key` / `gen_image_key`.
pub fn gen_image_key(content_id: &str, passcode: &[u8; PASSCODE_SIZE]) -> [u8; HASH_SIZE] {
    gen_specific_key(content_id, passcode, 1)
}

fn gen_specific_key(
    content_id: &str,
    passcode: &[u8; PASSCODE_SIZE],
    index: u32,
) -> [u8; HASH_SIZE] {
    let mut d2 = [0u8; 0x30];
    let mut d3 = [0u8; 2 * HASH_SIZE + PASSCODE_SIZE];

    let d1 = index.to_be_bytes();
    d3[..HASH_SIZE].copy_from_slice(&sha256(&d1));

    let cid_bytes = content_id.as_bytes();
    let copy_len = CONTENT_ID_SIZE.min(cid_bytes.len());
    d2[..copy_len].copy_from_slice(&cid_bytes[..copy_len]);
    d3[HASH_SIZE..2 * HASH_SIZE].copy_from_slice(&sha256(&d2));

    d3[2 * HASH_SIZE..].copy_from_slice(passcode);
    sha256(&d3)
}

/// HMAC-SHA256(image_key, le32(index) || seed).
pub fn gen_crypto_key(
    image_key: &[u8; HASH_SIZE],
    seed: &[u8; SEED_SIZE],
    index: u32,
) -> [u8; HASH_SIZE] {
    let mut d = [0u8; 4 + SEED_SIZE];
    d[..4].copy_from_slice(&index.to_le_bytes());
    d[4..].copy_from_slice(seed);
    hmac_sha256(image_key, &d)
}

pub fn gen_encryption_key(
    image_key: &[u8; HASH_SIZE],
    seed: &[u8; SEED_SIZE],
) -> [u8; HASH_SIZE] {
    gen_crypto_key(image_key, seed, 1)
}

pub fn gen_signing_key(image_key: &[u8; HASH_SIZE], seed: &[u8; SEED_SIZE]) -> [u8; HASH_SIZE] {
    gen_crypto_key(image_key, seed, 2)
}

/// Derive enc/sig keys for a PKG/title PFS from passcode or image_key.
///
/// If final keys are already present and no passcode/image_key is set, succeeds as a no-op.
pub fn derive_title_keys(
    keyset: &mut TitleKeyset,
    content_id: Option<&str>,
    seed: &[u8; SEED_SIZE],
    use_new_algo: bool,
) -> Result<[u8; HASH_SIZE]> {
    let content_id = content_id.unwrap_or(keyset.content_id.as_str());

    if keyset.has_passcode() || keyset.has_image_key() {
        let image_key = if let Some(passcode) = keyset.passcode {
            let tmp = gen_image_key(content_id, &passcode);
            let image_key = if use_new_algo {
                hmac_sha256(&tmp, seed)
            } else {
                tmp
            };
            keyset.image_key = Some(image_key);
            image_key
        } else {
            keyset
                .image_key
                .ok_or_else(|| Error::MissingKey("image_key".into()))?
        };

        let enc = gen_encryption_key(&image_key, seed);
        let mut tweak = [0u8; AES_KEY_SIZE];
        let mut data = [0u8; AES_KEY_SIZE];
        tweak.copy_from_slice(&enc[..AES_KEY_SIZE]);
        data.copy_from_slice(&enc[AES_KEY_SIZE..]);
        keyset.enc_tweak_key = Some(tweak);
        keyset.enc_data_key = Some(data);
        keyset.sig_hmac_key = Some(gen_signing_key(&image_key, seed));

        Ok(image_key)
    } else if keyset.has_encryption_key() && keyset.has_signing_key() {
        Ok(keyset.image_key.unwrap_or([0u8; HASH_SIZE]))
    } else {
        Err(Error::MissingKey(
            "passcode/image_key or final enc/sig keys".into(),
        ))
    }
}

/// Derive enc/sig keys for an SD/save PFS from mkey + sd content key.
pub fn derive_sd_keys(
    keyset: &mut TitleKeyset,
    content_key: &[u8; CONTENT_KEY_SIZE],
    seed: &[u8; SEED_SIZE],
) -> Result<()> {
    if let Some(mkey) = keyset.mkey {
        let mut image_key = [0u8; MKEY_SIZE];
        aes_decrypt_cbc_cts(content_key, None, &mkey, &mut image_key)?;

        // image_key is 32 bytes; gen_crypto_key expects HASH_SIZE (also 32).
        let mut ik = [0u8; HASH_SIZE];
        ik.copy_from_slice(&image_key);
        keyset.image_key = Some(ik);

        let enc = gen_encryption_key(&ik, seed);
        let mut tweak = [0u8; AES_KEY_SIZE];
        let mut data = [0u8; AES_KEY_SIZE];
        tweak.copy_from_slice(&enc[..AES_KEY_SIZE]);
        data.copy_from_slice(&enc[AES_KEY_SIZE..]);
        keyset.enc_tweak_key = Some(tweak);
        keyset.enc_data_key = Some(data);
        keyset.sig_hmac_key = Some(gen_signing_key(&ik, seed));
        Ok(())
    } else if keyset.has_encryption_key() && keyset.has_signing_key() {
        Ok(())
    } else {
        Err(Error::MissingKey("mkey or final enc/sig keys".into()))
    }
}

/// sc0_key = sha256(AES-CBC-CTS-decrypt(gdgp_content_key_obf_key, content_key_seed))[0..16]
pub fn gen_sc0_key(
    content_key_seed: &[u8; CONTENT_KEY_SIZE],
    gdgp_content_key_obf_key: &[u8; AES_KEY_SIZE],
) -> Result<[u8; SC0_KEY_SIZE]> {
    let mut d1 = *content_key_seed;
    let mut tmp = [0u8; CONTENT_KEY_SIZE];
    aes_decrypt_cbc_cts(gdgp_content_key_obf_key, None, &d1, &mut tmp)?;
    d1 = tmp;
    let hash = sha256(&d1);
    let mut sc0 = [0u8; SC0_KEY_SIZE];
    sc0.copy_from_slice(&hash[..SC0_KEY_SIZE]);
    Ok(sc0)
}
