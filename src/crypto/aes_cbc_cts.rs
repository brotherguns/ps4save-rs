//! AES-CBC with ciphertext stealing, matching pkg_pfs_tool's mbedtls-based CTS.

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};

use crate::error::{Error, Result};

fn crypt_cbc_enc(key: &[u8], iv: &mut [u8; 16], data: &mut [u8]) -> Result<()> {
    match key.len() {
        16 => cbc_enc_128(key.try_into().unwrap(), iv, data),
        24 => cbc_enc_192(key.try_into().unwrap(), iv, data),
        32 => cbc_enc_256(key.try_into().unwrap(), iv, data),
        _ => Err(Error::Crypto(format!(
            "unsupported AES key size {}",
            key.len()
        ))),
    }
}

fn crypt_cbc_dec(key: &[u8], iv: &mut [u8; 16], data: &mut [u8]) -> Result<()> {
    match key.len() {
        16 => cbc_dec_128(key.try_into().unwrap(), iv, data),
        24 => cbc_dec_192(key.try_into().unwrap(), iv, data),
        32 => cbc_dec_256(key.try_into().unwrap(), iv, data),
        _ => Err(Error::Crypto(format!(
            "unsupported AES key size {}",
            key.len()
        ))),
    }
}

fn crypt_ecb_enc(key: &[u8], block: &mut [u8; 16]) -> Result<()> {
    match key.len() {
        16 => ecb_enc_128(key.try_into().unwrap(), block),
        24 => ecb_enc_192(key.try_into().unwrap(), block),
        32 => ecb_enc_256(key.try_into().unwrap(), block),
        _ => Err(Error::Crypto(format!(
            "unsupported AES key size {}",
            key.len()
        ))),
    }
}

macro_rules! impl_cbc_ecb {
    ($enc_cbc:ident, $dec_cbc:ident, $enc_ecb:ident, $Cipher:ty, $key_ty:ty) => {
        fn $enc_cbc(key: &$key_ty, iv: &mut [u8; 16], data: &mut [u8]) -> Result<()> {
            let cipher = <$Cipher>::new_from_slice(key)
                .map_err(|_| Error::Crypto("AES setkey failed".into()))?;
            let mut prev = *iv;
            for chunk in data.chunks_exact_mut(16) {
                for (b, p) in chunk.iter_mut().zip(prev.iter()) {
                    *b ^= *p;
                }
                let mut block = aes::Block::clone_from_slice(chunk);
                cipher.encrypt_block(&mut block);
                chunk.copy_from_slice(block.as_slice());
                prev.copy_from_slice(chunk);
            }
            *iv = prev;
            Ok(())
        }

        fn $dec_cbc(key: &$key_ty, iv: &mut [u8; 16], data: &mut [u8]) -> Result<()> {
            let cipher = <$Cipher>::new_from_slice(key)
                .map_err(|_| Error::Crypto("AES setkey failed".into()))?;
            let mut prev = *iv;
            for chunk in data.chunks_exact_mut(16) {
                let ciphertext: [u8; 16] = chunk.try_into().unwrap();
                let mut block = aes::Block::clone_from_slice(chunk);
                cipher.decrypt_block(&mut block);
                for (b, p) in block.iter_mut().zip(prev.iter()) {
                    *b ^= *p;
                }
                chunk.copy_from_slice(block.as_slice());
                prev = ciphertext;
            }
            *iv = prev;
            Ok(())
        }

        fn $enc_ecb(key: &$key_ty, block: &mut [u8; 16]) -> Result<()> {
            let cipher = <$Cipher>::new_from_slice(key)
                .map_err(|_| Error::Crypto("AES setkey failed".into()))?;
            let mut b = aes::Block::from(*block);
            cipher.encrypt_block(&mut b);
            block.copy_from_slice(b.as_slice());
            Ok(())
        }
    };
}

impl_cbc_ecb!(cbc_enc_128, cbc_dec_128, ecb_enc_128, Aes128, [u8; 16]);
impl_cbc_ecb!(cbc_enc_192, cbc_dec_192, ecb_enc_192, Aes192, [u8; 24]);
impl_cbc_ecb!(cbc_enc_256, cbc_dec_256, ecb_enc_256, Aes256, [u8; 32]);

/// Encrypt with AES-CBC-CTS. If `iv` is `None`, a zero IV is used (and not written back).
pub fn aes_encrypt_cbc_cts(
    key: &[u8],
    iv: Option<&mut [u8; 16]>,
    input: &[u8],
    output: &mut [u8],
) -> Result<()> {
    if input.is_empty() || output.len() != input.len() {
        return Err(Error::Crypto(
            "empty or mismatched AES-CBC-CTS buffers".into(),
        ));
    }

    const BS: usize = 16;
    let mut tmp = [0u8; BS];
    if let Some(iv) = iv.as_ref() {
        tmp.copy_from_slice(*iv);
    }

    let data_size = input.len();
    output.copy_from_slice(input);

    if data_size >= BS {
        let data_size_left = data_size - BS;
        let data_size_trunc = data_size_left / BS * BS + BS;
        crypt_cbc_enc(key, &mut tmp, &mut output[..data_size_trunc])?;

        let rem = data_size_left & (BS - 1);
        if rem != 0 {
            crypt_ecb_enc(key, &mut tmp)?;
            for i in 0..rem {
                output[data_size_trunc + i] = input[data_size_trunc + i] ^ tmp[i];
            }
        }
    } else {
        crypt_ecb_enc(key, &mut tmp)?;
        for i in 0..data_size {
            output[i] = input[i] ^ tmp[i];
        }
    }

    if let Some(iv) = iv {
        *iv = tmp;
    }
    Ok(())
}

/// Decrypt with AES-CBC-CTS. If `iv` is `None`, a zero IV is used (and not written back).
pub fn aes_decrypt_cbc_cts(
    key: &[u8],
    iv: Option<&mut [u8; 16]>,
    input: &[u8],
    output: &mut [u8],
) -> Result<()> {
    if input.is_empty() || output.len() != input.len() {
        return Err(Error::Crypto(
            "empty or mismatched AES-CBC-CTS buffers".into(),
        ));
    }

    const BS: usize = 16;
    let mut tmp = [0u8; BS];
    if let Some(iv) = iv.as_ref() {
        tmp.copy_from_slice(*iv);
    }

    let data_size = input.len();
    output.copy_from_slice(input);

    if data_size >= BS {
        let data_size_left = data_size - BS;
        let data_size_trunc = data_size_left / BS * BS + BS;
        crypt_cbc_dec(key, &mut tmp, &mut output[..data_size_trunc])?;

        let rem = data_size_left & (BS - 1);
        if rem != 0 {
            crypt_ecb_enc(key, &mut tmp)?;
            for i in 0..rem {
                output[data_size_trunc + i] = input[data_size_trunc + i] ^ tmp[i];
            }
        }
    } else {
        crypt_ecb_enc(key, &mut tmp)?;
        for i in 0..data_size {
            output[i] = input[i] ^ tmp[i];
        }
    }

    if let Some(iv) = iv {
        *iv = tmp;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_aligned() {
        let key = [0u8; 16];
        let iv = [1u8; 16];
        let plain = [0xAAu8; 32];
        let mut enc = [0u8; 32];
        let mut dec = [0u8; 32];
        let mut iv_enc = iv;
        aes_encrypt_cbc_cts(&key, Some(&mut iv_enc), &plain, &mut enc).unwrap();
        let mut iv_dec = iv;
        aes_decrypt_cbc_cts(&key, Some(&mut iv_dec), &enc, &mut dec).unwrap();
        assert_eq!(plain, dec);
    }

    #[test]
    fn roundtrip_unaligned() {
        let key = [0x11u8; 16];
        let plain = [0x55u8; 20];
        let mut enc = [0u8; 20];
        let mut dec = [0u8; 20];
        aes_encrypt_cbc_cts(&key, None, &plain, &mut enc).unwrap();
        aes_decrypt_cbc_cts(&key, None, &enc, &mut dec).unwrap();
        assert_eq!(plain, dec);
    }
}
