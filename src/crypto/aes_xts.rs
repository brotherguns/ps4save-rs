//! AES-XTS sector cipher matching pkg_pfs_tool encdec_device.

use aes::Aes128;
use aes::cipher::KeyInit;
use xts_mode::{Xts128, get_tweak_default};

use crate::error::{Error, Result};

/// PFS encdec sector size (2^12).
pub const PFS_ENCDEC_SECTOR_SIZE: usize = 0x1000;

/// AES-XTS device used for PFS sector encrypt/decrypt.
///
/// Key material is concatenated as `data_key || tweak_key` (mbedtls order),
/// which means cipher1 = data_key and cipher2 = tweak_key.
pub struct EncDecDevice {
    cipher: Xts128<Aes128>,
    sector_size: usize,
}

impl EncDecDevice {
    pub fn new(tweak_key: &[u8; 16], data_key: &[u8; 16], sector_size: usize) -> Result<Self> {
        if !sector_size.is_power_of_two() || sector_size == 0 {
            return Err(Error::Crypto(
                "sector size must be a non-zero power of two".into(),
            ));
        }

        let cipher_1 = Aes128::new_from_slice(data_key)
            .map_err(|_| Error::Crypto("AES-XTS data key rejected".into()))?;
        let cipher_2 = Aes128::new_from_slice(tweak_key)
            .map_err(|_| Error::Crypto("AES-XTS tweak key rejected".into()))?;

        Ok(Self {
            cipher: Xts128::new(cipher_1, cipher_2),
            sector_size,
        })
    }

    pub fn sector_size(&self) -> usize {
        self.sector_size
    }

    pub fn decrypt(&self, input: &[u8], output: &mut [u8], start_sector: u64) -> Result<()> {
        self.process(input, output, start_sector, false)
    }

    pub fn encrypt(&self, input: &[u8], output: &mut [u8], start_sector: u64) -> Result<()> {
        self.process(input, output, start_sector, true)
    }

    pub fn decrypt_inplace(&self, buf: &mut [u8], start_sector: u64) -> Result<()> {
        self.process_inplace(buf, start_sector, false)
    }

    pub fn encrypt_inplace(&self, buf: &mut [u8], start_sector: u64) -> Result<()> {
        self.process_inplace(buf, start_sector, true)
    }

    fn process_inplace(&self, buf: &mut [u8], start_sector: u64, encrypt: bool) -> Result<()> {
        let sector_size = self.sector_size;
        let num_full = buf.len() / sector_size;
        let rem = buf.len() % sector_size;

        for i in 0..num_full {
            let sector = start_sector + i as u64;
            let off = i * sector_size;
            let dst = &mut buf[off..off + sector_size];
            if encrypt {
                self.cipher
                    .encrypt_area(dst, sector_size, sector as u128, get_tweak_default);
            } else {
                self.cipher
                    .decrypt_area(dst, sector_size, sector as u128, get_tweak_default);
            }
        }

        if rem != 0 {
            let sector = start_sector + num_full as u64;
            let off = num_full * sector_size;
            let mut tmp = buf[off..].to_vec();
            tmp.resize(sector_size, 0);
            if encrypt {
                self.cipher
                    .encrypt_area(&mut tmp, sector_size, sector as u128, get_tweak_default);
            } else {
                self.cipher
                    .decrypt_area(&mut tmp, sector_size, sector as u128, get_tweak_default);
            }
            buf[off..].copy_from_slice(&tmp[..rem]);
        }

        Ok(())
    }

    fn process(
        &self,
        input: &[u8],
        output: &mut [u8],
        start_sector: u64,
        encrypt: bool,
    ) -> Result<()> {
        if output.len() != input.len() {
            return Err(Error::Crypto("encdec buffer size mismatch".into()));
        }

        let sector_size = self.sector_size;
        let num_full = input.len() / sector_size;
        let rem = input.len() % sector_size;

        for i in 0..num_full {
            let sector = start_sector + i as u64;
            let off = i * sector_size;
            let dst = &mut output[off..off + sector_size];
            dst.copy_from_slice(&input[off..off + sector_size]);
            if encrypt {
                self.cipher
                    .encrypt_area(dst, sector_size, sector as u128, get_tweak_default);
            } else {
                self.cipher
                    .decrypt_area(dst, sector_size, sector as u128, get_tweak_default);
            }
        }

        if rem != 0 {
            let sector = start_sector + num_full as u64;
            let off = num_full * sector_size;
            let mut buf = vec![0u8; sector_size];
            buf[..rem].copy_from_slice(&input[off..]);
            if encrypt {
                self.cipher
                    .encrypt_area(&mut buf, sector_size, sector as u128, get_tweak_default);
            } else {
                self.cipher
                    .decrypt_area(&mut buf, sector_size, sector as u128, get_tweak_default);
            }
            output[off..].copy_from_slice(&buf[..rem]);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sector() {
        let tweak = [0x01u8; 16];
        let data = [0x02u8; 16];
        let dev = EncDecDevice::new(&tweak, &data, 0x1000).unwrap();
        let plain = vec![0xABu8; 0x1000];
        let mut enc = vec![0u8; 0x1000];
        let mut dec = vec![0u8; 0x1000];
        dev.encrypt(&plain, &mut enc, 0).unwrap();
        assert_ne!(plain, enc);
        dev.decrypt(&enc, &mut dec, 0).unwrap();
        assert_eq!(plain, dec);
    }
}
