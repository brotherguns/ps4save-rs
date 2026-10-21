//! PFS (Sony Filesystem) support: header, dinode, block list, and directory walk.
//!
//! Ported from flatz's pkg_pfs_tool (pfs.c, pfs_block.c, pfs_dinode.c, pfs_io.c,
//! pfs_lookup.c, pfs_parsers.c).

mod block;
mod dir;
mod encrypt;
mod io;

pub mod header;

use std::fs::File;
use std::io::Read;

use crate::crypto::{EncDecDevice, hmac_sha256};
use crate::error::{Error, Result};
use crate::keys::sizes::*;
use crate::keys::{CommonKeys, TitleKeyset, decrypt_sealed_key, derive_sd_keys};

pub use block::check_cipher_block;
pub use dir::{PfsEntry, PfsEntryType};
pub use header::{
    PfsDinode, PfsDirEntry, PfsFormat, PfsHeader, PFS_DIRECT_BLOCK_MAX_COUNT,
    PFS_ENCDEC_SECTOR_SIZE, PFS_FS_MAGIC, PFS_HEADER_COVER_SIZE_FOR_ICV, PFS_HEADER_SIZE,
    PFS_MODE_CASE_INSENSITIVE_FLAG, PFS_MODE_ENCRYPTED_FLAG, PFS_MODE_SIGNED_FLAG,
    PFS_SD_HEADER_SIZE, entry_block_no,
};
pub use io::{PfsFile, align_up};
pub use encrypt::{EncryptOptions, EncryptStats, encrypt_dir, reauth_header_block};

pub const PFS_MODE_ENCRYPTED: u16 = 0x4;
pub const PFS_MODE_SIGNED: u16 = 0x1;

pub const PFS_FLAGS_PLAYGO: u32 = 1 << 0;
pub const PFS_FLAGS_CASE_SENSITIVE: u32 = 1 << 1;

/// Options controlling a `Pfs::open`.
#[derive(Debug, Clone, Default)]
pub struct PfsOpenOptions {
    pub case_sensitive: bool,
    pub skip_signature_check: bool,
    /// Open an already-decrypted image: ignore the header's encrypted/signed
    /// flags and do not build an encdec device.
    pub force_plaintext: bool,
    /// Open the backing file read-write (needed for in-place resign).
    pub read_write: bool,
}

/// An opened PFS filesystem backed by a single file.
pub struct Pfs {
    file: File,
    pub hdr: PfsHeader,
    pub format: PfsFormat,

    pub basic_block_size: usize,
    pub basic_block_size_shift: u32,
    pub basic_block_mask: u64,
    pub basic_block_qmask: u64,

    pub is_inner: bool,
    pub is_signed: bool,
    pub is_encrypted: bool,
    pub flags: u32,

    pub dinode_struct_size: usize,
    pub block_info_struct_size: usize,
    pub inodes_per_block: usize,
    pub indirect_ptrs_per_block: usize,
    pub indirect_ptrs_per_block_for_level: [i64; 5],

    pub super_root_dir_ino: u32,
    pub block_bitmap_ino: u32,
    pub ino_bitmap_ino: u32,
    pub user_root_dir_ino: u32,
    pub block_addr_table_ino: u32,
    pub flat_path_table_ino: u32,
    pub collision_resolver_ino: u32,

    encdec: Option<EncDecDevice>,
    pub sig_hmac_key: Option<[u8; HMAC_KEY_SIZE]>,
}

impl Pfs {
    /// Open a PFS image (pfs_alloc). `keyset` must already contain the
    /// encdec keys (and optionally the signing key).
    pub fn open(
        path: impl AsRef<std::path::Path>,
        keyset: &TitleKeyset,
        opts: &PfsOpenOptions,
    ) -> Result<Pfs> {
        let mut file = if opts.read_write {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)?
        } else {
            File::open(&path)?
        };
        let mut hdr_buf = [0u8; PFS_HEADER_SIZE];
        file.read_exact(&mut hdr_buf)?;
        let hdr = PfsHeader::parse(&hdr_buf)?;

        let is_signed = hdr.is_signed() && !opts.force_plaintext;
        let is_encrypted = hdr.is_encrypted() && !opts.force_plaintext;

        // Validate basic block size is a supported power of two.
        let basic_block_size = hdr.basic_block_size as usize;
        {
            let mut bb = header::PFS_MIN_BLOCK_SIZE;
            loop {
                if bb == basic_block_size {
                    break;
                }
                bb *= 2;
                if bb > header::PFS_MAX_BLOCK_SIZE {
                    return Err(Error::Message(format!(
                        "unsupported basic block size 0x{basic_block_size:X}"
                    )));
                }
            }
        }

        let format = PfsFormat::from_mode(hdr.mode);
        let dinode_struct_size = format.dinode_struct_size();
        let block_info_struct_size = format.block_info_struct_size();
        let indirect_ptrs_per_block = basic_block_size / block_info_struct_size;
        let inodes_per_block = basic_block_size / dinode_struct_size;

        let mut indirect_ptrs_per_block_for_level = [0i64; 5];
        let mut indirect_ptr_count = indirect_ptrs_per_block as i64;
        for slot in indirect_ptrs_per_block_for_level.iter_mut() {
            *slot = indirect_ptr_count;
            indirect_ptr_count *= indirect_ptrs_per_block as i64;
        }

        // Encdec device for encrypted images.
        let encdec = if is_encrypted {
            let tweak = keyset
                .enc_tweak_key
                .ok_or_else(|| Error::MissingKey("enc_tweak_key".into()))?;
            let data = keyset
                .enc_data_key
                .ok_or_else(|| Error::MissingKey("enc_data_key".into()))?;
            Some(EncDecDevice::new(&tweak, &data, PFS_ENCDEC_SECTOR_SIZE)?)
        } else {
            None
        };

        // Verify the header ICV when signed (HMAC over 0x380 cover + zeros).
        let sig_hmac_key = keyset.sig_hmac_key;
        if is_signed && !opts.skip_signature_check {
            if let Some(sig_key) = sig_hmac_key {
                let mut cover = [0u8; PFS_HEADER_SIZE];
                cover[..PFS_HEADER_COVER_SIZE_FOR_ICV]
                    .copy_from_slice(&hdr.raw[..PFS_HEADER_COVER_SIZE_FOR_ICV]);
                let hash = hmac_sha256(&sig_key, &cover);
                if hash != hdr.header_hash {
                    return Err(Error::Message("invalid header hash".into()));
                }
            }
        }

        let flags = if opts.case_sensitive || hdr.is_case_sensitive() {
            PFS_FLAGS_CASE_SENSITIVE
        } else {
            0
        };

        let basic_block_size_shift = ilog2(basic_block_size);
        let basic_block_mask = !(basic_block_size as u64 - 1);
        let basic_block_qmask = basic_block_size as u64 - 1;

        let mut pfs = Pfs {
            file,
            hdr,
            format,
            basic_block_size,
            basic_block_size_shift,
            basic_block_mask,
            basic_block_qmask,
            is_inner: false,
            is_signed,
            is_encrypted,
            flags,
            dinode_struct_size,
            block_info_struct_size,
            inodes_per_block,
            indirect_ptrs_per_block,
            indirect_ptrs_per_block_for_level,
            super_root_dir_ino: 0,
            block_bitmap_ino: 0,
            ino_bitmap_ino: 0,
            user_root_dir_ino: 0,
            block_addr_table_ino: 0,
            flat_path_table_ino: 0,
            collision_resolver_ino: 0,
            encdec,
            sig_hmac_key,
        };

        pfs.super_root_dir_ino = pfs.hdr.super_root_dir_ino as u32;
        pfs.parse_super_root_directory()?;

        Ok(pfs)
    }

    pub fn block_no_to_offset(&self, block_no: u64) -> u64 {
        block_no << self.basic_block_size_shift
    }

    pub fn offset_in_block(&self, offset: u64) -> u64 {
        offset & self.basic_block_qmask
    }

    pub fn block_round_up(&self, size: u64) -> u64 {
        (size + self.basic_block_qmask) & self.basic_block_mask
    }

    /// Size in bytes occupied by logical block `lbn` (pfs_lbn_to_size).
    pub fn lbn_to_size(&self, size: u64, lbn: u64) -> u64 {
        if lbn >= PFS_DIRECT_BLOCK_MAX_COUNT as u64 || size >= self.block_no_to_offset(lbn + 1) {
            self.basic_block_size as u64
        } else {
            self.block_round_up(self.offset_in_block(size))
        }
    }
}

fn ilog2(n: usize) -> u32 {
    debug_assert!(n.is_power_of_two());
    n.trailing_zeros()
}

/// Minimal SD header view used for key setup (kept for `inspect-save`).
#[derive(Debug, Clone)]
pub struct PfsSdHeader {
    pub version: u64,
    pub magic: u32,
    pub mode: u16,
    pub basic_block_size: u32,
    pub sd_key_ver: u32,
    pub crypt_seed: [u8; SEED_SIZE],
    pub header_hash: [u8; HASH_SIZE],
    pub bottom_signature: [u8; HASH_SIZE],
    raw: Vec<u8>,
}

impl PfsSdHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < PFS_HEADER_SIZE {
            return Err(Error::InvalidLength {
                what: "pfs header",
                expected: PFS_HEADER_SIZE,
                got: data.len(),
            });
        }
        let version = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let magic = u32::from_le_bytes(data[8..12].try_into().unwrap());
        if magic < PFS_FS_MAGIC {
            return Err(Error::Message(format!(
                "unsupported/old PFS magic 0x{magic:X}"
            )));
        }
        let mode = u16::from_le_bytes(data[0x1C..0x1E].try_into().unwrap());
        let basic_block_size = u32::from_le_bytes(data[0x20..0x24].try_into().unwrap());
        let sd_key_ver = u32::from_le_bytes(data[0x36C..0x370].try_into().unwrap());
        let mut crypt_seed = [0u8; SEED_SIZE];
        crypt_seed.copy_from_slice(&data[0x370..0x380]);
        let mut header_hash = [0u8; HASH_SIZE];
        header_hash.copy_from_slice(&data[0x380..0x3A0]);
        let mut bottom_signature = [0u8; HASH_SIZE];
        bottom_signature.copy_from_slice(&data[0x580..0x5A0]);

        Ok(Self {
            version,
            magic,
            mode,
            basic_block_size,
            sd_key_ver,
            crypt_seed,
            header_hash,
            bottom_signature,
            raw: data[..PFS_HEADER_SIZE].to_vec(),
        })
    }

    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let mut file = std::fs::File::open(path)?;
        let mut buf = vec![0u8; PFS_HEADER_SIZE];
        file.read_exact(&mut buf)?;
        Self::parse(&buf)
    }

    pub fn is_encrypted(&self) -> bool {
        self.mode & PFS_MODE_ENCRYPTED != 0
    }

    pub fn is_signed(&self) -> bool {
        self.mode & PFS_MODE_SIGNED != 0
    }

    /// For `sd_key_ver > 2`, verify HMAC over first 0x580 bytes.
    pub fn verify_sd_header_signature(&self, common: &CommonKeys) -> Result<()> {
        if self.sd_key_ver <= 2 {
            return Ok(());
        }
        let key = common
            .sd_hdr_sig_key
            .as_ref()
            .ok_or_else(|| Error::MissingKey("sd_hdr_sig_key".into()))?;
        let computed = hmac_sha256(key, &self.raw[..PFS_SD_HEADER_SIZE]);
        if computed != self.bottom_signature {
            return Err(Error::Message(
                "invalid SD header signature (sd_hdr_sig_key HMAC mismatch)".into(),
            ));
        }
        Ok(())
    }
}

/// Decrypt sealed key + derive SD enc/sig keys from PFS header.
pub fn prepare_sd_keyset_from_sealed(
    common: &CommonKeys,
    sealed: &crate::keys::SealedKey,
    hdr: &PfsSdHeader,
) -> Result<TitleKeyset> {
    let mkey = decrypt_sealed_key(common, sealed)?;

    let content_key = common
        .get_sd_content_key(hdr.sd_key_ver)
        .ok_or_else(|| Error::MissingKey(format!("sd_content_key_{}", hdr.sd_key_ver)))?;

    let mut keyset = TitleKeyset::new(FAKE_CONTENT_ID);
    keyset.mkey = Some(mkey);
    derive_sd_keys(&mut keyset, content_key, &hdr.crypt_seed)?;
    Ok(keyset)
}

pub fn prepare_sd_keyset(
    common: &CommonKeys,
    sealed_path: impl AsRef<std::path::Path>,
    hdr: &PfsSdHeader,
) -> Result<TitleKeyset> {
    let sealed = crate::keys::SealedKey::from_file(sealed_path)?;
    prepare_sd_keyset_from_sealed(common, &sealed, hdr)
}
