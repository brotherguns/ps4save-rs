//! PFS header, dinode, and block-info structs matching pkg_pfs_tool pfs.h.

use crate::error::{Error, Result};

pub const PFS_HEADER_SIZE: usize = 0x5A0;
pub const PFS_HEADER_COVER_SIZE_FOR_ICV: usize = 0x380;
pub const PFS_SD_HEADER_SIZE: usize = 0x580;
pub const PFS_FS_MAGIC: u32 = 0x1332A0B;
pub const PFSC_MAGIC: u32 = 0x43534650;
pub const PFSC_HEADER_SIZE: usize = 0x30;
/// zlib window size used by the PS4's PFSC compression (2^12).
pub const PFSC_ZLIB_WINDOW_BITS: i32 = 12;

pub const PFS_DIR_ENTRY_NAME_MAX_SIZE: usize = 16384;
pub const PFS_DIRECT_BLOCK_MAX_COUNT: usize = 12;
pub const PFS_INDIRECT_BLOCK_MAX_COUNT: usize = 5;
pub const PFS_HASH_SIZE: usize = 32;
pub const PFS_SIGNATURE_SIZE: usize = 256;
pub const PFS_DEVICE_BLOCK_SIZE: usize = 512;
pub const PFS_ENCDEC_SECTOR_SIZE: usize = 0x1000;
pub const PFS_ENCDEC_SECTOR_SIZE_SHIFT: u32 = 12;
pub const PFS_MIN_BLOCK_SIZE: usize = 0x1000;
pub const PFS_MAX_BLOCK_SIZE: usize = 0x200000;
pub const PFS_MIN_DIR_ENTRY_SIZE: usize = 0x14;

pub const PFS_MODE_FORMAT_MASK: u16 = 0x3;
pub const PFS_MODE_SIGNED_FLAG: u16 = 0x1;
pub const PFS_MODE_ENCRYPTED_FLAG: u16 = 0x4;
pub const PFS_MODE_CASE_INSENSITIVE_FLAG: u16 = 0x8;

pub const PFS_INODE_STRUCT_SIZE: usize = 0xB8;
pub const PFS_BLOCK32_STRUCT_SIZE: usize = 0x4;
pub const PFS_BLOCK64_STRUCT_SIZE: usize = 0x8;
pub const PFS_SBLOCK32_STRUCT_SIZE: usize = 0x24;
pub const PFS_SBLOCK64_STRUCT_SIZE: usize = 0x28;
pub const PFS_DINODE32_STRUCT_SIZE: usize = 0x48;
pub const PFS_DINODE64_STRUCT_SIZE: usize = 0x90;
pub const PFS_SDINODE32_STRUCT_SIZE: usize = 0x268;
pub const PFS_SDINODE64_STRUCT_SIZE: usize = 0x2B0;
pub const PFS_DINODE_TOP_STRUCT_SIZE: usize = 0x60;
pub const PFS_DINODE_STRUCT_SIZE: usize = 0x310;

/// Bit layout of the dinode block-info union tail (largest variant).
pub const PFS_DINODE_UNION_SIZE: usize = PFS_SDINODE64_STRUCT_SIZE;

// File flags.
pub const PFS_FILE_COMPRESSED: u32 = 1 << 0;
pub const PFS_FILE_ENCRYPTED: u32 = 1 << 2;

// Mode type mask/values.
pub const PFS_FILE_TYPE_MASK: u16 = 0o170000;
pub const PFS_FILE_TYPE_FIFO: u16 = 0o010000;
pub const PFS_FILE_TYPE_CHR: u16 = 0o020000;
pub const PFS_FILE_TYPE_DIR: u16 = 0o040000;
pub const PFS_FILE_TYPE_BLK: u16 = 0o060000;
pub const PFS_FILE_TYPE_REG: u16 = 0o100000;
pub const PFS_FILE_TYPE_LNK: u16 = 0o120000;
pub const PFS_FILE_TYPE_SOCK: u16 = 0o140000;
pub const PFS_FILE_TYPE_WHT: u16 = 0o160000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PfsFormat {
    /// 32-bit inodes
    Format32,
    /// 32-bit inodes (signed)
    Format32Signed,
    /// 64-bit inodes
    Format64,
    /// 64-bit inodes (signed)
    Format64Signed,
}

impl PfsFormat {
    pub fn from_mode(mode: u16) -> Self {
        match mode & PFS_MODE_FORMAT_MASK {
            0 => PfsFormat::Format32,
            1 => PfsFormat::Format32Signed,
            2 => PfsFormat::Format64,
            _ => PfsFormat::Format64Signed,
        }
    }

    pub fn is_signed(&self) -> bool {
        matches!(self, PfsFormat::Format32Signed | PfsFormat::Format64Signed)
    }

    pub fn dinode_struct_size(&self) -> usize {
        PFS_DINODE_TOP_STRUCT_SIZE
            + match self {
                PfsFormat::Format32 => PFS_DINODE32_STRUCT_SIZE,
                PfsFormat::Format64 => PFS_DINODE64_STRUCT_SIZE,
                PfsFormat::Format32Signed => PFS_SDINODE32_STRUCT_SIZE,
                PfsFormat::Format64Signed => PFS_SDINODE64_STRUCT_SIZE,
            }
    }

    pub fn block_info_struct_size(&self) -> usize {
        match self {
            PfsFormat::Format32 => PFS_BLOCK32_STRUCT_SIZE,
            PfsFormat::Format64 => PFS_BLOCK64_STRUCT_SIZE,
            PfsFormat::Format32Signed => PFS_SBLOCK32_STRUCT_SIZE,
            PfsFormat::Format64Signed => PFS_SBLOCK64_STRUCT_SIZE,
        }
    }

    /// Block number field size within a (s)block entry.
    pub fn block_no_size(&self) -> usize {
        match self {
            PfsFormat::Format32 | PfsFormat::Format32Signed => 4,
            PfsFormat::Format64 | PfsFormat::Format64Signed => 8,
        }
    }

    /// Offset of the block_no field within one (s)block entry.
    pub fn block_no_offset(&self) -> usize {
        if self.is_signed() {
            PFS_HASH_SIZE
        } else {
            0
        }
    }
}

/// PFS dir entry (`pfs_dir_entry`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PfsDirEntry {
    pub ino: u32,
    pub entry_type: u32,
    pub name_size: u32,
    pub entry_size: u32,
    pub name: Vec<u8>,
}

/// Parsed dinode (`pfs_dinode`): 0x60 header fields + raw block-info union.
#[derive(Debug, Clone, PartialEq)]
pub struct PfsDinode {
    pub mode: u16,
    pub link_count: u16,
    pub flags: u32,
    pub size: u64,
    pub size_uncompressed: u64,
    pub last_access_time: u64,
    pub last_modified_time: u64,
    pub last_change_time: u64,
    pub creation_time: u64,
    pub last_modified_time_ns: u32,
    pub last_access_time_ns: u32,
    pub last_change_time_ns: u32,
    pub creation_time_ns: u32,
    pub uid: u32,
    pub gid: u32,
    pub spare: [u64; 2],
    /// Block-info union at offset 0x60 (raw).
    pub union: [u8; PFS_DINODE_UNION_SIZE],
}

impl PfsDinode {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < PFS_DINODE_TOP_STRUCT_SIZE {
            return Err(Error::InvalidLength {
                what: "pfs dinode",
                expected: PFS_DINODE_TOP_STRUCT_SIZE,
                got: data.len(),
            });
        }
        let mode = u16::from_le_bytes(data[0x00..0x02].try_into().unwrap());
        let link_count = u16::from_le_bytes(data[0x02..0x04].try_into().unwrap());
        let flags = u32::from_le_bytes(data[0x04..0x08].try_into().unwrap());
        let size = u64::from_le_bytes(data[0x08..0x10].try_into().unwrap());
        let size_uncompressed = u64::from_le_bytes(data[0x10..0x18].try_into().unwrap());
        let last_access_time = u64::from_le_bytes(data[0x18..0x20].try_into().unwrap());
        let last_modified_time = u64::from_le_bytes(data[0x20..0x28].try_into().unwrap());
        let last_change_time = u64::from_le_bytes(data[0x28..0x30].try_into().unwrap());
        let creation_time = u64::from_le_bytes(data[0x30..0x38].try_into().unwrap());
        let last_modified_time_ns = u32::from_le_bytes(data[0x38..0x3C].try_into().unwrap());
        let last_access_time_ns = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap());
        let last_change_time_ns = u32::from_le_bytes(data[0x40..0x44].try_into().unwrap());
        let creation_time_ns = u32::from_le_bytes(data[0x44..0x48].try_into().unwrap());
        let uid = u32::from_le_bytes(data[0x48..0x4C].try_into().unwrap());
        let gid = u32::from_le_bytes(data[0x4C..0x50].try_into().unwrap());
        let mut spare = [0u64; 2];
        spare[0] = u64::from_le_bytes(data[0x50..0x58].try_into().unwrap());
        spare[1] = u64::from_le_bytes(data[0x58..0x60].try_into().unwrap());

        let mut union = [0u8; PFS_DINODE_UNION_SIZE];
        let union_avail = data.len().min(PFS_DINODE_TOP_STRUCT_SIZE + PFS_DINODE_UNION_SIZE);
        if union_avail > PFS_DINODE_TOP_STRUCT_SIZE {
            union[..union_avail - PFS_DINODE_TOP_STRUCT_SIZE]
                .copy_from_slice(&data[PFS_DINODE_TOP_STRUCT_SIZE..union_avail]);
        }

        Ok(Self {
            mode,
            link_count,
            flags,
            size,
            size_uncompressed,
            last_access_time,
            last_modified_time,
            last_change_time,
            creation_time,
            last_modified_time_ns,
            last_access_time_ns,
            last_change_time_ns,
            creation_time_ns,
            uid,
            gid,
            spare,
            union,
        })
    }

    pub fn file_type(&self) -> u16 {
        self.mode & PFS_FILE_TYPE_MASK
    }

    pub fn is_dir(&self) -> bool {
        self.file_type() == PFS_FILE_TYPE_DIR
    }

    pub fn is_reg(&self) -> bool {
        self.file_type() == PFS_FILE_TYPE_REG
    }

    pub fn is_compressed(&self) -> bool {
        self.flags & PFS_FILE_COMPRESSED != 0
    }

    fn u32_at(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.union[off..off + 4].try_into().unwrap())
    }

    fn u64_at(&self, off: usize) -> u64 {
        u64::from_le_bytes(self.union[off..off + 8].try_into().unwrap())
    }

    /// Read `block_count` field for the given format.
    pub fn block_count(&self, format: PfsFormat) -> u64 {
        match format.block_no_size() {
            4 => self.u32_at(0x00) as u64,
            _ => self.u64_at(0x00),
        }
    }

    /// Read direct block `i` (0..12) block_no for the given format.
    pub fn direct_block_no(&self, format: PfsFormat, i: usize) -> u64 {
        debug_assert!(i < PFS_DIRECT_BLOCK_MAX_COUNT);
        let entry = format.block_info_struct_size();
        let field = format.block_no_offset();
        let base = match format.block_no_size() {
            4 => 0x04,
            _ => 0x08,
        };
        let off = base + i * entry + field;
        match format.block_no_size() {
            4 => self.u32_at(off) as u64,
            _ => self.u64_at(off),
        }
    }

    /// Read indirect block `n` (0..5) block_no for the given format.
    pub fn indirect_block_no(&self, format: PfsFormat, n: usize) -> u64 {
        debug_assert!(n < PFS_INDIRECT_BLOCK_MAX_COUNT);
        let entry = format.block_info_struct_size();
        let field = format.block_no_offset();
        let base = match format {
            PfsFormat::Format32 => 0x34,
            PfsFormat::Format32Signed => 0x1B4,
            PfsFormat::Format64 => 0x68,
            PfsFormat::Format64Signed => 0x1E8,
        };
        let off = base + n * entry + field;
        match format.block_no_size() {
            4 => self.u32_at(off) as u64,
            _ => self.u64_at(off),
        }
    }
}

/// Full PFS header (`pfs_header`), 0x5A0 bytes.
#[derive(Debug, Clone)]
pub struct PfsHeader {
    pub version: u64,
    pub magic: u64,
    pub id: [u32; 2],
    pub fmode: u8,
    pub clean: u8,
    pub read_only: u8,
    pub rsv: u8,
    pub mode: u16,
    pub basic_block_size: u32,
    pub nbackup: u32,
    pub nblock: u64,
    pub dinode_count: u64,
    pub data_block_count: u64,
    pub dinode_block_count: u64,
    pub super_root_dir_ino: u64,
    pub super_root_dinode: PfsDinode,
    pub unk1: u32,
    pub unk2: u32,
    pub unk3: u32,
    pub sd_key_ver: u32,
    pub crypt_seed: [u8; 16],
    pub header_hash: [u8; PFS_HASH_SIZE],
    pub raw: [u8; PFS_HEADER_SIZE],
}

impl PfsHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < PFS_HEADER_SIZE {
            return Err(Error::InvalidLength {
                what: "pfs header",
                expected: PFS_HEADER_SIZE,
                got: data.len(),
            });
        }
        let version = u64::from_le_bytes(data[0x00..0x08].try_into().unwrap());
        let magic = u64::from_le_bytes(data[0x08..0x10].try_into().unwrap());
        if (magic as u32) != PFS_FS_MAGIC && (magic as u32) < PFS_FS_MAGIC {
            return Err(Error::Message(format!(
                "unsupported/old PFS magic 0x{magic:X}"
            )));
        }
        let mode = u16::from_le_bytes(data[0x1C..0x1E].try_into().unwrap());
        let basic_block_size = u32::from_le_bytes(data[0x20..0x24].try_into().unwrap());
        let nbackup = u32::from_le_bytes(data[0x24..0x28].try_into().unwrap());
        let nblock = u64::from_le_bytes(data[0x28..0x30].try_into().unwrap());
        let dinode_count = u64::from_le_bytes(data[0x30..0x38].try_into().unwrap());
        let data_block_count = u64::from_le_bytes(data[0x38..0x40].try_into().unwrap());
        let dinode_block_count = u64::from_le_bytes(data[0x40..0x48].try_into().unwrap());
        let super_root_dir_ino = u64::from_le_bytes(data[0x48..0x50].try_into().unwrap());
        let super_root_dinode = PfsDinode::parse(&data[0x50..0x50 + PFS_DINODE_STRUCT_SIZE])?;
        let unk1 = u32::from_le_bytes(data[0x360..0x364].try_into().unwrap());
        let unk2 = u32::from_le_bytes(data[0x364..0x368].try_into().unwrap());
        let unk3 = u32::from_le_bytes(data[0x368..0x36C].try_into().unwrap());
        let sd_key_ver = u32::from_le_bytes(data[0x36C..0x370].try_into().unwrap());
        let mut crypt_seed = [0u8; 16];
        crypt_seed.copy_from_slice(&data[0x370..0x380]);
        let mut header_hash = [0u8; PFS_HASH_SIZE];
        header_hash.copy_from_slice(&data[0x380..0x3A0]);

        let mut raw = [0u8; PFS_HEADER_SIZE];
        raw.copy_from_slice(&data[..PFS_HEADER_SIZE]);

        Ok(Self {
            version,
            magic,
            id: [
                u32::from_le_bytes(data[0x10..0x14].try_into().unwrap()),
                u32::from_le_bytes(data[0x14..0x18].try_into().unwrap()),
            ],
            fmode: data[0x18],
            clean: data[0x19],
            read_only: data[0x1A],
            rsv: data[0x1B],
            mode,
            basic_block_size,
            nbackup,
            nblock,
            dinode_count,
            data_block_count,
            dinode_block_count,
            super_root_dir_ino,
            super_root_dinode,
            unk1,
            unk2,
            unk3,
            sd_key_ver,
            crypt_seed,
            header_hash,
            raw,
        })
    }

    pub fn is_signed(&self) -> bool {
        self.mode & PFS_MODE_SIGNED_FLAG != 0
    }

    pub fn is_encrypted(&self) -> bool {
        self.mode & PFS_MODE_ENCRYPTED_FLAG != 0
    }

    pub fn is_case_sensitive(&self) -> bool {
        self.mode & PFS_MODE_CASE_INSENSITIVE_FLAG == 0
    }
}

/// Read a `(s)block` entry's block_no from a raw indirect block buffer.
pub fn entry_block_no(format: PfsFormat, buf: &[u8], idx: usize) -> u64 {
    let entry = format.block_info_struct_size();
    let off = idx * entry + format.block_no_offset();
    match format.block_no_size() {
        4 => u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as u64,
        _ => u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()),
    }
}
