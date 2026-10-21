//! Dinode lookup and data-block list resolution (pfs_dinode.c / pfs_block.c).

use super::Pfs;
use crate::crypto::hmac_sha256;
use crate::error::{Error, Result};
use crate::pfs::header::{
    PfsDinode, PfsFormat, PFS_DINODE_TOP_STRUCT_SIZE, PFS_DIRECT_BLOCK_MAX_COUNT,
    PFS_FILE_TYPE_REG, PFS_SBLOCK32_STRUCT_SIZE, entry_block_no,
};

impl Pfs {
    /// Whether `dinode` equals the header's embedded super-root dinode.
    pub fn is_super_root_dinode(&self, dinode: &PfsDinode) -> bool {
        dinode == &self.hdr.super_root_dinode
    }

    /// Fetch a dinode by inode number, returning it together with its location.
    pub fn get_dinode(&self, ino: u32) -> Result<(PfsDinode, u64, usize)> {
        let inodes_per_block = self.inodes_per_block as u32;
        let idx1 = ino / inodes_per_block;
        let idx2 = (ino % inodes_per_block) as usize;

        let (block_no, _sino) = self.get_block_no_sino(&self.hdr.super_root_dinode, idx1 as u64)?;

        let dinode_offset = idx2 * self.dinode_struct_size;
        let mut block = vec![0u8; self.basic_block_size];
        self.read_blocks(block_no, &mut block)?;

        let dinode = PfsDinode::parse(
            &block[dinode_offset..dinode_offset + self.dinode_struct_size],
        )?;
        Ok((dinode, block_no, dinode_offset))
    }

    /// Rewrite the super-root's digest slot for the inode-table block
    /// `tbl_block` to `tbl_digest`, fixing the sblock digest chain up to the
    /// header's super-root dinode.
    ///
    /// Large saves spread the inode table over many blocks: the first 12 land
    /// in the super-root's direct entries (digest inline in block 0); the rest
    /// are addressed through a level-0 "bridge" block whose entries are
    /// SBLOCK32 records (digest + blockno), and the bridge's own digest lives
    /// in the super-root's first indirect slot (also in block 0).
    ///
    /// Returns the updated block-0 bytes; the caller re-authenticates the
    /// header and writes it back. The modified bridge block is written in
    /// place.
    pub fn patch_super_root_tbl_digest(
        &self,
        hmac_key: &[u8],
        tbl_block: u64,
        tbl_digest: &[u8],
    ) -> Result<Vec<u8>> {
        let sr = &self.hdr.super_root_dinode;
        let sr_format = PfsFormat::Format64Signed;
        let sr_entry_size = sr_format.block_info_struct_size(); // SBLOCK64: 32B digest + u64
        let sr_base = 0x08usize; // S64 blk_count is u64
        let sr_union_off = 0x50 + PFS_DINODE_TOP_STRUCT_SIZE;

        let mut b0 = self.read_raw_block(0)?;

        // Super-root direct entries: digest lives inline in block 0.
        for i in 0..PFS_DIRECT_BLOCK_MAX_COUNT {
            if sr.direct_block_no(sr_format, i) == tbl_block {
                let off = sr_union_off + sr_base + i * sr_entry_size;
                b0[off..off + 32].copy_from_slice(tbl_digest);
                return Ok(b0);
            }
        }

        // Level-0 bridge block (u0): the digest sits inside u0 as an SBLOCK32
        // entry; u0's own digest is the first of the super-root's indirect
        // slots, which are stored right after the 12 direct entries in block 0.
        let ib_no = sr.indirect_block_no(sr_format, 0);
        let mut ib = vec![0u8; self.basic_block_size];
        self.read_blocks(ib_no, &mut ib)?;

        let count = self.basic_block_size / PFS_SBLOCK32_STRUCT_SIZE;
        for j in 0..count {
            let off = j * PFS_SBLOCK32_STRUCT_SIZE;
            let stored =
                u32::from_le_bytes(ib[off + 32..off + 36].try_into().unwrap()) as u64;
            if stored != tbl_block {
                continue;
            }
            ib[off..off + 32].copy_from_slice(tbl_digest);
            self.write_plain_block(ib_no, &ib)?;
            let ib_digest = hmac_sha256(hmac_key, &ib);

            let slot_off =
                sr_union_off + sr_base + PFS_DIRECT_BLOCK_MAX_COUNT * sr_entry_size;
            let stored_ib =
                u64::from_le_bytes(b0[slot_off + 32..slot_off + 40].try_into().unwrap());
            if stored_ib != ib_no {
                return Err(Error::Message(format!(
                    "super-root indirect slot 0 does not reference bridge block \
                     {ib_no} (got {stored_ib})"
                )));
            }
            b0[slot_off..slot_off + 32].copy_from_slice(&ib_digest);
            return Ok(b0);
        }

        Err(Error::Message(format!(
            "inode-table block {tbl_block} not managed by super-root"
        )))
    }

    /// Resolve the physical block number for `block_counter` within `dinode`'s data.
    ///
    /// Supports direct blocks (0..12) and indirect levels 0/1/2.
    pub fn get_block_no_sino(&self, dinode: &PfsDinode, block_counter: u64) -> Result<(u64, u32)> {
        let flags = self.hdr.super_root_dinode.flags;
        let max_block_count = self.hdr.super_root_dinode.block_count(self.format);

        if max_block_count < block_counter + 1 {
            return Err(Error::Message(format!(
                "no blocks: {}/{}",
                block_counter + 1,
                max_block_count
            )));
        }

        if flags & 0x10 != 0 && !self.is_signed {
            let base = if self.is_super_root_dinode(dinode) {
                dinode.direct_block_no(PfsFormat::Format64Signed, 0)
            } else if self.format == PfsFormat::Format64 {
                dinode.direct_block_no(PfsFormat::Format64, 0)
            } else {
                dinode.direct_block_no(PfsFormat::Format32, 0)
            };
            return Ok((base + block_counter, 0));
        }

        // Direct blocks.
        if (block_counter as usize) < PFS_DIRECT_BLOCK_MAX_COUNT {
            let block_no =
                dinode.direct_block_no(PfsFormat::Format64Signed, block_counter as usize);
            return Ok((block_no, 0));
        }

        let db_format = PfsFormat::Format64Signed;
        let ib_format = self.format;
        let mut remaining = block_counter - PFS_DIRECT_BLOCK_MAX_COUNT as u64;

        // Indirect level 0.
        let ptrs = self.indirect_ptrs_per_block as u64;
        {
            let u0 = self.read_indirect_block(dinode, db_format, 0)?;
            let idx = remaining / ptrs;
            let off = remaining % ptrs;
            if idx == 0 {
                let block_no = entry_block_no(ib_format, &u0, off as usize);
                return Ok((block_no, 0));
            }
            remaining -= ptrs;
        }

        // Indirect level 1.
        {
            let u1 = self.read_indirect_block(dinode, db_format, 1)?;
            let outer = remaining / ptrs;
            let inner = remaining % ptrs;
            let idx = inner / ptrs;
            let off = inner % ptrs;
            if outer == 0 {
                let l0_block_no = entry_block_no(ib_format, &u1, idx as usize);
                let mut u0 = vec![0u8; self.basic_block_size];
                self.read_blocks(l0_block_no, &mut u0)?;
                let block_no = entry_block_no(ib_format, &u0, off as usize);
                return Ok((block_no, 0));
            }
            remaining -= ptrs * ptrs;
        }

        // Indirect level 2.
        {
            let u2 = self.read_indirect_block(dinode, db_format, 2)?;
            let l2_idx = remaining / (ptrs * ptrs);
            let l1_rem = remaining % (ptrs * ptrs);
            let l1_idx = l1_rem / ptrs;
            let l0_idx = l1_rem % ptrs;
            let l1_block_no = entry_block_no(ib_format, &u2, l2_idx as usize);
            let mut u1 = vec![0u8; self.basic_block_size];
            self.read_blocks(l1_block_no, &mut u1)?;
            let l0_block_no = entry_block_no(ib_format, &u1, l1_idx as usize);
            let mut u0 = vec![0u8; self.basic_block_size];
            self.read_blocks(l0_block_no, &mut u0)?;
            let block_no = entry_block_no(ib_format, &u0, l0_idx as usize);
            return Ok((block_no, 0));
        }
    }

    /// Build the full list of data block numbers for `dinode` (pfs_get_block_list).
    pub fn get_block_list(&self, dinode: &PfsDinode) -> Result<Vec<u64>> {
        let db_format = if self.is_super_root_dinode(dinode) {
            PfsFormat::Format64Signed
        } else {
            self.format
        };
        let ib_format = self.format;

        let real_size = dinode.size;
        let capacity = (real_size / self.basic_block_size as u64) + 1;
        let mut blocks: Vec<u64> = Vec::with_capacity(capacity as usize);
        let mut processed_size: u64 = 0;

        let needed_block_count = dinode.block_count(db_format);

        // Direct blocks.
        let mut contig_block_count: u64 = 0;
        for i in 0..PFS_DIRECT_BLOCK_MAX_COUNT {
            let block_no = dinode.direct_block_no(db_format, i);
            if block_no == 0xFFFF_FFFF {
                contig_block_count = needed_block_count.saturating_sub(i as u64);
                break;
            }
            blocks.push(block_no);
            processed_size += self.lbn_to_size(real_size, (blocks.len() - 1) as u64);
            if processed_size >= real_size {
                return Ok(blocks);
            }
        }

        if contig_block_count > 0 {
            for _ in 0..contig_block_count {
                let block_no = blocks[blocks.len() - 1] + 1;
                blocks.push(block_no);
                processed_size += self.lbn_to_size(real_size, (blocks.len() - 1) as u64);
                if processed_size >= real_size {
                    return Ok(blocks);
                }
            }
        }

        // Indirect level 0.
        {
            let u0 = self.read_indirect_block(dinode, db_format, 0)?;
            for i in 0..self.indirect_ptrs_per_block {
                let block_no = entry_block_no(ib_format, &u0, i);
                blocks.push(block_no);
                processed_size += self.lbn_to_size(real_size, (blocks.len() - 1) as u64);
                if processed_size >= real_size {
                    return Ok(blocks);
                }
            }
        }

        // Indirect level 1.
        {
            let u1 = self.read_indirect_block(dinode, db_format, 1)?;
            for j in 0..self.indirect_ptrs_per_block {
                let block_no = entry_block_no(ib_format, &u1, j);
                let mut u0 = vec![0u8; self.basic_block_size];
                self.read_blocks(block_no, &mut u0)?;
                for i in 0..self.indirect_ptrs_per_block {
                    let block_no = entry_block_no(ib_format, &u0, i);
                    blocks.push(block_no);
                    processed_size +=
                        self.lbn_to_size(real_size, (blocks.len() - 1) as u64);
                    if processed_size >= real_size {
                        return Ok(blocks);
                    }
                }
            }
        }

        // Indirect level 2.
        {
            let u2 = self.read_indirect_block(dinode, db_format, 2)?;
            for k in 0..self.indirect_ptrs_per_block {
                let block_no = entry_block_no(ib_format, &u2, k);
                let mut u1 = vec![0u8; self.basic_block_size];
                self.read_blocks(block_no, &mut u1)?;
                for j in 0..self.indirect_ptrs_per_block {
                    let block_no = entry_block_no(ib_format, &u1, j);
                    let mut u0 = vec![0u8; self.basic_block_size];
                    self.read_blocks(block_no, &mut u0)?;
                    for i in 0..self.indirect_ptrs_per_block {
                        let block_no = entry_block_no(ib_format, &u0, i);
                        blocks.push(block_no);
                        processed_size +=
                            self.lbn_to_size(real_size, (blocks.len() - 1) as u64);
                        if processed_size >= real_size {
                            return Ok(blocks);
                        }
                    }
                }
            }
        }

        Ok(blocks)
    }

    fn read_indirect_block(
        &self,
        dinode: &PfsDinode,
        format: PfsFormat,
        n: usize,
    ) -> Result<Vec<u8>> {
        let block_no = dinode.indirect_block_no(format, n);
        let mut buf = vec![0u8; self.basic_block_size];
        self.read_blocks(block_no, &mut buf)?;
        Ok(buf)
    }
}

/// C's `pfs_check_cipher_block` for data blocks.
pub fn check_cipher_block(pfs: &Pfs, dinode: Option<&PfsDinode>) -> bool {
    if !pfs.is_encrypted {
        return false;
    }
    match dinode {
        None => true,
        Some(d) => {
            if d.file_type() != PFS_FILE_TYPE_REG {
                return true;
            }
            d.flags & crate::pfs::header::PFS_FILE_ENCRYPTED != 0
        }
    }
}
