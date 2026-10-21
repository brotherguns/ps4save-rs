//! Raw block I/O and file reads (pfs_io.c).

use std::io::{Read, Seek, SeekFrom, Write};

use super::Pfs;
use crate::error::{Error, Result};
use crate::pfs::header::{PfsDinode, PFSC_HEADER_SIZE, PFSC_MAGIC, PFS_FILE_COMPRESSED};

/// An open file context (pfs_file_context).
#[derive(Debug, Clone)]
pub struct PfsFile {
    pub ino: u32,
    pub dinode: PfsDinode,
    pub block_list: Vec<u64>,
    pub file_size: u64,
    pub flags: u32,
    /// PFSC metadata, populated when `flags & PFS_FILE_COMPRESSED`.
    pub cmp_rounded_file_size: u64,
    pub cmp_block_size: usize,
    pub cmp_block_count: u64,
    pub cmp_block_offsets: Vec<u64>,
}

impl PfsFile {
    pub fn is_compressed(&self) -> bool {
        self.flags & PFS_FILE_COMPRESSED != 0
    }

    pub fn is_dir(&self) -> bool {
        self.dinode.is_dir()
    }
}

impl Pfs {
    /// Read `data.len()` bytes of the (optionally encrypted) block stream
    /// starting at `block_no`. `data` must be a multiple of the basic block size.
    pub fn read_blocks(&self, block_no: u64, data: &mut [u8]) -> Result<()> {
        if data.is_empty() || !data.len().is_multiple_of(self.basic_block_size) {
            return Err(Error::Message(format!(
                "read_blocks: size {} not a multiple of block size {}",
                data.len(),
                self.basic_block_size
            )));
        }

        let offset = self.block_no_to_offset(block_no);
        let file_len = self.file.metadata()?.len();
        if offset + data.len() as u64 > file_len {
            return Err(Error::Message(format!(
                "read_blocks: block_no {block_no} at offset {:#X} + {} bytes exceeds file size {:#X}",
                offset, data.len(), file_len,
            )));
        }
        let mut file = &self.file;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(data)?;

        if self.is_encrypted {
            let encdec = self
                .encdec
                .as_ref()
                .ok_or_else(|| Error::Message("missing encdec device for encrypted PFS".into()))?;
            let sector = offset >> crate::pfs::header::PFS_ENCDEC_SECTOR_SIZE_SHIFT;
            encdec.decrypt_inplace(data, sector)?;
        }

        Ok(())
    }

    /// Encrypt `plain` (one basic block) with XTS and write it to `block_no`.
    /// Used by in-place resign to rewrite only the blocks that changed.
    pub fn write_plain_block(&self, block_no: u64, plain: &[u8]) -> Result<()> {
        if plain.len() != self.basic_block_size {
            return Err(Error::Message(format!(
                "write_plain_block: expected {} bytes, got {}",
                self.basic_block_size,
                plain.len()
            )));
        }
        let mut out = plain.to_vec();
        if self.is_encrypted {
            let encdec = self
                .encdec
                .as_ref()
                .ok_or_else(|| Error::Message("missing encdec device for encrypted PFS".into()))?;
            let offset = self.block_no_to_offset(block_no);
            let sector = offset >> crate::pfs::header::PFS_ENCDEC_SECTOR_SIZE_SHIFT;
            encdec.encrypt_inplace(&mut out, sector)?;
        }
        let mut file = &self.file;
        file.seek(SeekFrom::Start(self.block_no_to_offset(block_no)))?;
        file.write_all(&out)?;
        Ok(())
    }

    /// Write raw (already-encrypted) bytes to `block_no` without touching them.
    pub fn write_raw_block(&self, block_no: u64, data: &[u8]) -> Result<()> {
        if data.len() != self.basic_block_size {
            return Err(Error::Message(format!(
                "write_raw_block: expected {} bytes, got {}",
                self.basic_block_size,
                data.len()
            )));
        }
        let mut file = &self.file;
        file.seek(SeekFrom::Start(self.block_no_to_offset(block_no)))?;
        file.write_all(data)?;
        Ok(())
    }

    /// Read a block as stored on disk without XTS decrypting it (block 0).
    pub fn read_raw_block(&self, block_no: u64) -> Result<Vec<u8>> {
        let mut out = vec![0u8; self.basic_block_size];
        let mut file = &self.file;
        file.seek(SeekFrom::Start(self.block_no_to_offset(block_no)))?;
        file.read_exact(&mut out)?;
        Ok(out)
    }

    /// Look up a file context for `ino`.
    pub fn get_file(&self, ino: u32) -> Result<PfsFile> {
        let (dinode, _block_no, _offset) = self.get_dinode(ino)?;
        let block_list = self.get_block_list(&dinode)?;

        let flags = dinode.flags;
        let mut file = PfsFile {
            ino,
            dinode,
            block_list,
            file_size: 0,
            flags,
            cmp_rounded_file_size: 0,
            cmp_block_size: 0,
            cmp_block_count: 0,
            cmp_block_offsets: Vec::new(),
        };

        if flags & PFS_FILE_COMPRESSED != 0 {
            file.file_size = file.dinode.size_uncompressed;
            self.load_pfsc(&mut file)?;
        } else {
            file.file_size = file.dinode.size;
        }

        Ok(file)
    }

    /// Parse the PFSC header from the file's first data block and load the
    /// compressed-block offset table (pfs_file_open).
    fn load_pfsc(&self, file: &mut PfsFile) -> Result<()> {
        if file.block_list.is_empty() {
            return Err(Error::Message(
                "compressed file has no data blocks".into(),
            ));
        }

        let mut hdr = vec![0u8; PFSC_HEADER_SIZE];
        self.file_read_raw(file, 0, &mut hdr)?;

        let magic = u32::from_le_bytes(hdr[0x00..0x04].try_into().unwrap());
        if magic != PFSC_MAGIC {
            return Err(Error::Message("not PFSC format".into()));
        }
        let block_size = u32::from_le_bytes(hdr[0x0C..0x10].try_into().unwrap());
        let block_table_offset = u64::from_le_bytes(hdr[0x18..0x20].try_into().unwrap());
        let rounded_file_size = u64::from_le_bytes(hdr[0x28..0x30].try_into().unwrap());

        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(Error::Message(format!(
                "invalid PFSC block size 0x{block_size:X}"
            )));
        }

        let block_count = rounded_file_size / block_size as u64 + 1;
        let mut raw = vec![0u8; (block_count * 8) as usize];
        self.file_read_raw(file, block_table_offset, &mut raw)?;

        let mut block_offsets = Vec::with_capacity(block_count as usize);
        for i in 0..block_count as usize {
            block_offsets.push(u64::from_le_bytes(
                raw[i * 8..i * 8 + 8].try_into().unwrap(),
            ));
        }

        file.cmp_rounded_file_size = rounded_file_size;
        file.cmp_block_size = block_size as usize;
        file.cmp_block_count = block_count;
        file.cmp_block_offsets = block_offsets;
        Ok(())
    }

    /// Read `data.len()` bytes of a file, handling compression when needed.
    pub fn file_read(&self, file: &PfsFile, offset: u64, data: &mut [u8]) -> Result<()> {
        let data_size = data.len() as u64;
        if offset + data_size > file.file_size {
            return Err(Error::Message(format!(
                "read past end of file: offset 0x{offset:X} + size 0x{data_size:X} > 0x{:X}",
                file.file_size
            )));
        }

        if file.block_list.is_empty() {
            return Err(Error::Message("file has no data blocks".into()));
        }

        if file.is_compressed() {
            return self.file_read_compressed(file, offset, data);
        }

        self.file_read_raw(file, offset, data)
    }

    /// Compressed (PFSC) file read, mirroring pfs_file_read_compressed.
    fn file_read_compressed(&self, file: &PfsFile, offset: u64, data: &mut [u8]) -> Result<()> {
        let data_size = data.len() as u64;
        if file.cmp_block_offsets.is_empty() {
            return Err(Error::Message("missing PFSC block table".into()));
        }

        let block_size = file.cmp_block_size as u64;
        let block_size_shift = file.cmp_block_size.trailing_zeros();
        let block_size_qmask = block_size - 1;
        let block_offsets = &file.cmp_block_offsets;
        let total_block_count = file.cmp_block_count;
        let total_size = file.cmp_rounded_file_size;

        let start_block = offset >> block_size_shift;
        let start_offset = offset & block_size_qmask;
        let block_count = align_up(data_size, block_size) >> block_size_shift;
        let end_block = start_block + block_count;

        if block_count > total_block_count {
            return Err(Error::Message(
                "read spans beyond the PFSC block table".into(),
            ));
        }

        let mut work_in = vec![0u8; block_size as usize];
        let mut work_out = vec![0u8; block_size as usize];
        let mut processed: u64 = 0;

        for i in start_block..end_block {
            self.file_read_raw(file, block_offsets[i as usize], &mut work_in)?;
            let compressed_size = block_offsets[i as usize + 1] - block_offsets[i as usize];

            let last = (i + 1) >= total_block_count;
            let cur_size;
            if compressed_size == block_size {
                // Block stored uncompressed: raw copy.
                cur_size = if i + 1 < end_block {
                    block_size - start_offset
                } else {
                    data_size - processed
                };
                let dst = &mut data[processed as usize..(processed + cur_size) as usize];
                dst.copy_from_slice(
                    &work_in[start_offset as usize..(start_offset + cur_size) as usize],
                );
            } else {
                let decompressed_size = if !last {
                    block_size
                } else {
                    total_size - (total_block_count - 1) * block_size
                };
                if decompressed_size < compressed_size {
                    // C falls back to a raw copy in this case.
                    cur_size = if i + 1 < end_block {
                        block_size - start_offset
                    } else {
                        data_size - processed
                    };
                    let dst = &mut data[processed as usize..(processed + cur_size) as usize];
                    dst.copy_from_slice(
                        &work_in[start_offset as usize..(start_offset + cur_size) as usize],
                    );
                } else {
                    let written = pfsc_decompress(
                        &work_in[..compressed_size as usize],
                        &mut work_out[..decompressed_size as usize],
                    )?;
                    cur_size = if i + 1 < end_block {
                        written as u64 - start_offset
                    } else {
                        data_size - processed
                    };
                    let dst = &mut data[processed as usize..(processed + cur_size) as usize];
                    dst.copy_from_slice(
                        &work_out[start_offset as usize..(start_offset + cur_size) as usize],
                    );
                }
            }
            processed += cur_size;
        }

        Ok(())
    }

    /// Raw (uncompressed) file read, mirroring pfs_file_read_raw.
    pub fn file_read_raw(&self, file: &PfsFile, offset: u64, data: &mut [u8]) -> Result<()> {
        let data_size = data.len() as u64;
        let start_block = offset >> self.basic_block_size_shift;
        let start_offset = offset & self.basic_block_qmask;
        let block_count = align_up(data_size, self.basic_block_size as u64) >> self.basic_block_size_shift;
        let end_block = start_block + block_count;

        if block_count > file.block_list.len() as u64 {
            return Err(Error::Message(
                "read spans beyond the file's block list".into(),
            ));
        }

        // C uses a 2-block scratch so a sector boundary crossing is read at once.
        let read_block_count = if start_offset > 0 { 2usize } else { 1 };
        let mut tmp = vec![0u8; read_block_count * self.basic_block_size];

        let mut processed: u64 = 0;
        for i in start_block..end_block {
            let cur_size = self
                .lbn_to_size(file.file_size, i)
                .min(data_size - processed);

            let n_blocks = if (i + 1) < file.block_list.len() as u64 {
                read_block_count as u64
            } else {
                1
            };
            let mut read_tmp = vec![0u8; n_blocks as usize * self.basic_block_size];
            self.read_blocks(file.block_list[i as usize], &mut read_tmp)?;
            tmp[..n_blocks as usize * self.basic_block_size]
                .copy_from_slice(&read_tmp[..n_blocks as usize * self.basic_block_size]);

            let src_start = start_offset as usize;
            let src_end = src_start + cur_size as usize;
            let dst = &mut data[processed as usize..processed as usize + cur_size as usize];
            dst.copy_from_slice(&tmp[src_start..src_end]);

            processed += cur_size;
        }

        Ok(())
    }
}

pub fn align_up(value: u64, align: u64) -> u64 {
    value.wrapping_add(align - 1) & !(align - 1)
}

/// zlib inflate with the given window bits (PS4 uses 2^12).
/// flate2's decoder uses the maximum window, which can still decode streams
/// produced with a smaller window.
fn pfsc_decompress(input: &[u8], output: &mut [u8]) -> Result<usize> {
    use flate2::read::ZlibDecoder;

    let mut decoder = ZlibDecoder::new(input);
    let mut written = 0usize;
    loop {
        match decoder.read(&mut output[written..]) {
            Ok(0) => break,
            Ok(n) => written += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::pfsc_decompress;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write as _;

    #[test]
    fn pfsc_decompress_roundtrip() {
        let plain: Vec<u8> = (0u8..250).cycle().take(100_000).collect();
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&plain).unwrap();
        let compressed = enc.finish().unwrap();
        assert!(compressed.len() < plain.len());

        let mut out = vec![0u8; plain.len()];
        let written = pfsc_decompress(&compressed, &mut out).unwrap();
        assert_eq!(written, plain.len());
        assert_eq!(out, plain);
    }

    #[test]
    fn pfsc_decompress_window12() {
        // Stream produced with zlib window_bits = 12 (the PS4's PFSC setting),
        // generated via python3: zlib.compressobj(6, zlib.DEFLATED, 12).
        let plain = (b"hello ps4 save data window 12 test ".repeat(200)).to_vec();
        let compressed: Vec<u8> = vec![
            0x48, 0x89, 0xED, 0xCA, 0xD1, 0x09, 0x80, 0x20, 0x14, 0x00, 0xC0, 0x55, 0xDE, 0x0A,
            0x45, 0x0B, 0x09, 0x0A, 0x06, 0x92, 0x81, 0xA2, 0xEB, 0x37, 0x48, 0x77, 0xDF, 0x57,
            0x4B, 0x6B, 0x3D, 0xDE, 0x71, 0xC5, 0x48, 0xAB, 0x44, 0x4E, 0x33, 0xC5, 0xBE, 0x9F,
            0xDC, 0x77, 0x1C, 0x67, 0xCC, 0x32, 0x66, 0x54, 0x45, 0x51, 0x14, 0x45, 0x51, 0x14,
            0x45, 0x51, 0x14, 0x45, 0x51, 0x14, 0x45, 0x51, 0x14, 0x45, 0x51, 0x14, 0x45, 0xF9,
            0x7B, 0xF9, 0x00, 0x1C, 0x8E, 0x6C, 0x40,
        ];

        let mut out = vec![0u8; plain.len()];
        let written = pfsc_decompress(&compressed, &mut out).unwrap();
        assert_eq!(written, plain.len());
        assert_eq!(out, plain);
    }
}
