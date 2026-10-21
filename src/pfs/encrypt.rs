//! PFS image writer (encrypt).
//!
//! Produces a signed+encrypted SD PFS image:
//! build the block layout, write dirents/inodes/bitmaps/BAT, stamp the header
//! and authentication fields, copy the header to the backup block, then
//! AES-XTS-encrypt every sector except block 0 and the backup block.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::crypto::{aes_encrypt_cbc_cts, hmac_sha256, EncDecDevice};
use crate::error::{Error, Result};
use crate::keys::sizes::*;
use crate::keys::{derive_sd_keys, encrypt_sealed_key, CommonKeys, TitleKeyset};
use crate::pfs::header::{
    PFS_DIRECT_BLOCK_MAX_COUNT, PFS_FILE_COMPRESSED, PFS_HEADER_COVER_SIZE_FOR_ICV,
    PFS_SD_HEADER_SIZE,
};

const SECTOR_SIZE: usize = 0x1000;
const PFS_VERSION: u64 = 0x1;
const PFS_MAGIC: u64 = 0x1332A0B;
const PFS_MODE: u16 = 0xD; // Signed, 32 Bit, Encrypted, Case Insensitive

const PFS_ENTRY_FILE: u32 = 2;
const PFS_ENTRY_DIR: u32 = 3;
const PFS_ENTRY_CUR_DIR: u32 = 4;
const PFS_ENTRY_PARENT_DIR: u32 = 5;

const ALIGNMENT: u64 = 8;

const SBLOCK32_SIZE: usize = 0x24;
const SBLOCK64_SIZE: usize = 0x28;
const SDINODE32_SIZE: usize = 0x268;
const SDINODE64_SIZE: usize = 0x2B0;
const DINODE_HEADER_SIZE: usize = 0x60;

const SD_INFO_SIZE: usize = 0x1E0; // 0x3A0..0x580
const AUTHCODE_MAGIC: u64 = 0x459A9BBBC11A2B79;
const AUTHCODE_OFFSET: usize = 0x7F90;
const AUTHCODE_DATA_SIZE: usize = 0x50;

/// Directory / file mode values used by the Python tool.
const MODE_DIR_SUPER: u16 = 0o40777; // 16895
const MODE_DIR_USER: u16 = 0o40775; // 16893
const MODE_FILE: u16 = 0o100777; // 33279

/// Root special files and the header inode use these flags.
const FLAGS_ROOT: u32 = 0x1001E;
/// User files / directories use these flags.
const FLAGS_USER: u32 = 0x2000C;
/// Regular files that live directly under the user root (console-verified
/// value for user data files); everything else uses FLAGS_USER.
const FLAGS_USER_FILE: u32 = 0xC;

// PFSC (compressed-file) format constants; matches the C reader in pfs.c.
const PFSC_MAGIC: u32 = 0x4353_4650;
const PFSC_HEADER_SIZE: usize = 0x30;
/// zlib window bits used by the PS4 for PFSC (2^12).
const PFSC_WINDOW_BITS: u8 = 12;
/// `alignment` field in the PFSC header.
const PFSC_ALIGNMENT: u32 = 0x10;

/// PFS encrypt parameters.
#[derive(Debug, Clone)]
pub struct EncryptOptions {
    /// Basic block size (0x8000).
    pub block_size: usize,
    /// Total number of blocks in the image — must come from SAVEDATA_BLOCKS.
    pub total_blocks: usize,
    /// Total number of inodes.
    pub total_inodes: usize,
    /// Sealed key version used when wrapping EKPFS (10).
    pub sealed_key_version: u16,
    /// Fixed EKPFS (for reproducible builds); random if `None`.
    pub ekpfs: Option<[u8; EKPFS_SIZE]>,
    /// Fixed crypt seed; random if `None`.
    pub seed: Option<[u8; SEED_SIZE]>,
    /// Fixed sealed-key IV (for reproducible resign); random if `None`.
    pub sealed_iv: Option<[u8; 16]>,
    /// Enable PFSC compression for user files where it saves blocks.
    pub compress_files: bool,
    /// Auto-size `total_blocks` up to fit the contents. When `false`,
    /// `total_blocks` is used as-is and an error is returned if it is too small.
    pub auto_blocks: bool,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            block_size: 0x8000,
            total_blocks: 0,
            total_inodes: 1024,
            sealed_key_version: 10,
            ekpfs: None,
            seed: None,
            sealed_iv: None,
            compress_files: false,
            auto_blocks: true,
        }
    }
}

/// Statistics about an encrypted image.
#[derive(Debug, Clone)]
pub struct EncryptStats {
    pub used_blocks: u64,
    pub used_inodes: u32,
    pub image_size: usize,
    pub backup_block: u64,
    /// Effective block count used for the image layout.
    pub total_blocks: usize,
    /// Effective inode count used for the inode field / bitmap.
    pub total_inodes: usize,
}

/// Build a signed+encrypted SD PFS image from `input` (a directory), writing
/// the image to `output` and the sealed key to `output.bin`.
pub fn encrypt_dir(
    common: &CommonKeys,
    input: &Path,
    output: &Path,
    opts: &EncryptOptions,
) -> Result<EncryptStats> {
    let block_size = opts.block_size;
    if block_size == 0 || !block_size.is_power_of_two() {
        return Err(Error::Message(format!(
            "block size 0x{block_size:X} must be a non-zero power of two"
        )));
    }
    if !opts.auto_blocks && opts.total_blocks == 0 {
        return Err(Error::Message(
            "total_blocks must come from SAVEDATA_BLOCKS in param.sfo".into(),
        ));
    }

    let content_key_ver = sealedkey_to_content(opts.sealed_key_version);

    // --- Keys ---
    let ekpfs = match opts.ekpfs {
        Some(k) => k,
        None => rand_bytes()?,
    };
    let seed = match opts.seed {
        Some(s) => s,
        None => rand_bytes()?,
    };

    let content_key = common
        .get_sd_content_key(content_key_ver)
        .ok_or_else(|| Error::MissingKey(format!("sd_content_key_{content_key_ver}")))?;

    let mut keyset = TitleKeyset::new(FAKE_CONTENT_ID);
    keyset.mkey = Some(ekpfs);
    derive_sd_keys(&mut keyset, content_key, &seed)?;

    let hmac_key = keyset
        .sig_hmac_key
        .ok_or_else(|| Error::MissingKey("sig_hmac_key".into()))?;
    let tweak_key = keyset
        .enc_tweak_key
        .ok_or_else(|| Error::MissingKey("enc_tweak_key".into()))?;
    let data_key = keyset
        .enc_data_key
        .ok_or_else(|| Error::MissingKey("enc_data_key".into()))?;

    // --- Layout (fix-point so the image always fits) ---
    let (mut prepared, used_inodes) = prepare_nodes(input, opts)?;
    let total_inodes = opts.total_inodes.max(used_inodes as usize + 6);
    let (final_blocks, layout) = resolve_total_blocks(&prepared, opts, total_inodes)?;

    // --- Grow SAVEDATA_BLOCKS in param.sfo when the layout outgrew it ---
    if let Some(new_bytes) = patch_param_savedata_blocks(input, final_blocks)? {
        println!(
            "updating SAVEDATA_BLOCKS in {} to {final_blocks}",
            input.join("sce_sys").join("param.sfo").display()
        );
        if let Some(idx) = prepared
            .iter()
            .position(|n| n.path == input.join("sce_sys").join("param.sfo") && !n.is_dir)
        {
            let mut buf = new_bytes;
            buf.resize(prepared[idx].blocks as usize * block_size, 0);
            prepared[idx].data = buf;
        }
    }

    // --- Build the image (plaintext) ---
    let (image, stats) = assemble_image(
        &prepared,
        &layout,
        used_inodes,
        opts,
        &hmac_key,
        &seed,
        content_key_ver,
    )?;

    // --- Authenticate the header ---
    let image = write_authcode_to_image(image, &hmac_key, content_key_ver, common)?;

    // --- Backup header (copy of primary at backup_block) ---
    let image = write_backup_header(
        image,
        stats.backup_block,
        block_size,
        &hmac_key,
        content_key_ver,
        common,
    )?;

    // --- XTS-encrypt everything except block 0 and the backup block ---
    let image = xts_encrypt_image(
        image,
        stats.total_blocks as u64,
        stats.backup_block,
        block_size,
        &tweak_key,
        &data_key,
    )?;

    // --- Write outputs ---
    std::fs::write(output, &image)?;

    let sealed_iv = match opts.sealed_iv {
        Some(iv) => iv,
        None => rand_bytes()?,
    };
    let sealed = encrypt_sealed_key(common, opts.sealed_key_version, sealed_iv, &ekpfs)?;
    let bin_path = PathBuf::from(format!("{}.bin", output.display()));
    std::fs::write(&bin_path, sealed.to_bytes())?;

    println!("wrote {} ({} bytes)", output.display(), image.len());
    println!(
        "wrote sealed key {} (version {})",
        bin_path.display(),
        opts.sealed_key_version
    );
    Ok(stats)
}

// ---------------------------------------------------------------------------
// Node map / layout
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Node {
    ino: u32,
    parent: Option<u32>,
    is_dir: bool,
    children: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
struct FileMapping {
    ino: u32,
    parent: u32,
    blocks: Vec<u64>,
    block_count: u64,
    is_dir: bool,
    real_size: u64,
    /// Original (uncompressed) size when `compressed`; 0 otherwise.
    size_uncompressed: u64,
    /// File data is a PFSC blob (dinode flags include PFS_FILE_COMPRESSED).
    compressed: bool,
}

#[derive(Debug, Clone)]
struct InodeLayout {
    dinode_size: usize,
    inodes_per_block: usize,
    total_inode_bytes: usize,
    inode_field_blocks: u64,
    indirect_blocks_required: u64,
}

impl InodeLayout {
    fn calc(block_size: usize, total_inodes: usize) -> Self {
        let dinode_size = DINODE_HEADER_SIZE + SDINODE32_SIZE;
        let inodes_per_block = block_size / dinode_size;
        let total_inode_bytes = dinode_size * total_inodes;
        let inode_field_blocks = total_inode_bytes.div_ceil(block_size) as u64;

        let entries_per_indirect_block = block_size / SBLOCK32_SIZE;
        let indirect_blocks_required = if inode_field_blocks > PFS_DIRECT_BLOCK_MAX_COUNT as u64 {
            let remaining = inode_field_blocks - PFS_DIRECT_BLOCK_MAX_COUNT as u64;
            remaining.div_ceil(entries_per_indirect_block as u64)
        } else {
            0
        };

        Self {
            dinode_size,
            inodes_per_block,
            total_inode_bytes,
            inode_field_blocks,
            indirect_blocks_required,
        }
    }

    /// Byte offset within the inode field for a given inode number.
    /// Each block of inodes is padded to `block_size` so the reader's
    /// `idx1/idx2` lookup lands on the correct bytes.
    fn offset_for_ino(&self, ino: u32, block_size: usize) -> usize {
        let idx1 = ino as usize / self.inodes_per_block;
        let idx2 = ino as usize % self.inodes_per_block;
        idx1 * block_size + idx2 * self.dinode_size
    }
}

fn collect_paths(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    entries.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
    for e in entries {
        out.push(e.clone());
        if e.is_dir() {
            collect_paths(&e, out);
        }
    }
}

fn build_node_map(root: &Path) -> Result<(HashMap<PathBuf, Node>, u32)> {
    let mut nodes: HashMap<PathBuf, Node> = HashMap::new();

    let super_key = PathBuf::from("__SUPER__");
    nodes.insert(
        super_key,
        Node {
            ino: 0,
            parent: None,
            is_dir: true,
            children: vec![root.to_path_buf()],
        },
    );
    nodes.insert(
        root.to_path_buf(),
        Node {
            ino: 1,
            parent: Some(0),
            is_dir: true,
            children: Vec::new(),
        },
    );

    let mut all_paths = Vec::new();
    collect_paths(root, &mut all_paths);

    let mut inode_counter: u32 = 6;

    // Directories first (in sorted order), then files.
    for p in all_paths.iter().filter(|p| p.is_dir()) {
        let parent_key = p.parent().unwrap_or(root).to_path_buf();
        let parent_ino = nodes[&parent_key].ino;
        nodes.insert(
            p.clone(),
            Node {
                ino: inode_counter,
                parent: Some(parent_ino),
                is_dir: true,
                children: Vec::new(),
            },
        );
        nodes
            .get_mut(&parent_key)
            .ok_or_else(|| Error::Message("parent node missing".into()))?
            .children
            .push(p.clone());
        inode_counter += 1;
    }

    for p in all_paths.iter().filter(|p| p.is_file()) {
        let parent_key = p.parent().unwrap_or(root).to_path_buf();
        let parent_ino = nodes[&parent_key].ino;
        nodes.insert(
            p.clone(),
            Node {
                ino: inode_counter,
                parent: Some(parent_ino),
                is_dir: false,
                children: Vec::new(),
            },
        );
        nodes
            .get_mut(&parent_key)
            .ok_or_else(|| Error::Message("parent node missing".into()))?
            .children
            .push(p.clone());
        inode_counter += 1;
    }

    Ok((nodes, inode_counter))
}

// ---------------------------------------------------------------------------
// Node preparation (reads files, applies PFSC compression)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct PreparedNode {
    path: PathBuf,
    ino: u32,
    parent: u32,
    is_dir: bool,
    is_root_child: bool,
    /// Dirent blob (dirs) or (possibly compressed) file content, padded to full blocks.
    data: Vec<u8>,
    /// Number of full blocks occupied by `data`.
    blocks: u64,
    real_size: u64,
    size_uncompressed: u64,
    compressed: bool,
}

fn build_dir_entries(node: &Node, nodes: &HashMap<PathBuf, Node>) -> Vec<u8> {
    let mut entries: Vec<u8> = Vec::new();
    entries.extend(build_dirent(node.ino, PFS_ENTRY_CUR_DIR, "."));
    entries.extend(build_dirent(
        node.parent.unwrap_or(0),
        PFS_ENTRY_PARENT_DIR,
        "..",
    ));
    for child in &node.children {
        let child_node = &nodes[child];
        let entry_type = if child_node.is_dir {
            PFS_ENTRY_DIR
        } else {
            PFS_ENTRY_FILE
        };
        let name = child
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        entries.extend(build_dirent(child_node.ino, entry_type, &name));
    }
    entries
}

/// Read every user node from `root` and compute its final stored bytes
/// (dirent blob for directories, raw or PFSC-compressed content for files).
/// `sce_sys/param.sfo` is never compressed so it can be patched in place later.
fn prepare_nodes(root: &Path, opts: &EncryptOptions) -> Result<(Vec<PreparedNode>, u32)> {
    let (nodes, used_inodes) = build_node_map(root)?;
    let mut nodes_by_ino: Vec<(&PathBuf, &Node)> = nodes.iter().collect();
    nodes_by_ino.sort_by_key(|(_, n)| n.ino);

    let param_path = root.join("sce_sys").join("param.sfo");
    let mut out = Vec::new();
    for (path, node) in nodes_by_ino {
        if node.ino == 0 || node.ino == 1 {
            continue;
        }
        let raw = if node.is_dir {
            build_dir_entries(node, &nodes)
        } else {
            std::fs::read(path)?
        };
        let mut size_uncompressed = 0u64;
        let mut compressed = false;
        let mut content = raw.clone();
        if opts.compress_files && !node.is_dir && *path != param_path {
            let pfsc = pfsc_compress_data(&raw, opts.block_size)?;
            let pfsc_blocks = blocks_required(pfsc.len(), opts.block_size) as u64;
            if pfsc_blocks < blocks_required(raw.len(), opts.block_size) as u64 {
                size_uncompressed = raw.len() as u64;
                compressed = true;
                content = pfsc;
            }
        }
        let real_size = content.len();
        let blocks = blocks_required(real_size, opts.block_size) as u64;
        content.resize(blocks as usize * opts.block_size, 0);
        out.push(PreparedNode {
            path: path.clone(),
            ino: node.ino,
            parent: node.parent.unwrap_or(1),
            is_dir: node.is_dir,
            is_root_child: node.parent == Some(1),
            data: content,
            blocks,
            real_size: real_size as u64,
            size_uncompressed,
            compressed,
        });
    }
    Ok((out, used_inodes))
}

// ---------------------------------------------------------------------------
// Block layout (pure integer math, run to a fix-point over total_blocks)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Layout {
    total_blocks: usize,
    total_inodes: usize,
    inode_layout: InodeLayout,
    indirect_block: Option<u64>,
    inode_start: u64,
    inode_end: u64,
    backup_block: u64,
    blk_bitmap_bytes: usize,
    badblk_bitmap_bytes: usize,
    ino_bitmap_bytes: usize,
    block_addr_table_bytes: usize,
    blk_bitmap_blocks: usize,
    badblk_bitmap_blocks: usize,
    ino_bitmap_blocks: usize,
    block_addr_table_blocks: usize,
    blk_bitmap_start: u64,
    badblk_bitmap_start: u64,
    ino_bitmap_start: u64,
    block_addr_table_start: u64,
    super_root_block: u64,
    user_root_block: u64,
    user_root_blocks: u64,
    used_blocks: u64,
    /// Per-prepared-node list of data block numbers (may exclude the backup hole).
    files: Vec<Vec<u64>>,
    block_owner: HashMap<u64, u32>,
}

/// Number of S32 indirect entries that fit in one block.
fn indirect_entries_per_block(block_size: usize) -> usize {
    block_size / SBLOCK32_SIZE
}

/// Indirect-table shape for a file's data-block count.
///
/// Returns `(u0_count, l1_needed)`: the number of level-0 tables required for
/// the tail past `PFS_DIRECT_BLOCK_MAX_COUNT`, and whether a single level-1
/// table is needed to reference the extra level-0 tables.
fn indirect_shape(blocks: u64, per: usize) -> (usize, bool) {
    if blocks <= PFS_DIRECT_BLOCK_MAX_COUNT as u64 {
        return (0, false);
    }
    let tail = blocks - PFS_DIRECT_BLOCK_MAX_COUNT as u64;
    let u0 = tail.div_ceil(per as u64) as usize;
    (u0, u0 > 1)
}

fn compute_layout(
    prepared: &[PreparedNode],
    total_blocks: usize,
    total_inodes: usize,
    block_size: usize,
) -> Result<Layout> {
    let inode_layout = InodeLayout::calc(block_size, total_inodes);

    let mut current_block: u64 = 1; // block 0 is the header
    let mut indirect_block: Option<u64> = None;
    if inode_layout.indirect_blocks_required > 0 {
        indirect_block = Some(current_block);
        current_block += 1;
    }

    let inode_blocks = inode_layout.inode_field_blocks;
    let inode_start = current_block;
    let inode_end = inode_start + inode_blocks - 1;
    current_block += inode_blocks;

    let backup_block =
        (calculate_backup_header_offset(total_blocks, block_size)? / block_size) as u64;

    let blk_bitmap_bytes = bitmap_size(total_blocks);
    let badblk_bitmap_bytes = bitmap_size(total_blocks);
    let ino_bitmap_bytes = bitmap_size(total_inodes);
    let block_addr_table_bytes = total_blocks * 4;

    let blk_bitmap_blocks = blocks_required(blk_bitmap_bytes, block_size);
    let badblk_bitmap_blocks = blocks_required(badblk_bitmap_bytes, block_size);
    let ino_bitmap_blocks = blocks_required(ino_bitmap_bytes, block_size);
    let block_addr_table_blocks = blocks_required(block_addr_table_bytes, block_size);

    let blk_bitmap_start = current_block;
    current_block += blk_bitmap_blocks as u64;
    let badblk_bitmap_start = current_block;
    current_block += badblk_bitmap_blocks as u64;
    let ino_bitmap_start = current_block;
    current_block += ino_bitmap_blocks as u64;
    let block_addr_table_start = current_block;
    current_block += block_addr_table_blocks as u64;

    let super_root_block = current_block;
    current_block += 1;
    let user_root_block = current_block;

    let uroot_len = uroot_entries_len(prepared);
    let user_root_blocks = blocks_required(uroot_len, block_size) as u64;

    let mut block_owner: HashMap<u64, u32> = HashMap::new();
    block_owner.insert(backup_block, 0);
    block_owner.insert(super_root_block, 0);
    for b in user_root_block..user_root_block + user_root_blocks {
        block_owner.insert(b, 1);
    }
    for b in blk_bitmap_start..blk_bitmap_start + blk_bitmap_blocks as u64 {
        block_owner.insert(b, 2);
    }
    for b in badblk_bitmap_start..badblk_bitmap_start + badblk_bitmap_blocks as u64 {
        block_owner.insert(b, 3);
    }
    for b in ino_bitmap_start..ino_bitmap_start + ino_bitmap_blocks as u64 {
        block_owner.insert(b, 4);
    }
    for b in block_addr_table_start..block_addr_table_start + block_addr_table_blocks as u64 {
        block_owner.insert(b, 5);
    }

    let mut used_blocks = user_root_block + user_root_blocks;
    let mut files = Vec::with_capacity(prepared.len());
    for n in prepared {
        // Allocate the file's data blocks, carving the backup-header block out
        // of the allocatable range (a file's block list may then be split
        // around the hole).
        let mut blocks = Vec::with_capacity(n.blocks as usize);
        for _ in 0..n.blocks {
            if used_blocks == backup_block {
                used_blocks += 1;
            }
            blocks.push(used_blocks);
            used_blocks += 1;
        }
        for &b in &blocks {
            block_owner.insert(b, n.ino);
        }
        files.push(blocks);
    }

    Ok(Layout {
        total_blocks,
        total_inodes,
        inode_layout,
        indirect_block,
        inode_start,
        inode_end,
        backup_block,
        blk_bitmap_bytes,
        badblk_bitmap_bytes,
        ino_bitmap_bytes,
        block_addr_table_bytes,
        blk_bitmap_blocks,
        badblk_bitmap_blocks,
        ino_bitmap_blocks,
        block_addr_table_blocks,
        blk_bitmap_start,
        badblk_bitmap_start,
        ino_bitmap_start,
        block_addr_table_start,
        super_root_block,
        user_root_block,
        user_root_blocks,
        used_blocks,
        files,
        block_owner,
    })
}

/// Byte length of the user-root directory dirent blob: "." + ".." plus one
/// entry per top-level node.
fn uroot_entries_len(prepared: &[PreparedNode]) -> usize {
    let mut len = build_dirent(1, PFS_ENTRY_CUR_DIR, ".").len()
        + build_dirent(1, PFS_ENTRY_PARENT_DIR, "..").len();
    for n in prepared.iter().filter(|n| n.is_root_child) {
        let name = n
            .path
            .file_name()
            .map(|nn| nn.to_string_lossy().into_owned())
            .unwrap_or_default();
        let entry_type = if n.is_dir {
            PFS_ENTRY_DIR
        } else {
            PFS_ENTRY_FILE
        };
        len += build_dirent(n.ino, entry_type, &name).len();
    }
    len
}

/// Build the user-root dirent blob.
fn build_uroot_entries(prepared: &[PreparedNode]) -> Vec<u8> {
    let mut uroot_entries: Vec<u8> = Vec::with_capacity(uroot_entries_len(prepared));
    uroot_entries.extend(build_dirent(1, PFS_ENTRY_CUR_DIR, "."));
    uroot_entries.extend(build_dirent(1, PFS_ENTRY_PARENT_DIR, ".."));
    for n in prepared {
        if n.is_root_child {
            let entry_type = if n.is_dir {
                PFS_ENTRY_DIR
            } else {
                PFS_ENTRY_FILE
            };
            let name = n
                .path
                .file_name()
                .map(|nn| nn.to_string_lossy().into_owned())
                .unwrap_or_default();
            uroot_entries.extend(build_dirent(n.ino, entry_type, &name));
        }
    }
    uroot_entries
}

const MAX_TOTAL_BLOCKS: usize = 32768;

/// Find the smallest `total_blocks` (>= `opts.total_blocks`) that fits the
/// contents. In auto mode this grows as far as needed; otherwise it errors when
/// the given total is too small — matching the historical behavior.
fn resolve_total_blocks(
    prepared: &[PreparedNode],
    opts: &EncryptOptions,
    total_inodes: usize,
) -> Result<(usize, Layout)> {
    let mut total_blocks = if opts.auto_blocks {
        opts.total_blocks.max(96)
    } else {
        opts.total_blocks
    };
    if total_blocks > MAX_TOTAL_BLOCKS {
        return Err(Error::Message(format!(
            "total_blocks {total_blocks} exceeds the PS4 maximum of {MAX_TOTAL_BLOCKS}"
        )));
    }
    loop {
        let layout = compute_layout(prepared, total_blocks, total_inodes, opts.block_size)?;
        // Indirect tables are appended past used_blocks during assembly: one
        // level-0 table per 910 tail entries, plus a single level-1 table once
        // the tail needs more than one level-0 table.
        let per = indirect_entries_per_block(opts.block_size);
        let indirect_extra: u64 = prepared
            .iter()
            .filter(|n| !n.is_dir && n.blocks > PFS_DIRECT_BLOCK_MAX_COUNT as u64)
            .map(|n| {
                let (u0, l1) = indirect_shape(n.blocks, per);
                (u0 + usize::from(l1)) as u64
            })
            .sum();
        let need = layout.used_blocks + indirect_extra;
        if need <= total_blocks as u64 {
            return Ok((total_blocks, layout));
        }
        if !opts.auto_blocks {
            return Err(Error::Message(format!(
                "layout requires {need} blocks but total_blocks is only {total_blocks}"
            )));
        }
        total_blocks = need as usize;
        if total_blocks > MAX_TOTAL_BLOCKS {
            return Err(Error::Message(format!(
                "layout requires {need} blocks but the PS4 maximum is {MAX_TOTAL_BLOCKS}"
            )));
        }
    }
}

// ---------------------------------------------------------------------------
// Image assembly
// ---------------------------------------------------------------------------

/// Split a block list for a single-level inode (native layout): the first
/// block becomes the indirect pointer and the next 12 stay direct. Directories
/// and system files never exceed two levels.
fn single_indirect_split(blocks: &[u64]) -> (Vec<u64>, Vec<u64>) {
    if blocks.len() > PFS_DIRECT_BLOCK_MAX_COUNT {
        (
            blocks[1..=PFS_DIRECT_BLOCK_MAX_COUNT].to_vec(),
            vec![blocks[0]],
        )
    } else {
        (blocks.to_vec(), Vec::new())
    }
}

#[allow(clippy::too_many_arguments)]
fn assemble_image(
    prepared: &[PreparedNode],
    layout: &Layout,
    used_inodes: u32,
    opts: &EncryptOptions,
    hmac_key: &[u8; HMAC_KEY_SIZE],
    seed: &[u8; SEED_SIZE],
    content_key_ver: u32,
) -> Result<(Vec<u8>, EncryptStats)> {
    let block_size = opts.block_size;
    let total_blocks = layout.total_blocks;
    let total_inodes = layout.total_inodes;
    let inode_layout = &layout.inode_layout;
    let per = indirect_entries_per_block(block_size);

    let mut block_owner: HashMap<u64, u32> = layout.block_owner.clone();
    let image_size = total_blocks * block_size;

    // --- Indirect block assignment (must be stable before the block address
    // table is serialized, since indirect-addressed data blocks are encoded in
    // it as `0x80000000 | indirect_block_no`, matching the console). The order
    // stored per file is [u0#1, u0#2, ..., u0#N, u1?]: u0 #1 is referenced by
    // the inode's Indirect[0], the later u0s by the level-1 table, which is
    // referenced by Indirect[1]. ---
    let mut indirect_assignment: HashMap<u32, Vec<u64>> = HashMap::new();
    {
        let mut used_blocks = layout.used_blocks;
        for (n, blocks) in prepared.iter().zip(&layout.files) {
            let (u0_count, l1) = indirect_shape(blocks.len() as u64, per);
            if u0_count > 0 {
                if u0_count > per {
                    return Err(Error::Message(format!(
                        "inode {} needs more than two levels of indirection",
                        n.ino
                    )));
                }
                let count = u0_count + usize::from(l1);
                let mut iblocks = Vec::with_capacity(count);
                for _ in 0..count {
                    let mut ib = used_blocks;
                    if ib == layout.backup_block {
                        ib += 1;
                    }
                    used_blocks = ib + 1;
                    block_owner.insert(ib, n.ino);
                    iblocks.push(ib);
                }
                indirect_assignment.insert(n.ino, iblocks);
            }
        }
    }

    // --- Bitmaps + block address table ---
    let mut allocated_blocks: std::collections::HashSet<u64> = (0..layout.used_blocks).collect();
    allocated_blocks.insert(layout.backup_block);
    // Indirect blocks are allocated during assembly (they are the first blocks
    // past used_blocks); they must be flagged in the bitmap too or the kernel
    // will treat the live indirect tables as free space on save.
    allocated_blocks.extend(indirect_assignment.values().flatten().copied());

    let mut blk_bitmap = vec![0u8; layout.blk_bitmap_bytes];
    for bit in allocated_blocks {
        blk_bitmap[bit as usize / 8] |= 1 << (7 - (bit as usize % 8));
    }

    let mut allocated_inodes: std::collections::HashSet<u32> =
        prepared.iter().map(|n| n.ino).collect();
    // Console marks the full 0..=N prefix: super root (0) and user root (1)
    // live in the inode field but have no dirent, so they must be added here.
    allocated_inodes.extend([0, 1, 2, 3, 4, 5]);

    let mut ino_bitmap = vec![0u8; layout.ino_bitmap_bytes];
    for bit in allocated_inodes {
        ino_bitmap[bit as usize / 8] |= 1 << (7 - (bit as usize % 8));
    }

    let mut bat = vec![0u8; layout.block_addr_table_bytes];
    for (block, ino) in &block_owner {
        let off = (*block as usize) * 4;
        bat[off..off + 4].copy_from_slice(&ino.to_le_bytes());
    }
    // Indirect-addressed data blocks are tagged with their parent indirect
    // block number in the high bits (console encoding).
    for (n, blocks) in prepared.iter().zip(&layout.files) {
        if let Some(iblocks) = indirect_assignment.get(&n.ino) {
            let marker = 0x8000_0000u32 | (iblocks[0] as u32);
            for db in &blocks[PFS_DIRECT_BLOCK_MAX_COUNT..] {
                let off = (*db as usize) * 4;
                bat[off..off + 4].copy_from_slice(&marker.to_le_bytes());
            }
        }
    }

    // --- Root directory entries ---
    let super_raw: Vec<u8> = [
        (1u32, PFS_ENTRY_DIR, "uroot"),
        (2, PFS_ENTRY_FILE, "blk_bitmap"),
        (3, PFS_ENTRY_FILE, "badblk_bitmap"),
        (4, PFS_ENTRY_FILE, "ino_bitmap"),
        (5, PFS_ENTRY_FILE, "block_addr_table"),
    ]
    .iter()
    .flat_map(|(ino, ty, name)| build_dirent(*ino, *ty, name))
    .collect();
    let super_blocks = blocks_required(super_raw.len(), block_size);

    let mut uroot_entries: Vec<u8> = build_uroot_entries(prepared);

    // --- Assemble the plaintext image ---
    let mut image = vec![0u8; image_size];

    let (sr, ur) = (layout.super_root_block as usize, layout.user_root_block as usize);
    image[sr * block_size..sr * block_size + super_raw.len()].copy_from_slice(&super_raw);
    let uroot_start = ur * block_size;
    let uroot_end = uroot_start + layout.user_root_blocks as usize * block_size;
    uroot_entries.resize(uroot_end - uroot_start, 0);
    image[uroot_start..uroot_end].copy_from_slice(&uroot_entries);

    let mut file_mappings: Vec<FileMapping> = Vec::new();
    for (n, blocks) in prepared.iter().zip(&layout.files) {
        for (i, &b) in blocks.iter().enumerate() {
            let off = b as usize * block_size;
            image[off..off + block_size]
                .copy_from_slice(&n.data[i * block_size..(i + 1) * block_size]);
        }
        file_mappings.push(FileMapping {
            ino: n.ino,
            parent: n.parent,
            blocks: blocks.clone(),
            block_count: n.blocks,
            is_dir: n.is_dir,
            real_size: n.real_size,
            size_uncompressed: n.size_uncompressed,
            compressed: n.compressed,
        });
    }

    let (bb, ib, batb) = (
        layout.blk_bitmap_start as usize,
        layout.ino_bitmap_start as usize,
        layout.block_addr_table_start as usize,
    );
    image[bb * block_size..bb * block_size + blk_bitmap.len()].copy_from_slice(&blk_bitmap);
    image[ib * block_size..ib * block_size + ino_bitmap.len()].copy_from_slice(&ino_bitmap);
    image[batb * block_size..batb * block_size + bat.len()].copy_from_slice(&bat);
    // badblk bitmap is left as zeros.

    let inode_field_offset = layout.inode_start * block_size as u64;

    // --- Inodes ---
    let (super_direct, super_indirect) = single_indirect_split(&[layout.super_root_block]);
    let super_inode = inode_write(
        InodeType::S32,
        super_blocks as u64 * block_size as u64,
        &super_direct,
        &super_indirect,
        MODE_DIR_SUPER,
        1,
        FLAGS_ROOT,
        &image,
        block_size,
        hmac_key,
        0,
        false,
        None,
        None,
    )?;
    let off = inode_field_offset as usize + inode_layout.offset_for_ino(0, block_size);
    image[off..off + inode_layout.dinode_size].copy_from_slice(&super_inode);

    let uroot_subdirs = prepared
        .iter()
        .filter(|n| n.parent == 1 && n.is_dir)
        .count() as u16;
    let uroot_blocks = layout.user_root_blocks;
    let (uroot_direct, uroot_indirect) = single_indirect_split(
        &(layout.user_root_block..layout.user_root_block + uroot_blocks).collect::<Vec<u64>>(),
    );
    let uroot_inode = inode_write(
        InodeType::S32,
        uroot_blocks * block_size as u64,
        &uroot_direct,
        &uroot_indirect,
        MODE_DIR_SUPER,
        // Console: user root's ".." is a self-reference (inode 1), so it gets
        // 3 + subdirs (parent entry, ".", self-"..") instead of the usual 2.
        3 + uroot_subdirs,
        FLAGS_ROOT,
        &image,
        block_size,
        hmac_key,
        0,
        false,
        None,
        None,
    )?;
    let off = inode_field_offset as usize + inode_layout.offset_for_ino(1, block_size);
    image[off..off + inode_layout.dinode_size].copy_from_slice(&uroot_inode);

    let root_files = [
        (
            2u32,
            layout.blk_bitmap_start,
            layout.blk_bitmap_blocks,
            layout.blk_bitmap_bytes,
        ),
        (
            3,
            layout.badblk_bitmap_start,
            layout.badblk_bitmap_blocks,
            layout.badblk_bitmap_bytes,
        ),
        (
            4,
            layout.ino_bitmap_start,
            layout.ino_bitmap_blocks,
            layout.ino_bitmap_bytes,
        ),
        (
            5,
            layout.block_addr_table_start,
            layout.block_addr_table_blocks,
            layout.block_addr_table_bytes,
        ),
    ];

    for (ino, blk_start, blk_count, byte_size) in root_files {
        let blocks_list: Vec<u64> = (blk_start..blk_start + blk_count as u64).collect();
        let (direct_blocks, indirect_blocks) = single_indirect_split(&blocks_list);
        let inode_bytes = inode_write(
            InodeType::S32,
            byte_size as u64,
            &direct_blocks,
            &indirect_blocks,
            MODE_FILE,
            1,
            FLAGS_ROOT,
            &image,
            block_size,
            hmac_key,
            0,
            false,
            None,
            None,
        )?;
        let off = inode_field_offset as usize + inode_layout.offset_for_ino(ino, block_size);
        image[off..off + inode_layout.dinode_size].copy_from_slice(&inode_bytes);
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let timestamps = [now, now, now, now];
    let mut mappings = std::mem::take(&mut file_mappings);
    let mut used_blocks = layout.used_blocks;
    for m in &mut mappings {
        let mut direct_blocks: Vec<u64> = m.blocks.clone();
        let mut indirect_blocks: Vec<u64> = Vec::new();
        if m.blocks.len() > PFS_DIRECT_BLOCK_MAX_COUNT {
            // Tail past the 12 direct blocks is addressed by level-0 tables.
            // One level-0 table per indirect-block entry, chained by a single
            // level-1 table referenced from the inode's Indirect[1].
            direct_blocks = m.blocks[..PFS_DIRECT_BLOCK_MAX_COUNT].to_vec();
            let tail = &m.blocks[PFS_DIRECT_BLOCK_MAX_COUNT..];
            let (u0_count, l1) = indirect_shape(m.blocks.len() as u64, per);
            let iblocks = indirect_assignment[&m.ino].clone();

            // Write the level-0 tables first: the level-1 table digests their
            // (already serialized) block contents.
            let mut offset = 0usize;
            for i in 0..u0_count {
                let end = (offset + per).min(tail.len());
                let content = build_indirect_block(&tail[offset..end], &image, block_size, hmac_key);
                let blk = iblocks[i] as usize * block_size;
                image[blk..blk + content.len()].copy_from_slice(&content);
                offset = end;
            }
            if l1 {
                let u1_blk = iblocks[u0_count];
                let content =
                    build_indirect_block(&iblocks[1..u0_count], &image, block_size, hmac_key);
                let blk = u1_blk as usize * block_size;
                image[blk..blk + content.len()].copy_from_slice(&content);
                indirect_blocks = vec![iblocks[0], u1_blk];
            } else {
                indirect_blocks = vec![iblocks[0]];
            }
            used_blocks = used_blocks.max(*iblocks.last().unwrap() + 1);
        }

        let (link_count, mode) = if m.is_dir {
            let subdirs = prepared
                .iter()
                .filter(|n| n.parent == m.ino && n.is_dir)
                .count() as u16;
            (2 + subdirs, MODE_DIR_USER)
        } else {
            (1, MODE_FILE)
        };

        // Console: regular files that live directly under the user root carry
        // flags 0xC; everything else (dirs, files in subdirs like sce_sys) uses
        // FLAGS_USER (0x2000C).
        let flags = if !m.is_dir && m.parent == 1 {
            FLAGS_USER_FILE
        } else {
            FLAGS_USER
        };

        let size = if m.is_dir {
            m.block_count * block_size as u64
        } else {
            m.real_size
        };

        let inode_bytes = inode_write(
            InodeType::S32,
            size,
            &direct_blocks,
            &indirect_blocks,
            mode,
            link_count,
            flags,
            &image,
            block_size,
            hmac_key,
            m.size_uncompressed,
            m.compressed,
            Some(m.blocks.len() as u64),
            Some(&timestamps),
        )?;
        let off = inode_field_offset as usize + inode_layout.offset_for_ino(m.ino, block_size);
        image[off..off + inode_layout.dinode_size].copy_from_slice(&inode_bytes);
    }

    // --- Header inode (SDINODE64, points at the inode field blocks) ---
    let field_blocks: Vec<u64> = (layout.inode_start..=layout.inode_end).collect();
    let (header_direct_blocks, header_indirect_blocks) =
        if inode_layout.indirect_blocks_required > 0 {
        let indirect_data_blocks = field_blocks[PFS_DIRECT_BLOCK_MAX_COUNT..].to_vec();
        let direct_blocks = field_blocks[..PFS_DIRECT_BLOCK_MAX_COUNT].to_vec();

        let mut entries: Vec<u8> = Vec::new();
        for blk in &indirect_data_blocks {
            let block_data = &image[*blk as usize * block_size..(*blk as usize + 1) * block_size];
            let digest = hmac_sha256(hmac_key, block_data);
            let mut entry = digest.to_vec();
            entry.extend_from_slice(&(*blk as u32).to_le_bytes());
            entries.extend_from_slice(&entry);
        }

        let ib = layout.indirect_block.unwrap() as usize;
        image[ib * block_size..ib * block_size + entries.len()].copy_from_slice(&entries);
        (direct_blocks, vec![layout.indirect_block.unwrap()])
    } else {
        (field_blocks, Vec::new())
    };

    // build_header reads total_blocks/inodes from opts; feed it the effective
    // values so the header matches the resized image.
    let mut eff_opts = opts.clone();
    eff_opts.total_blocks = total_blocks;
    eff_opts.total_inodes = total_inodes;
    let header = build_header(
        &eff_opts,
        &image,
        inode_layout.inode_field_blocks,
        inode_layout.total_inode_bytes as u64,
        &header_direct_blocks,
        &header_indirect_blocks,
        seed,
        content_key_ver,
        hmac_key,
    )?;
    image[..header.len()].copy_from_slice(&header);

    let stats = EncryptStats {
        used_blocks,
        used_inodes,
        image_size,
        backup_block: layout.backup_block,
        total_blocks,
        total_inodes,
    };
    Ok((image, stats))
}

/// Updating SAVEDATA_BLOCKS in the on-disk `sce_sys/param.sfo`.
///
/// Grow-only: the value is only raised when the layout outgrows it. Returns the
/// patched param.sfo bytes when it changed (so the caller can mirror the patch
/// into the plaintext image), or `None` when nothing changed / key is missing.
fn patch_param_savedata_blocks(input: &Path, new_blocks: usize) -> Result<Option<Vec<u8>>> {
    let sfo_path = input.join("sce_sys").join("param.sfo");
    if !sfo_path.exists() {
        return Ok(None);
    }
    let sfo = std::fs::read(&sfo_path)?;
    let Some(current) = crate::sfo::read_savedata_blocks(&sfo)? else {
        eprintln!("warning: param.sfo has no SAVEDATA_BLOCKS, cannot update it");
        return Ok(None);
    };
    if (new_blocks as u64) <= current {
        return Ok(None); // grow-only
    }
    let Some(patched) = crate::sfo::patch_savedata_blocks(&sfo, new_blocks as u64)? else {
        return Ok(None);
    };
    std::fs::write(&sfo_path, &patched)?;
    Ok(Some(patched))
}
// ---------------------------------------------------------------------------
// Header, inodes, dirents, auth
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn build_header(
    opts: &EncryptOptions,
    image: &[u8],
    inode_blocks: u64,
    total_inode_bytes: u64,
    header_direct_blocks: &[u64],
    header_indirect_blocks: &[u64],
    seed: &[u8; SEED_SIZE],
    content_key_ver: u32,
    hmac_key: &[u8; HMAC_KEY_SIZE],
) -> Result<Vec<u8>> {
    let mut header = vec![0u8; 0x5A0];

    put_u64(&mut header, 0x00, PFS_VERSION);
    put_u64(&mut header, 0x08, PFS_MAGIC);
    put_u16(&mut header, 0x1C, PFS_MODE);
    put_u32(&mut header, 0x20, opts.block_size as u32);
    put_u32(&mut header, 0x24, 1); // nbackup
    put_u64(&mut header, 0x28, 1); // nblock
    put_u64(&mut header, 0x30, opts.total_inodes as u64);
    put_u64(&mut header, 0x38, opts.total_blocks as u64); // block_count
    put_u64(&mut header, 0x40, inode_blocks);
    put_u64(&mut header, 0x48, 0); // super root index

    let header_inode = inode_write(
        InodeType::S64,
        total_inode_bytes,
        header_direct_blocks,
        header_indirect_blocks,
        0,
        1,
        FLAGS_ROOT,
        image,
        opts.block_size,
        hmac_key,
        0,
        false,
        Some(inode_blocks),
        None,
    )?;
    header[0x50..0x50 + header_inode.len()].copy_from_slice(&header_inode);

    put_u32(&mut header, 0x36C, content_key_ver);
    header[0x370..0x370 + SEED_SIZE].copy_from_slice(seed);

    Ok(header)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InodeType {
    S32,
    S64,
}

/// Build a complete pfs_dinode (header + sdinode block info).
#[allow(clippy::too_many_arguments)]
fn inode_write(
    inode_type: InodeType,
    size: u64,
    direct_blocks: &[u64],
    indirect_blocks: &[u64],
    mode: u16,
    link_count: u16,
    flags: u32,
    image: &[u8],
    block_size: usize,
    hmac_key: &[u8],
    size_uncompressed: u64,
    compressed: bool,
    logical_block_count: Option<u64>,
    timestamps: Option<&[u64; 4]>, // atime, mtime, ctime, birthtime
) -> Result<Vec<u8>> {
    let (is_64, sdi_size, sblock_size) = match inode_type {
        InodeType::S64 => (true, SDINODE64_SIZE, SBLOCK64_SIZE),
        InodeType::S32 => (false, SDINODE32_SIZE, SBLOCK32_SIZE),
    };

    let blk_count = logical_block_count.unwrap_or(direct_blocks.len() as u64);

    let mut flags = flags;
    if compressed {
        flags |= PFS_FILE_COMPRESSED;
    }

    let mut hdr = vec![0u8; DINODE_HEADER_SIZE];
    put_u16(&mut hdr, 0x00, mode);
    put_u16(&mut hdr, 0x02, link_count);
    put_u32(&mut hdr, 0x04, flags);
    put_u64(&mut hdr, 0x08, size);
    if compressed {
        put_u64(&mut hdr, 0x10, size_uncompressed);
    }
    if let Some(ts) = timestamps {
        put_u64(&mut hdr, 0x18, ts[0]);
        put_u64(&mut hdr, 0x20, ts[1]);
        put_u64(&mut hdr, 0x28, ts[2]);
        put_u64(&mut hdr, 0x30, ts[3]);
    }

    let mut sdi = vec![0u8; sdi_size];
    let mut offset = if is_64 {
        sdi[..8].copy_from_slice(&blk_count.to_le_bytes());
        8
    } else {
        sdi[..4].copy_from_slice(&(blk_count as u32).to_le_bytes());
        4
    };

    // Direct block entries.
    for i in 0..PFS_DIRECT_BLOCK_MAX_COUNT {
        if i < direct_blocks.len() {
            let entry = build_sblock(inode_type, direct_blocks[i], image, block_size, hmac_key)?;
            sdi[offset..offset + entry.len()].copy_from_slice(&entry);
        }
        offset += sblock_size;
    }

    // Indirect block entries.
    for i in 0..5 {
        if i < indirect_blocks.len() {
            let entry = build_sblock(inode_type, indirect_blocks[i], image, block_size, hmac_key)?;
            sdi[offset..offset + entry.len()].copy_from_slice(&entry);
        }
        offset += sblock_size;
    }

    let mut out = hdr;
    out.extend_from_slice(&sdi);
    Ok(out)
}

fn build_sblock(
    inode_type: InodeType,
    block_no: u64,
    image: &[u8],
    block_size: usize,
    hmac_key: &[u8],
) -> Result<Vec<u8>> {
    let start = block_no as usize * block_size;
    let end = start + block_size;
    if end > image.len() {
        return Err(Error::Message(format!(
            "block {block_no} out of range for inode sblock"
        )));
    }
    let digest = hmac_sha256(hmac_key, &image[start..end]);
    let mut entry = digest.to_vec();
    match inode_type {
        InodeType::S32 => entry.extend_from_slice(&(block_no as u32).to_le_bytes()),
        InodeType::S64 => entry.extend_from_slice(&block_no.to_le_bytes()),
    }
    Ok(entry)
}

fn build_indirect_block(
    data_blocks: &[u64],
    image: &[u8],
    block_size: usize,
    hmac_key: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(data_blocks.len() * SBLOCK32_SIZE);
    for blk in data_blocks {
        let start = *blk as usize * block_size;
        let digest = hmac_sha256(hmac_key, &image[start..start + block_size]);
        out.extend_from_slice(&digest);
        out.extend_from_slice(&(*blk as u32).to_le_bytes());
    }
    out
}

fn build_dirent(ino: u32, entry_type: u32, name: &str) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let namelen = name_bytes.len();
    let raw = 16 + namelen + 1;
    let entsize = align_u64(raw as u64) as usize;
    let padding = entsize - raw;

    let mut data = Vec::with_capacity(entsize);
    data.extend_from_slice(&ino.to_le_bytes());
    data.extend_from_slice(&entry_type.to_le_bytes());
    data.extend_from_slice(&(namelen as u32).to_le_bytes());
    data.extend_from_slice(&(entsize as u32).to_le_bytes());
    data.extend_from_slice(name_bytes);
    data.push(0);
    data.extend(std::iter::repeat_n(0, padding));
    data
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

pub fn write_authcode_to_image(
    mut image: Vec<u8>,
    sign_key: &[u8; HASH_SIZE],
    content_key_ver: u32,
    common: &CommonKeys,
) -> Result<Vec<u8>> {
    // 1. header_hash (always) — covers 0..0x380, does not include sd_info
    let mut cover = vec![0u8; 0x5A0];
    cover[..PFS_HEADER_COVER_SIZE_FOR_ICV].copy_from_slice(&image[..PFS_HEADER_COVER_SIZE_FOR_ICV]);
    let header_hash = hmac_sha256(sign_key, &cover);
    image[0x380..0x3A0].copy_from_slice(&header_hash);

    // 2. authcode (ver >= 2) — its ciphertext tail (0x7FF0..0x8000) seeds the
    //    sd_info CBC-CT IV, so it must be written before step 3.
    if content_key_ver >= 2 {
        write_authcode(&mut image, &header_hash, common)?;
    }

    // 3. sd_info_data — the region is CBC-CTS-encrypted with sd_hdr_data_key
    //    using the last 16 bytes of the basic block as IV. Store a validly
    //    encrypted blank so it decrypts to zeros (matching native re-saves),
    //    instead of raw zeroed ciphertext that decrypts to garbage fields.
    if content_key_ver >= 3 {
        let data_key = common
            .sd_hdr_data_key
            .as_ref()
            .ok_or_else(|| Error::MissingKey("sd_hdr_data_key".into()))?;
        let mut iv = [0u8; 16];
        let tail = 0x8000usize;
        iv.copy_from_slice(&image[tail - 16..tail]);

        let plain = vec![0u8; SD_INFO_SIZE];
        let mut cipher = vec![0u8; SD_INFO_SIZE];
        let mut iv_enc = iv;
        aes_encrypt_cbc_cts(data_key, Some(&mut iv_enc), &plain, &mut cipher)?;
        image[0x3A0..0x3A0 + SD_INFO_SIZE].copy_from_slice(&cipher);
    }

    // 4. bottom_signature (ver >= 3) — covers 0..0x580 including sd_info
    if content_key_ver >= 3 {
        let sig_key = common
            .sd_hdr_sig_key
            .as_ref()
            .ok_or_else(|| Error::MissingKey("sd_hdr_sig_key".into()))?;
        let bottom = hmac_sha256(sig_key, &image[..PFS_SD_HEADER_SIZE]);
        image[0x580..0x5A0].copy_from_slice(&bottom);
    }

    Ok(image)
}

/// Re-run header authentication on a fresh (already-written) image where the
/// caller only changed the account ID and the PFS sblock digest chain. This
/// keeps sd_info data untouched (preserving the original layout) and
/// recomputes header_hash, authcode, and bottom_signature.
pub fn reauth_header_block(
    image: &mut [u8],
    sign_key: &[u8; HASH_SIZE],
    content_key_ver: u32,
    common: &CommonKeys,
) -> Result<()> {
    let mut cover = vec![0u8; 0x5A0];
    cover[..PFS_HEADER_COVER_SIZE_FOR_ICV].copy_from_slice(&image[..PFS_HEADER_COVER_SIZE_FOR_ICV]);
    let header_hash = hmac_sha256(sign_key, &cover);
    image[0x380..0x3A0].copy_from_slice(&header_hash);

    if content_key_ver >= 2 {
        write_authcode(image, &header_hash, common)?;
    }

    if content_key_ver >= 3 {
        let sig_key = common
            .sd_hdr_sig_key
            .as_ref()
            .ok_or_else(|| Error::MissingKey("sd_hdr_sig_key".into()))?;
        let bottom = hmac_sha256(sig_key, &image[..PFS_SD_HEADER_SIZE]);
        image[0x580..0x5A0].copy_from_slice(&bottom);
    }

    Ok(())
}

fn write_authcode(
    image: &mut [u8],
    header_hash: &[u8; HASH_SIZE],
    common: &CommonKeys,
) -> Result<()> {
    let auth_code_key = common
        .sd_auth_code_key
        .as_ref()
        .ok_or_else(|| Error::MissingKey("sd_auth_code_key".into()))?;

    put_u64(image, AUTHCODE_OFFSET, AUTHCODE_MAGIC);
    put_u32(image, AUTHCODE_OFFSET + 8, 1);
    put_u32(image, AUTHCODE_OFFSET + 12, 1);

    let iv: [u8; 16] = rand_bytes()?;
    image[0x7FA0..0x7FB0].copy_from_slice(&iv);

    let mut plain = vec![0u8; AUTHCODE_DATA_SIZE];
    plain[0x00..0x20].copy_from_slice(header_hash);
    plain[0x20..0x40].copy_from_slice(header_hash);
    plain[0x40..0x48].copy_from_slice(&1i64.to_le_bytes());

    let mut iv_enc = iv;
    let mut enc = vec![0u8; AUTHCODE_DATA_SIZE];
    aes_encrypt_cbc_cts(auth_code_key, Some(&mut iv_enc), &plain, &mut enc)?;
    image[0x7FB0..0x7FB0 + AUTHCODE_DATA_SIZE].copy_from_slice(&enc);
    Ok(())
}

// ---------------------------------------------------------------------------
// Backup header + encryption
// ---------------------------------------------------------------------------

fn write_backup_header(
    mut image: Vec<u8>,
    backup_block: u64,
    block_size: usize,
    _sign_key: &[u8; HASH_SIZE],
    content_key_ver: u32,
    common: &CommonKeys,
) -> Result<Vec<u8>> {
    let dst = backup_block as usize * block_size;
    if dst + 0x5A0 > image.len() {
        return Err(Error::Message("backup header out of range".into()));
    }

    // Copy the primary header fields (0..0x5A0) to the backup block.
    let header = image[..0x5A0].to_vec();
    image[dst..dst + 0x5A0].copy_from_slice(&header);

    // The backup header is independent of the primary: its sd_info is
    // encrypted under the backup block's own tail IV and its bottom
    // signature recomputed over the backup content (like the console).
    if content_key_ver >= 3 {
        if let Some(ref data_key) = common.sd_hdr_data_key {
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&image[dst + block_size - 16..dst + block_size]);

            let plain = vec![0u8; SD_INFO_SIZE];
            let mut cipher = vec![0u8; SD_INFO_SIZE];
            let mut iv_enc = iv;
            aes_encrypt_cbc_cts(data_key, Some(&mut iv_enc), &plain, &mut cipher)?;
            image[dst + 0x3A0..dst + 0x3A0 + SD_INFO_SIZE].copy_from_slice(&cipher);
        }

        let sig_key = common
            .sd_hdr_sig_key
            .as_ref()
            .ok_or_else(|| Error::MissingKey("sd_hdr_sig_key".into()))?;
        let bottom = hmac_sha256(sig_key, &image[dst..dst + PFS_SD_HEADER_SIZE]);
        image[dst + 0x580..dst + 0x5A0].copy_from_slice(&bottom);
    }

    Ok(image)
}

fn xts_encrypt_image(
    mut image: Vec<u8>,
    total_blocks: u64,
    backup_block: u64,
    block_size: usize,
    tweak_key: &[u8; AES_KEY_SIZE],
    data_key: &[u8; AES_KEY_SIZE],
) -> Result<Vec<u8>> {
    let dev = EncDecDevice::new(tweak_key, data_key, SECTOR_SIZE)?;

    let start_offset = block_size as u64; // skip block 0
    let end_offset = total_blocks * block_size as u64;

    if end_offset <= start_offset || end_offset > image.len() as u64 {
        return Err(Error::Message("encryption range out of bounds".into()));
    }

    // Encrypt sectors in two runs, skipping block 0 and the plaintext backup
    // header block (the SD must be able to locate the backup magic).
    let backup_start = backup_block * block_size as u64;
    let backup_end = backup_start + block_size as u64;

    let first_begin = start_offset as usize;
    let first_end = backup_start.clamp(start_offset, end_offset) as usize;
    if first_end > first_begin {
        dev.encrypt_inplace(&mut image[first_begin..first_end], start_offset / SECTOR_SIZE as u64)?;
    }

    let second_begin = backup_end.clamp(start_offset, end_offset) as usize;
    let second_end = end_offset as usize;
    if second_end > second_begin {
        dev.encrypt_inplace(
            &mut image[second_begin..second_end],
            backup_end / SECTOR_SIZE as u64,
        )?;
    }

    Ok(image)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn align_u64(v: u64) -> u64 {
    (v + (ALIGNMENT - 1)) & !(ALIGNMENT - 1)
}

fn blocks_required(size_bytes: usize, block_size: usize) -> usize {
    if size_bytes == 0 {
        return 1;
    }
    size_bytes.div_ceil(block_size)
}

fn bitmap_size(count: usize) -> usize {
    count.div_ceil(8)
}

fn sealedkey_to_content(sk_ver: u16) -> u32 {
    match sk_ver {
        1 | 2 => 1,
        3 => 2,
        4 => 3,
        5 => 4,
        6 => 5,
        7 => 6,
        8 => 7,
        9 => 8,
        10 => 9,
        _ => 9,
    }
}

fn calculate_backup_header_offset(block_cnt: usize, block_size: usize) -> Result<usize> {
    if !(96..=32768).contains(&block_cnt) {
        return Err(Error::Message(format!(
            "block_cnt {block_cnt} must be between 96-32768"
        )));
    }
    let (base, origin): (usize, usize) = if block_cnt < 10000 {
        (0x1F8000, 95)
    } else if block_cnt < 20001 {
        (0x9CC0000, 10000)
    } else if block_cnt < 30000 {
        (0x13908000, 20001)
    } else {
        (0x1D548000, 30000)
    };
    let index = (block_cnt - origin) / 2;
    Ok(base + index * block_size)
}

fn rand_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|e| Error::Message(format!("rng failure: {e}")))?;
    Ok(buf)
}

/// Compress a user file into a PFSC blob (header + block data + block table).
///
/// Layout (file-relative offsets, matching the C reader in pfs.c):
/// ```text
/// 0x00: pfsc_header (0x30)
/// 0x30: data block 0, block 1, ... (each compressed, or raw padded to block_size)
/// end : u64 table with `block_count` entries; the final entry equals the end of
///       the block data (== block_table_offset).
/// ```
/// A block is stored raw (padded to `block_size`) when compressing does not
/// shrink it; raw blocks always occupy exactly `block_size` bytes so the reader
/// can detect them via `compressed_size == block_size`.
fn pfsc_compress_data(data: &[u8], block_size: usize) -> Result<Vec<u8>> {
    if block_size == 0 {
        return Err(Error::Message("pfsc: block size must be non-zero".into()));
    }
    let n_blocks = data.len().div_ceil(block_size).max(1);
    let rounded = n_blocks * block_size;

    let mut blocks_out: Vec<Vec<u8>> = Vec::with_capacity(n_blocks);
    for i in 0..n_blocks {
        let start = i * block_size;
        let end = (start + block_size).min(data.len());
        let compressed = zlib_compress_window12(&data[start..end])?;
        if compressed.len() < block_size {
            blocks_out.push(compressed);
        } else {
            let mut raw = data[start..end].to_vec();
            raw.resize(block_size, 0);
            blocks_out.push(raw);
        }
    }

    let block_data_offset: u64 = PFSC_HEADER_SIZE as u64;
    let mut table: Vec<u64> = Vec::with_capacity(n_blocks + 1);
    let mut offset = block_data_offset;
    for b in &blocks_out {
        table.push(offset);
        offset += b.len() as u64;
    }
    table.push(offset); // end-of-data sentinel == block_table_offset

    let mut blob = vec![0u8; PFSC_HEADER_SIZE];
    put_u32(&mut blob, 0x00, PFSC_MAGIC);
    put_u32(&mut blob, 0x04, 1); // version
    put_u32(&mut blob, 0x08, 0);
    put_u32(&mut blob, 0x0C, block_size as u32);
    put_u32(&mut blob, 0x10, PFSC_ALIGNMENT);
    put_u32(&mut blob, 0x14, 0);
    put_u64(&mut blob, 0x18, offset);
    put_u64(&mut blob, 0x20, block_data_offset);
    put_u64(&mut blob, 0x28, rounded as u64);

    for b in &blocks_out {
        blob.extend_from_slice(b);
    }
    for e in &table {
        blob.extend_from_slice(&e.to_le_bytes());
    }
    Ok(blob)
}

/// zlib deflate with window bits = 12 (the PS4's PFSC setting).
fn zlib_compress_window12(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::{Compress, Compression, FlushCompress, Status};

    let mut compressor =
        Compress::new_with_window_bits(Compression::default(), true, PFSC_WINDOW_BITS);
    // Reserve enough for the worst case (deflate can slightly expand input);
    // `compress_vec` writes into spare capacity and does not grow the Vec.
    let mut out = Vec::with_capacity(data.len() + data.len() / 8 + 64);
    loop {
        let before = out.len();
        let status = compressor
            .compress_vec(data, &mut out, FlushCompress::Finish)
            .map_err(|e| Error::Message(format!("zlib compress failed: {e}")))?;
        match status {
            Status::StreamEnd => break,
            _ if out.len() == before => {
                out.reserve(data.len() / 8 + 64);
            }
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirent_layout() {
        let d = build_dirent(6, PFS_ENTRY_FILE, "param.sfo");
        assert_eq!(&d[..4], &6u32.to_le_bytes());
        assert_eq!(&d[4..8], &PFS_ENTRY_FILE.to_le_bytes());
        assert_eq!(&d[8..12], &9u32.to_le_bytes()); // namelen
        assert_eq!(d.len(), 32); // align(16 + 9 + 1 = 26) -> 32
        assert_eq!(&d[12..16], &32u32.to_le_bytes()); // entsize
        assert_eq!(&d[16..25], b"param.sfo");
        assert_eq!(d[25], 0);
        assert!(d[26..].iter().all(|&b| b == 0));
    }

    #[test]
    fn blocks_required_zero_is_one() {
        assert_eq!(blocks_required(0, 0x8000), 1);
        assert_eq!(blocks_required(1, 0x8000), 1);
        assert_eq!(blocks_required(0x8000, 0x8000), 1);
        assert_eq!(blocks_required(0x8001, 0x8000), 2);
    }

    #[test]
    fn sealedkey_to_content_map() {
        assert_eq!(sealedkey_to_content(1), 1);
        assert_eq!(sealedkey_to_content(3), 2);
        assert_eq!(sealedkey_to_content(10), 9);
    }

    #[test]
    fn backup_header_offset_458() {
        // 458 blocks < 10000: base 0x1F8000, origin 95, index (458-95)/2 = 181.
        assert_eq!(
            calculate_backup_header_offset(458, 0x8000).unwrap(),
            0x1F8000 + 181 * 0x8000
        );
    }

    #[test]
    fn pfsc_compress_roundtrip() {
        let data: Vec<u8> = (0u8..251).cycle().take(100_000).collect();
        let block_size = 0x8000;
        let blob = pfsc_compress_data(&data, block_size).unwrap();

        assert_eq!(&blob[0..4], &PFSC_MAGIC.to_le_bytes());
        assert_eq!(
            u32::from_le_bytes(blob[0x0C..0x10].try_into().unwrap()),
            block_size as u32
        );
        let block_data_offset = u64::from_le_bytes(blob[0x20..0x28].try_into().unwrap());
        let block_table_offset = u64::from_le_bytes(blob[0x18..0x20].try_into().unwrap());
        let rounded = u64::from_le_bytes(blob[0x28..0x30].try_into().unwrap());

        assert_eq!(block_data_offset, PFSC_HEADER_SIZE as u64);
        assert_eq!(
            rounded as usize,
            data.len().div_ceil(block_size) * block_size
        );
        let block_count = (rounded / block_size as u64 + 1) as usize;

        let table: Vec<u64> = blob[block_table_offset as usize..]
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .take(block_count)
            .collect();
        assert_eq!(table.len(), block_count);
        assert_eq!(table[block_count - 1], block_table_offset);

        // Each block must decode back to the original chunk, and every stored
        // block must fit in a PFS block.
        let n = block_count - 1;
        let mut out = Vec::new();
        for i in 0..n {
            let start = table[i] as usize;
            let end = table[i + 1] as usize;
            assert!(end - start <= block_size);
            let chunk = &data[i * block_size..((i + 1) * block_size).min(data.len())];
            let stored = &blob[start..end];
            // zlib header: CINFO nibble must be 4 => 2^12 window, accepted by
            // the PS4's inflateInit2(12).
            assert_eq!(stored[0] >> 4, PFSC_WINDOW_BITS - 8);
            let decompressed = zlib_decompress_window12(&blob[start..end]);
            assert_eq!(decompressed, chunk, "block {i}");
            out.extend_from_slice(&decompressed);
        }
        assert_eq!(out, data);
    }

    #[test]
    fn pfsc_compress_raw_fallback() {
        // Incompressible data: every block is stored raw, padded to block_size,
        // and the table sentinel still lands on block_table_offset.
        let mut data = vec![0u8; 2 * 0x8000];
        let mut x: u32 = 0x12345678;
        for b in data.iter_mut() {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            *b = (x >> 24) as u8;
        }
        let block_size = 0x8000;
        let blob = pfsc_compress_data(&data, block_size).unwrap();

        let block_data_offset = u64::from_le_bytes(blob[0x20..0x28].try_into().unwrap());
        let block_table_offset = u64::from_le_bytes(blob[0x18..0x20].try_into().unwrap());
        let rounded = u64::from_le_bytes(blob[0x28..0x30].try_into().unwrap());
        let block_count = (rounded / block_size as u64 + 1) as usize;

        let table: Vec<u64> = blob[block_table_offset as usize..]
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .take(block_count)
            .collect();

        // Two full blocks, both stored raw => each occupies a full block.
        assert_eq!(block_count, 3);
        assert_eq!(table[0], block_data_offset);
        assert_eq!(table[1] - table[0], block_size as u64);
        assert_eq!(table[2] - table[1], block_size as u64);
        assert_eq!(table[2], block_table_offset);
    }

    fn zlib_decompress_window12(input: &[u8]) -> Vec<u8> {
        use flate2::read::ZlibDecoder;
        use std::io::Read;

        let mut out = Vec::new();
        ZlibDecoder::new(input)
            .read_to_end(&mut out)
            .expect("zlib window-12 decode failed");
        out
    }

    const TEST_BLOCKS: u64 = 96;
    const SFO_HDR: usize = 20;
    const SFO_IDX: usize = 16;

    fn test_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ps4save_rs_{}_{tag}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("sce_sys")).unwrap();
        dir
    }

    fn write_param_sfo(dir: &std::path::Path, blocks: u64) {
        // TITLE_ID, ACCOUNT_ID, SAVEDATA_DIRECTORY, SAVEDATA_BLOCKS
        let keys = ["TITLE_ID\0", "ACCOUNT_ID\0", "SAVEDATA_DIRECTORY\0", "SAVEDATA_BLOCKS\0"];
        let vals: Vec<Vec<u8>> = vec![
            b"CUSA12345\0".to_vec(),
            0x1122_3344_5566_7788u64.to_le_bytes().to_vec(),
            b"SAVE1\0".to_vec(),
            blocks.to_le_bytes().to_vec(),
        ];
        let num = keys.len();
        let key_table_offset = SFO_HDR + num * SFO_IDX;
        let key_table_size: usize = keys.iter().map(|k| k.len()).sum();
        let data_table_offset = key_table_offset + key_table_size;
        let mut out = Vec::new();
        out.extend_from_slice(b"\x00PSF");
        out.extend_from_slice(&0x0101u32.to_le_bytes());
        out.extend_from_slice(&(key_table_offset as u32).to_le_bytes());
        out.extend_from_slice(&(data_table_offset as u32).to_le_bytes());
        out.extend_from_slice(&(num as u32).to_le_bytes());
        let mut key_off = 0usize;
        let mut data_off = 0usize;
        for (i, key) in keys.iter().copied().enumerate() {
            let fmt: u16 = if key != "TITLE_ID\0" && key != "SAVEDATA_DIRECTORY\0" {
                0x0004 // binary uint64
            } else {
                0x0204 // utf8
            };
            let max_len = vals[i].len() as u32;
            out.extend_from_slice(&(key_off as u16).to_le_bytes());
            out.extend_from_slice(&fmt.to_le_bytes());
            out.extend_from_slice(&max_len.to_le_bytes());
            out.extend_from_slice(&max_len.to_le_bytes());
            out.extend_from_slice(&(data_off as u32).to_le_bytes());
            key_off += key.len();
            data_off += max_len as usize;
        }
        for key in keys {
            out.extend_from_slice(key.as_bytes());
        }
        for v in &vals {
            out.extend_from_slice(v);
        }
        std::fs::write(dir.join("sce_sys").join("param.sfo"), &out).unwrap();
    }

    #[test]
    fn auto_sizes_blocks_to_fit_contents() {
        let dir = test_dir("autoblocks");
        write_param_sfo(&dir, TEST_BLOCKS);
        let big = dir.join("big.bin");
        std::fs::write(&big, vec![0u8; 4 * 1024 * 1024]).unwrap();

        let opts = EncryptOptions {
            total_blocks: TEST_BLOCKS as usize,
            auto_blocks: true,
            ..Default::default()
        };
        let (prepared, used_inodes) = prepare_nodes(&dir, &opts).unwrap();
        let total_inodes = opts.total_inodes.max(used_inodes as usize + 6);
        let (final_blocks, layout) = resolve_total_blocks(&prepared, &opts, total_inodes).unwrap();

        assert!(final_blocks > TEST_BLOCKS as usize, "should have grown");
        let indirect_extra = prepared
            .iter()
            .filter(|n| !n.is_dir && n.blocks > PFS_DIRECT_BLOCK_MAX_COUNT as u64)
            .count() as u64;
        assert!(layout.used_blocks + indirect_extra <= final_blocks as u64);
        // No block overlap between the spans.
        let mut seen = std::collections::HashSet::new();
        for blocks in &layout.files {
            for &b in blocks {
                assert!(seen.insert(b), "overlapping block {b}");
                assert!(
                    b != layout.backup_block,
                    "file block {b} collides with the backup-header block"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auto_respects_explicit_blocks_override() {
        let dir = test_dir("override");
        write_param_sfo(&dir, TEST_BLOCKS);
        std::fs::write(dir.join("big.bin"), vec![0u8; 4 * 1024 * 1024]).unwrap();

        let opts = EncryptOptions {
            total_blocks: TEST_BLOCKS as usize,
            auto_blocks: false,
            ..Default::default()
        };
        let (prepared, used_inodes) = prepare_nodes(&dir, &opts).unwrap();
        let total_inodes = opts.total_inodes.max(used_inodes as usize + 6);
        assert!(resolve_total_blocks(&prepared, &opts, total_inodes).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auto_scales_inodes_past_default() {
        let dir = test_dir("manyfiles");
        write_param_sfo(&dir, TEST_BLOCKS);
        for i in 0..1200 {
            std::fs::write(dir.join(format!("f{i:04}.bin")), [0u8]).unwrap();
        }
        let opts = EncryptOptions {
            total_blocks: TEST_BLOCKS as usize,
            auto_blocks: true,
            ..Default::default()
        };
        let (prepared, used_inodes) = prepare_nodes(&dir, &opts).unwrap();
        let total_inodes = opts.total_inodes.max(used_inodes as usize + 6);
        assert!(total_inodes > opts.total_inodes, "inode field must scale");
        let (final_blocks, _layout) =
            resolve_total_blocks(&prepared, &opts, total_inodes).unwrap();
        assert!(used_inodes as usize <= total_inodes);
        assert!(final_blocks > TEST_BLOCKS as usize);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn param_patch_grows_only() {
        let dir = test_dir("param");
        write_param_sfo(&dir, 96);
        let sfo_path = dir.join("sce_sys").join("param.sfo");

        // Grow.
        let patched = patch_param_savedata_blocks(&dir, 3704).unwrap().unwrap();
        assert_eq!(crate::sfo::read_savedata_blocks(&patched).unwrap(), Some(3704));
        let on_disk = std::fs::read(&sfo_path).unwrap();
        assert_eq!(crate::sfo::read_savedata_blocks(&on_disk).unwrap(), Some(3704));

        // Shrink attempt is a no-op (grow-only).
        assert!(patch_param_savedata_blocks(&dir, 100).unwrap().is_none());
        let on_disk = std::fs::read(&sfo_path).unwrap();
        assert_eq!(crate::sfo::read_savedata_blocks(&on_disk).unwrap(), Some(3704));

        // Missing sce_sys/param.sfo -> None.
        std::fs::remove_dir_all(dir.join("sce_sys")).unwrap();
        assert!(patch_param_savedata_blocks(&dir, 100).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
