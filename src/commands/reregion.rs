use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::read_save_file_bytes;
use super::{derive_output_path, open_save_cfg, resolve_all_save_pairs, resolve_save_pair};
use crate::config::Config;
use crate::crypto::hmac_sha256;
use crate::pfs::header::PFS_DINODE_TOP_STRUCT_SIZE;
use crate::pfs::{reauth_header_block, PfsOpenOptions};
use crate::sfo::{
    parse_account_id, patch_account_id, patch_string, patch_title_id_raw, read_account_id,
    read_string,
};

/// In-place reregion: copy the source PFS image byte-for-byte, then patch
/// param.sfo (TITLE_ID, SAVEDATA_DIRECTORY, ACCOUNT_ID) and replace keystone
/// content, recomputing the sblock digest chain and header authentication.
pub fn reregion_inplace(
    cfg: &Config,
    src_sealed: &str,
    src_pfs: &str,
    _sample_sfo: &[u8],
    sample_keystone: &[u8],
    target_title_id: &str,
    target_dir: Option<&str>,
    new_id: Option<u64>,
    out: &Path,
) -> crate::Result<()> {
    let ctx = open_save_cfg(cfg, src_sealed, src_pfs)?;
    let hmac_key = ctx
        .keyset
        .sig_hmac_key
        .ok_or_else(|| crate::Error::MissingKey("sig_hmac_key".into()))?;
    let content_key_ver = ctx.hdr.sd_key_ver;

    std::fs::copy(src_pfs, out)?;

    let fs = crate::pfs::Pfs::open(
        out,
        &ctx.keyset,
        &PfsOpenOptions {
            read_write: true,
            skip_signature_check: true,
            ..Default::default()
        },
    )?;

    let block_size = fs.basic_block_size;

    // --- 1. Patch param.sfo ---
    let sfo = fs.get_file_by_path("sce_sys/param.sfo")?;
    if sfo.is_compressed() {
        return Err(crate::Error::Message(
            "in-place reregion requires an uncompressed param.sfo".into(),
        ));
    }
    let mut sfo_content = vec![0u8; sfo.file_size as usize];
    fs.file_read(&sfo, 0, &mut sfo_content)?;
    let old_title = read_string(&sfo_content, "TITLE_ID")?.unwrap_or_default();
    let old_id = read_account_id(&sfo_content)?;
    let mut patched_sfo = patch_string(&sfo_content, "TITLE_ID", target_title_id)?;
    if let Some(dir) = target_dir {
        match patch_string(&patched_sfo, "SAVEDATA_DIRECTORY", dir) {
            Ok(p) => patched_sfo = p,
            Err(_) => println!("  note: source has no SAVEDATA_DIRECTORY, skipped"),
        }
    }
    match read_string(_sample_sfo, "MAINTITLE") {
        Ok(Some(mt)) => match patch_string(&patched_sfo, "MAINTITLE", &mt) {
            Ok(p) => patched_sfo = p,
            Err(e) => println!("  note: MAINTITLE patch failed: {e}"),
        },
        _ => println!("  note: sample has no MAINTITLE, skipped"),
    }
    patch_title_id_raw(&mut patched_sfo, &old_title, target_title_id);
    if let Some(nid) = new_id {
        patched_sfo = patch_account_id(&patched_sfo, nid)?;
        println!("  param.sfo ACCOUNT_ID: {old_id:016x} -> {nid:016x}");
    } else {
        println!("  param.sfo ACCOUNT_ID: {old_id:016x} (unchanged)");
    }
    println!("  param.sfo TITLE_ID: {old_title:?} -> {target_title_id:?}");

    // Write patched param.sfo blocks, collect changed block numbers.
    let mut sfo_changed_blocks: Vec<u64> = Vec::new();
    let orig_sfo_blocks = sfo_content.len().div_ceil(block_size);
    for blk_idx in 0..orig_sfo_blocks {
        let off = blk_idx * block_size;
        let end = (off + block_size).min(sfo_content.len());
        if sfo_content[off..end] != patched_sfo[off..end] {
            let data_block = *sfo.block_list.get(blk_idx).ok_or_else(|| {
                crate::Error::Message(format!("param.sfo block {blk_idx} not in block list"))
            })?;
            let mut block = vec![0u8; block_size];
            fs.read_blocks(data_block, &mut block)?;
            block[..end - off].copy_from_slice(&patched_sfo[off..end]);
            fs.write_plain_block(data_block, &block)?;
            sfo_changed_blocks.push(data_block);
        }
    }

    // --- 2. Replace keystone ---
    let keystone = fs.get_file_by_path("sce_sys/keystone")?;
    if keystone.is_compressed() {
        return Err(crate::Error::Message(
            "in-place reregion requires an uncompressed keystone".into(),
        ));
    }
    let mut orig_keystone = vec![0u8; keystone.file_size as usize];
    fs.file_read(&keystone, 0, &mut orig_keystone)?;
    let mut keystone_changed_blocks: Vec<u64> = Vec::new();
    if orig_keystone != sample_keystone {
        let keystone_blocks = orig_keystone.len().div_ceil(block_size);
        for blk_idx in 0..keystone_blocks {
            let off = blk_idx * block_size;
            let orig_end = (off + block_size).min(orig_keystone.len());
            let new_end = (off + block_size).min(sample_keystone.len());
            let orig_chunk = if off < orig_keystone.len() {
                &orig_keystone[off..orig_end]
            } else {
                &[]
            };
            let new_chunk = if off < sample_keystone.len() {
                &sample_keystone[off..new_end]
            } else {
                &[]
            };
            if orig_chunk != new_chunk {
                let data_block = *keystone.block_list.get(blk_idx).ok_or_else(|| {
                    crate::Error::Message(format!("keystone block {blk_idx} not in block list"))
                })?;
                let mut block = vec![0u8; block_size];
                fs.read_blocks(data_block, &mut block)?;
                let copy_len = new_end - off;
                block[..copy_len].copy_from_slice(new_chunk);
                if orig_keystone.len() < sample_keystone.len() && new_end > orig_keystone.len() {
                    // zero remaining if new keystone is larger
                }
                fs.write_plain_block(data_block, &block)?;
                keystone_changed_blocks.push(data_block);
            }
        }
        println!("  keystone: replaced with sample's keystone");
    } else {
        println!("  keystone: unchanged");
    }

    // --- 3. Update sblock digest chain ---
    let mut all_changed_blocks = sfo_changed_blocks;
    all_changed_blocks.extend(keystone_changed_blocks);
    all_changed_blocks.sort_unstable();
    all_changed_blocks.dedup();

    if all_changed_blocks.is_empty() {
        println!("  no blocks changed, copying sealed key");
        std::fs::copy(src_sealed, PathBuf::from(format!("{}.bin", out.display())))?;
        return Ok(());
    }

    // Collect inode-table blocks that need updating.
    let mut dirty_tbl_blocks: HashSet<u64> = HashSet::new();

    // For each changed data block, update the sblock digest in the owning inode.
    let changed_files: Vec<(&str, &crate::pfs::PfsFile)> =
        vec![("param.sfo", &sfo), ("keystone", &keystone)];

    for (_name, pfs_file) in &changed_files {
        let (dinode, tbl_block, tbl_off) = fs.get_dinode(pfs_file.ino)?;
        let db_format = fs.format;
        let entry_size = db_format.block_info_struct_size();
        let base = match db_format.block_no_size() {
            4 => 0x04,
            _ => 0x08,
        };

        let mut tbl = vec![0u8; block_size];
        fs.read_blocks(tbl_block, &mut tbl)?;

        for &data_block in &all_changed_blocks {
            let mut entry_idx = None;
            for i in 0..crate::pfs::header::PFS_DIRECT_BLOCK_MAX_COUNT {
                if dinode.direct_block_no(db_format, i) == data_block {
                    entry_idx = Some(i);
                    break;
                }
            }
            let entry_idx = match entry_idx {
                Some(idx) => idx,
                None => continue, // this data block doesn't belong to this inode
            };

            let mut block = vec![0u8; block_size];
            fs.read_blocks(data_block, &mut block)?;
            let data_digest = hmac_sha256(&hmac_key, &block);

            let union_off = tbl_off + PFS_DINODE_TOP_STRUCT_SIZE;
            let digest_off = union_off + base + entry_idx * entry_size;
            tbl[digest_off..digest_off + 32].copy_from_slice(&data_digest);
            dirty_tbl_blocks.insert(tbl_block);
        }

        fs.write_plain_block(tbl_block, &tbl)?;
    }

    // --- 4. Update super_root dinode ---
    for tbl_block in &dirty_tbl_blocks {
        let mut tbl = vec![0u8; block_size];
        fs.read_blocks(*tbl_block, &mut tbl)?;
        let tbl_digest = hmac_sha256(&hmac_key, &tbl);

        let mut b0 = fs.patch_super_root_tbl_digest(&hmac_key, *tbl_block, &tbl_digest)?;

        reauth_header_block(&mut b0, &hmac_key, content_key_ver, &cfg.common)?;
        fs.write_raw_block(0, &b0)?;
    }

    std::fs::copy(src_sealed, PathBuf::from(format!("{}.bin", out.display())))?;
    println!("  wrote {} (in-place, layout preserved)", out.display());
    Ok(())
}

/// Path-based entry point. Resolves pairs from raw paths, then delegates to `run_reregion`.
pub fn reregion_from_paths(
    config: &str,
    src: &str,
    sample: &str,
    account_id: Option<&str>,
    out: Option<&str>,
    compress: bool,
) -> crate::Result<()> {
    // Single pair: resolve and reregion normally
    if !Path::new(src).is_dir() {
        let (src_sealed, src_pfs) = resolve_save_pair(src)?;
        let (sample_sealed, sample_pfs) = resolve_save_pair(sample)?;
        return run_reregion(
            config,
            src_sealed.to_str().unwrap(),
            src_pfs.to_str().unwrap(),
            sample_sealed.to_str().unwrap(),
            sample_pfs.to_str().unwrap(),
            account_id,
            out,
            compress,
        );
    }

    // Directory: scan for all pairs in src
    let pairs = resolve_all_save_pairs(src).unwrap_or_default();

    if !pairs.is_empty() {
        if pairs.len() == 1 {
            let (src_sealed, src_pfs) = &pairs[0];
            let (sample_sealed, sample_pfs) = resolve_save_pair(sample)?;
            return run_reregion(
                config,
                src_sealed.to_str().unwrap(),
                src_pfs.to_str().unwrap(),
                sample_sealed.to_str().unwrap(),
                sample_pfs.to_str().unwrap(),
                account_id,
                out,
                compress,
            );
        }

        // Multiple pairs at top level: reregion each using the same sample
        let (sample_sealed, sample_pfs) = resolve_save_pair(sample)?;
        let sample_sealed = sample_sealed.to_str().unwrap().to_owned();
        let sample_pfs = sample_pfs.to_str().unwrap().to_owned();

        let cfg = Config::load(config)?;
        let sample_ctx = open_save_cfg(&cfg, &sample_sealed, &sample_pfs)?;
        let sample_sfo = read_save_file_bytes(&sample_ctx, "param.sfo")?
            .ok_or_else(|| crate::Error::Message("sample save has no param.sfo".into()))?;
        let target_title_id = read_string(&sample_sfo, "TITLE_ID")?
            .ok_or_else(|| crate::Error::Message("sample save has no TITLE_ID".into()))?;

        let base_out = derive_output_path("reregioned", &target_title_id, "");
        std::fs::create_dir_all(&base_out)?;

        for (src_sealed, src_pfs) in &pairs {
            let name = src_pfs
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();

            println!("{name}:");
            let pair_out = base_out.join(&name);
            run_reregion(
                config,
                src_sealed.to_str().unwrap(),
                src_pfs.to_str().unwrap(),
                &sample_sealed,
                &sample_pfs,
                account_id,
                Some(pair_out.to_str().unwrap()),
                compress,
            )?;
        }

        let total = pairs.len();
        println!("reregioned {total} pairs to {}", base_out.display());
        return Ok(());
    }

    // No pairs at top level: check subdirectories (CUSA folder layout)
    let mut cusa_pairs: Vec<(String, PathBuf, PathBuf)> = Vec::new();
    let src_path = Path::new(src);
    if let Ok(rd) = std::fs::read_dir(src_path) {
        for entry in rd.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let cusa_name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            if let Ok(mut sub_pairs) = resolve_all_save_pairs(p.to_str().unwrap()) {
                for pair in sub_pairs.drain(..) {
                    cusa_pairs.push((cusa_name.clone(), pair.0, pair.1));
                }
            }
        }
    }

    if cusa_pairs.is_empty() {
        return Err(crate::Error::Message(format!(
            "no save pairs found in {src}"
        )));
    }

    let (sample_sealed, sample_pfs) = resolve_save_pair(sample)?;
    let sample_sealed = sample_sealed.to_str().unwrap().to_owned();
    let sample_pfs = sample_pfs.to_str().unwrap().to_owned();

    let cfg = Config::load(config)?;
    let sample_ctx = open_save_cfg(&cfg, &sample_sealed, &sample_pfs)?;
    let sample_sfo = read_save_file_bytes(&sample_ctx, "param.sfo")?
        .ok_or_else(|| crate::Error::Message("sample save has no param.sfo".into()))?;
    let target_title_id = read_string(&sample_sfo, "TITLE_ID")?
        .ok_or_else(|| crate::Error::Message("sample save has no TITLE_ID".into()))?;

    let base_out = derive_output_path("reregioned", &target_title_id, "");
    std::fs::create_dir_all(&base_out)?;

    for (cusa_name, src_sealed, src_pfs) in &cusa_pairs {
        let pair_name = src_pfs
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();

        println!("{cusa_name}/{pair_name}:");
        let pair_out = base_out.join(cusa_name).join(&pair_name);
        run_reregion(
            config,
            src_sealed.to_str().unwrap(),
            src_pfs.to_str().unwrap(),
            &sample_sealed,
            &sample_pfs,
            account_id,
            Some(pair_out.to_str().unwrap()),
            compress,
        )?;
    }

    let total = cusa_pairs.len();
    println!("reregioned {total} pairs to {}", base_out.display());
    Ok(())
}

/// Re-region a save using a sample save from the target region.
/// Mirrors htos `reregion`/`reregion_write`: take the sample's TITLE_ID (and
/// SAVEDATA_DIRECTORY when present) from its param.sfo, adopt its keystone,
/// and resign the ACCOUNT_ID to the given account.
///
/// Uses in-place patching (like resign) to preserve the exact block layout for
/// Save Wizard compatibility.
#[allow(clippy::too_many_arguments)]
pub fn run_reregion(
    config: &str,
    src_sealed: &str,
    src_pfs: &str,
    sample_sealed: &str,
    sample_pfs: &str,
    account_id: Option<&str>,
    out: Option<&str>,
    compress: bool,
) -> crate::Result<()> {
    let cfg = Config::load(config)?;
    let new_id = account_id.map(parse_account_id).transpose()?;

    let sample = open_save_cfg(&cfg, sample_sealed, sample_pfs)?;
    let sample_sfo = read_save_file_bytes(&sample, "param.sfo")?
        .ok_or_else(|| crate::Error::Message("sample save has no param.sfo".into()))?;
    let sample_keystone = read_save_file_bytes(&sample, "keystone")?
        .ok_or_else(|| crate::Error::Message("sample save has no keystone".into()))?;
    let target_title_id = read_string(&sample_sfo, "TITLE_ID")?
        .ok_or_else(|| crate::Error::Message("sample save has no TITLE_ID".into()))?;
    let target_dir = read_string(&sample_sfo, "SAVEDATA_DIRECTORY")?;
    println!(
        "sample save: TITLE_ID={target_title_id} SAVEDATA_DIRECTORY={}",
        target_dir.as_deref().unwrap_or("<none>")
    );

    let save_name = target_dir.as_deref().unwrap_or("ManualSave");

    let out_name = match out {
        Some(o) => PathBuf::from(o),
        None => derive_output_path("reregioned", &target_title_id, save_name),
    };
    if let Some(parent) = out_name.parent() {
        std::fs::create_dir_all(parent)?;
    }

    reregion_inplace(
        &cfg,
        src_sealed,
        src_pfs,
        &sample_sfo,
        &sample_keystone,
        &target_title_id,
        target_dir.as_deref(),
        new_id,
        &out_name,
    )?;

    let _ = compress;
    Ok(())
}
