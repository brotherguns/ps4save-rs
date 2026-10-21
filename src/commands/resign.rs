use std::path::{Path, PathBuf};

use super::{
    derive_output_path, open_save, open_save_cfg, read_title_id, resolve_all_save_pairs,
    resolve_save_pair,
};
use crate::config::Config;
use crate::crypto::hmac_sha256;
use crate::pfs::header::PFS_DINODE_TOP_STRUCT_SIZE;
use crate::pfs::{encrypt_dir, reauth_header_block, EncryptOptions, PfsOpenOptions};
use crate::sfo::{
    account_id_offset, parse_account_id, patch_account_id, read_account_id, read_savedata_blocks,
};

/// In-place resign: keep the source PFS image byte-for-byte (layout, block
/// allocation, sealed key all preserved) and only patch the ACCOUNT_ID bytes
/// inside param.sfo's data block, then recompute the sblock digest chain up to
/// the super-root dinode and the header authentication fields.
///
/// This mirrors how the PS4/Save Wizard resigns: decrypt with the original
/// sealed key, overwrite the 8 ACCOUNT_ID bytes, re-encrypt in place, and
/// refresh the hashes. Unlike the extract-then-rebuild path it never
/// re-allocates blocks, so the resulting layout is identical to the source.
pub fn resign_inplace(
    cfg: &Config,
    src_sealed: &str,
    src_pfs: &str,
    new_id: u64,
    out: &Path,
) -> crate::Result<()> {
    let ctx = open_save_cfg(cfg, src_sealed, src_pfs)?;
    let hmac_key = ctx
        .keyset
        .sig_hmac_key
        .ok_or_else(|| crate::Error::MissingKey("sig_hmac_key".into()))?;
    let content_key_ver = ctx.hdr.sd_key_ver;

    // Work on a copy so we never mutate the source.
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

    // 1. param.sfo data block: overwrite the 8 ACCOUNT_ID bytes.
    let sfo = fs.get_file_by_path("sce_sys/param.sfo")?;
    if sfo.is_compressed() {
        return Err(crate::Error::Message(
            "in-place resign requires an uncompressed param.sfo".into(),
        ));
    }
    let mut content = vec![0u8; sfo.file_size as usize];
    fs.file_read(&sfo, 0, &mut content)?;
    let old_id = read_account_id(&content)?;
    let acc_off = account_id_offset(&content)?;
    println!("  ACCOUNT_ID: {old_id:016x} -> {new_id:016x}");

    let acc_block_idx = acc_off / fs.basic_block_size;
    let acc_block_off = acc_off % fs.basic_block_size;
    let data_block = *sfo
        .block_list
        .get(acc_block_idx)
        .ok_or_else(|| crate::Error::Message("param.sfo block list too short".into()))?;

    let mut block = vec![0u8; fs.basic_block_size];
    fs.read_blocks(data_block, &mut block)?;
    block[acc_block_off..acc_block_off + 8].copy_from_slice(&new_id.to_le_bytes());
    fs.write_plain_block(data_block, &block)?;
    let data_digest = hmac_sha256(&hmac_key, &block);

    // 2. param.sfo's dinode lives in an inode-table block; update its sblock
    //    digest entry for the changed data block.
    let (dinode, tbl_block, tbl_off) = fs.get_dinode(sfo.ino)?;
    let db_format = fs.format;
    let entry_size = db_format.block_info_struct_size();
    let base = match db_format.block_no_size() {
        4 => 0x04,
        _ => 0x08,
    };
    let mut entry_idx = None;
    for i in 0..crate::pfs::header::PFS_DIRECT_BLOCK_MAX_COUNT {
        if dinode.direct_block_no(db_format, i) == data_block {
            entry_idx = Some(i);
            break;
        }
    }
    let entry_idx = entry_idx.ok_or_else(|| {
        crate::Error::Message("param.sfo data block not in a direct dinode entry".into())
    })?;

    let mut tbl = vec![0u8; fs.basic_block_size];
    fs.read_blocks(tbl_block, &mut tbl)?;
    let union_off = tbl_off + PFS_DINODE_TOP_STRUCT_SIZE;
    let digest_off = union_off + base + entry_idx * entry_size;
    let stored_block_no = match db_format.block_no_size() {
        4 => u32::from_le_bytes(tbl[digest_off + 32..digest_off + 36].try_into().unwrap()) as u64,
        _ => u64::from_le_bytes(tbl[digest_off + 32..digest_off + 40].try_into().unwrap()),
    };
    if stored_block_no != data_block {
        return Err(crate::Error::Message(format!(
            "dinode sblock mismatch: expected {data_block}, got {stored_block_no}"
        )));
    }
    tbl[digest_off..digest_off + 32].copy_from_slice(&data_digest);
    fs.write_plain_block(tbl_block, &tbl)?;
    let tbl_digest = hmac_sha256(&hmac_key, &tbl);

    // 3. super_root dinode (in block 0 header): update the sblock digest for
    //    the inode-table block, then re-authenticate the header.
    let mut b0 = fs.patch_super_root_tbl_digest(&hmac_key, tbl_block, &tbl_digest)?;

    reauth_header_block(&mut b0, &hmac_key, content_key_ver, &cfg.common)?;
    fs.write_raw_block(0, &b0)?;

    // Sealed key stays byte-identical (same EKPFS + IV).
    std::fs::copy(src_sealed, PathBuf::from(format!("{}.bin", out.display())))?;

    println!("  wrote {} (in-place, layout preserved)", out.display());
    Ok(())
}

fn resign_single(
    config: &str,
    src_sealed: &str,
    src_pfs: &str,
    new_id: u64,
    out: Option<&str>,
    compress: bool,
) -> crate::Result<()> {
    let cfg = Config::load(config)?;
    let ctx = open_save_cfg(&cfg, src_sealed, src_pfs)?;
    let title_id = read_title_id(&ctx)?;
    let original_name = Path::new(src_pfs)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "output".into());

    let out_name = match out {
        Some(o) => PathBuf::from(o),
        None => derive_output_path("resigned", &title_id, &original_name),
    };
    if let Some(parent) = out_name.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // In-place resign preserves the exact source layout, which is what makes
    // Save Wizard accept the result (rebuild-based resigns are rejected).
    resign_inplace(&cfg, src_sealed, src_pfs, new_id, &out_name)?;
    let _ = compress;

    Ok(())
}

/// Resign a single save or all saves under a directory.
/// Supports:
///   - Single file: resign one save pair
///   - Directory with one pair: resign that pair
///   - Directory with multiple pairs: resign each pair into subfolders
///   - Parent directory with CUSA folders: resign all pairs in all CUSA folders
pub fn run_resign(
    config: &str,
    save: &str,
    account_id: &str,
    out: Option<&str>,
    compress: bool,
) -> crate::Result<()> {
    let new_id = parse_account_id(account_id)?;
    let save_path = Path::new(save);

    // Single file: resolve pair and resign
    if save_path.is_file() {
        let (sealed, pfs) = resolve_save_pair(save)?;
        return resign_single(
            config,
            sealed.to_str().unwrap(),
            pfs.to_str().unwrap(),
            new_id,
            out,
            compress,
        );
    }

    // Directory: check for CUSA subfolders (bulk mode)
    // Bulk mode activates when the directory contains subfolders that either:
    //   - contain decrypted saves (sce_sys/param.sfo)
    //   - contain save pairs (.bin + image)
    let is_bulk_dir = {
        let mut has_decrypted = false;
        let mut has_pairs = false;
        if let Ok(rd) = std::fs::read_dir(save_path) {
            for entry in rd.flatten() {
                let p = entry.path();
                if !p.is_dir() {
                    continue;
                }
                if p.join("sce_sys").join("param.sfo").exists() {
                    has_decrypted = true;
                }
                if resolve_all_save_pairs(p.to_str().unwrap())
                    .map(|v| !v.is_empty())
                    .unwrap_or(false)
                {
                    has_pairs = true;
                }
                if has_decrypted && has_pairs {
                    break;
                }
            }
        }
        // Activate bulk mode if we have subfolders that contain pairs (and the
        // top-level directory doesn't itself resolve as a single save pair).
        has_pairs
    };

    if is_bulk_dir && out.is_none() {
        // Bulk mode: each subfolder is a decrypted save (or contains pairs)
        for entry in std::fs::read_dir(save_path)?.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }

            let sub_name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();

            // Check if this subfolder itself has pairs (encrypted multi-pair)
            if let Ok(pairs) = resolve_all_save_pairs(p.to_str().unwrap()) {
                if !pairs.is_empty() {
                    // Subfolder contains pairs: resign each pair
                    for (sealed_path, image_path) in &pairs {
                        let pair_name = image_path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .into_owned();

                        let out_pair = derive_output_path("resigned", &sub_name, &pair_name);
                        println!("{sub_name}/{pair_name}:");
                        resign_single(
                            config,
                            sealed_path.to_str().unwrap(),
                            image_path.to_str().unwrap(),
                            new_id,
                            Some(out_pair.to_str().unwrap()),
                            compress,
                        )?;
                    }
                    continue;
                }
            }

            // Subfolder is a direct decrypted save
            if p.join("sce_sys").join("param.sfo").exists() {
                println!("{sub_name}:");
                let cfg = Config::load(config)?;
                let sfo_path = p.join("sce_sys").join("param.sfo");
                let sfo = std::fs::read(&sfo_path)?;
                let old_id = read_account_id(&sfo)?;
                let blocks = read_savedata_blocks(&sfo)?.unwrap_or_else(|| {
                    eprintln!("  warning: param.sfo has no SAVEDATA_BLOCKS, using 0");
                    0
                });
                let patched = patch_account_id(&sfo, new_id)?;
                std::fs::write(&sfo_path, &patched)?;
                println!("  ACCOUNT_ID: {old_id:016x} -> {new_id:016x}");

                let title_id = super::read_title_id_from_dir(&p)?;
                let save_name = super::read_savedata_directory_from_dir(&p)?
                    .unwrap_or_else(|| sub_name.clone());
                let out_name = derive_output_path("resigned", &title_id, &save_name);
                if let Some(parent) = out_name.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let opts = EncryptOptions {
                    total_blocks: blocks as usize,
                    compress_files: compress,
                    ..Default::default()
                };
                let stats = encrypt_dir(&cfg.common, &p, &out_name, &opts)?;
                // Restore original param.sfo
                std::fs::write(&sfo_path, &sfo)?;
                println!(
                    "  used blocks: {}, inodes: {}, backup: {}",
                    stats.used_blocks, stats.used_inodes, stats.backup_block
                );
            }
        }
        return Ok(());
    }

    // Single directory: check for multiple pairs
    let pairs = resolve_all_save_pairs(save)?;
    if pairs.is_empty() {
        return Err(crate::Error::Message(format!(
            "no save pairs found in {save}"
        )));
    }

    if pairs.len() == 1 {
        let (sealed, pfs) = &pairs[0];
        return resign_single(
            config,
            sealed.to_str().unwrap(),
            pfs.to_str().unwrap(),
            new_id,
            out,
            compress,
        );
    }

    // Multiple pairs in a single CUSA folder
    let title_id = {
        let ctx = open_save(
            config,
            pairs[0].0.to_str().unwrap(),
            pairs[0].1.to_str().unwrap(),
        )?;
        read_title_id(&ctx)?
    };

    for (sealed_path, image_path) in &pairs {
        let name = image_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let pair_out = derive_output_path("resigned", &title_id, &name);
        println!("{name}:");
        resign_single(
            config,
            sealed_path.to_str().unwrap(),
            image_path.to_str().unwrap(),
            new_id,
            Some(pair_out.to_str().unwrap()),
            compress,
        )?;
    }
    Ok(())
}
