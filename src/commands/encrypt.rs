use std::path::{Path, PathBuf};

use super::{derive_output_path, read_savedata_blocks_from_dir, read_savedata_directory_from_dir, read_title_id_from_dir};
use crate::config::Config;
use crate::pfs::{EncryptOptions, encrypt_dir};

fn hex_to_key(hex: &str, expected: usize, what: &str) -> crate::Result<[u8; 32]> {
    if hex.len() != expected * 2 {
        return Err(crate::Error::Message(format!(
            "{what} must be {expected} hex bytes"
        )));
    }
    let mut out = [0u8; 32];
    for i in 0..expected {
        let b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| crate::Error::Message(format!("invalid {what} hex")))?;
        out[i] = b;
    }
    Ok(out)
}

fn encrypt_single(
    cfg: &Config,
    input: &Path,
    out_path: &Path,
    opts: &EncryptOptions,
) -> crate::Result<()> {
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let stats = encrypt_dir(&cfg.common, input, out_path, opts)?;
    println!("used blocks: {}", stats.used_blocks);
    println!("total blocks: {}", stats.total_blocks);
    println!("used inodes: {}", stats.used_inodes);
    println!("total inodes: {}", stats.total_inodes);
    println!("backup block: {}", stats.backup_block);
    Ok(())
}

/// Check if a directory contains subfolders with sce_sys/param.sfo (i.e. multiple decrypted pairs).
fn has_pair_subdirs(dir: &Path) -> bool {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() && p.join("sce_sys").join("param.sfo").exists() {
                return true;
            }
        }
    }
    false
}

/// Check if a directory contains only subdirectories (no files).
/// Used to detect bulk mode input (e.g. `encrypted/` with multiple CUSA folders).
fn is_all_subdirs(dir: &Path) -> bool {
    if let Ok(rd) = std::fs::read_dir(dir) {
        let entries: Vec<_> = rd.flatten().collect();
        return !entries.is_empty() && entries.iter().all(|e| e.path().is_dir());
    }
    false
}

fn encrypt_subfolder(
    cfg: &Config,
    p: &Path,
    sub_name: &str,
    base_out: &Path,
    blocks_override: Option<usize>,
    opts_template: &EncryptOptions,
    compress: bool,
) -> crate::Result<()> {
    let total_blocks = match blocks_override {
        Some(b) => b,
        None => read_savedata_blocks_from_dir(p)?
            .unwrap_or_else(|| {
                eprintln!("warning: {sub_name}: param.sfo has no SAVEDATA_BLOCKS, using 0");
                0
            }) as usize,
    };

    let mut opts = opts_template.clone();
    opts.total_blocks = total_blocks;
    opts.compress_files = compress;

    let save_name = read_savedata_directory_from_dir(p)?
        .unwrap_or_else(|| sub_name.to_string());
    let out_path = base_out.join(&save_name);

    encrypt_single(cfg, p, &out_path, &opts)
}

pub fn run_encrypt(
    config: &str,
    input: &str,
    output: Option<&str>,
    ekpfs_hex: Option<&str>,
    seed_hex: Option<&str>,
    blocks_override: Option<usize>,
    compress: bool,
) -> crate::Result<()> {
    let cfg = Config::load(config)?;
    let input_path = Path::new(input);

    // Build base options
    let build_opts = |total_blocks: usize| -> EncryptOptions {
        let mut opts = EncryptOptions {
            total_blocks,
            auto_blocks: blocks_override.is_none(),
            ..Default::default()
        };
        if let Some(h) = ekpfs_hex {
            opts.ekpfs = Some(hex_to_key(h, 32, "ekpfs").unwrap());
        }
        if let Some(h) = seed_hex {
            opts.seed = Some(hex_to_key(h, 16, "seed").unwrap()[..16].try_into().unwrap());
        }
        opts.compress_files = compress;
        opts
    };

    // Single CUSA with sub-pairs: the dir itself has sce_sys/param.sfo AND subfolders with it
    if input_path.is_dir()
        && input_path.join("sce_sys").join("param.sfo").exists()
        && has_pair_subdirs(input_path)
    {
        // Single CUSA folder with sub-pairs: encrypt each subfolder
        let title_id = {
            let first_subdir = std::fs::read_dir(input_path)?
                .flatten()
                .filter(|e| e.path().is_dir())
                .find(|e| e.path().join("sce_sys").join("param.sfo").exists())
                .ok_or_else(|| crate::Error::Message("no subfolders with param.sfo found".into()))?;
            read_title_id_from_dir(&first_subdir.path())?
        };

        let base_out = match output {
            Some(o) => PathBuf::from(o),
            None => derive_output_path("encrypted", &title_id, ""),
        };
        std::fs::create_dir_all(&base_out)?;

        let template_opts = build_opts(0);

        for entry in std::fs::read_dir(input_path)?.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            if !p.join("sce_sys").join("param.sfo").exists() {
                continue;
            }
            let name = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
            println!("{name}:");
            encrypt_subfolder(&cfg, &p, &name, &base_out, blocks_override, &template_opts, compress)?;
        }

        return Ok(());
    }

    // Bulk mode: directory with only subdirectories (no files)
    // A folder with its own sce_sys/param.sfo is a single decrypted save, even
    // if every entry is a directory (e.g. sce_sys/ + savedata0/).
    if input_path.is_dir()
        && is_all_subdirs(input_path)
        && !input_path.join("sce_sys").join("param.sfo").exists()
    {
        let template_opts = build_opts(0);

        for entry in std::fs::read_dir(input_path)?.flatten() {
            let cusa_path = entry.path();
            if !cusa_path.is_dir() {
                continue;
            }
            let cusa_name = cusa_path.file_name().unwrap_or_default().to_string_lossy().into_owned();

            // Sub-pairs inside this CUSA folder
            if has_pair_subdirs(&cusa_path) && !cusa_path.join("sce_sys").join("param.sfo").exists() {
                let title_id = {
                    let first_subdir = std::fs::read_dir(&cusa_path)?
                        .flatten()
                        .filter(|e| e.path().is_dir())
                        .find(|e| e.path().join("sce_sys").join("param.sfo").exists())
                        .ok_or_else(|| crate::Error::Message(format!("no subfolders with param.sfo in {cusa_name}")))?;
                    read_title_id_from_dir(&first_subdir.path())?
                };

                let base_out = derive_output_path("encrypted", &title_id, "");
                std::fs::create_dir_all(&base_out)?;

                for sub_entry in std::fs::read_dir(&cusa_path)?.flatten() {
                    let p = sub_entry.path();
                    if !p.is_dir() {
                        continue;
                    }
                    if !p.join("sce_sys").join("param.sfo").exists() {
                        continue;
                    }
                    let name = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
                    println!("{cusa_name}/{name}:");
                    encrypt_subfolder(&cfg, &p, &name, &base_out, blocks_override, &template_opts, compress)?;
                }
                continue;
            }

            // Deeper nesting: CUSA folder with sub-subdirs containing decrypted saves
            // e.g. from decrypt CUSA output: CUSA00168/{pair_name}/sce_sys/param.sfo
            if !has_pair_subdirs(&cusa_path)
                && !cusa_path.join("sce_sys").join("param.sfo").exists()
            {
                let nested: Vec<_> = std::fs::read_dir(&cusa_path)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .filter(|e| {
                        e.path().is_dir() && e.path().join("sce_sys").join("param.sfo").exists()
                    })
                    .collect();
                if !nested.is_empty() {
                    let title_id = read_title_id_from_dir(&nested[0].path())?;
                    let base_out = derive_output_path("encrypted", &title_id, "");
                    std::fs::create_dir_all(&base_out)?;
                    for entry in &nested {
                        let p = entry.path();
                        let name = p
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .into_owned();
                        println!("{cusa_name}/{name}:");
                        encrypt_subfolder(
                            &cfg,
                            &p,
                            &name,
                            &base_out,
                            blocks_override,
                            &template_opts,
                            compress,
                        )?;
                    }
                    continue;
                }
            }

            // Direct decrypted save
            if cusa_path.join("sce_sys").join("param.sfo").exists() {
                let title_id = read_title_id_from_dir(&cusa_path)?;
                let save_name = read_savedata_directory_from_dir(&cusa_path)?
                    .unwrap_or_else(|| cusa_name.clone());
                let out_path = derive_output_path("encrypted", &title_id, &save_name);

                let total_blocks = match blocks_override {
                    Some(b) => b,
                    None => read_savedata_blocks_from_dir(&cusa_path)?
                        .unwrap_or_else(|| {
                            eprintln!("warning: {cusa_name}: param.sfo has no SAVEDATA_BLOCKS, using 0");
                            0
                        }) as usize,
                };

                let mut opts = template_opts.clone();
                opts.total_blocks = total_blocks;
                opts.compress_files = compress;

                println!("{cusa_name}:");
                encrypt_single(&cfg, &cusa_path, &out_path, &opts)?;
            }
        }

        return Ok(());
    }

    // Single directory or file
    let total_blocks = match blocks_override {
        Some(b) => b,
        None => read_savedata_blocks_from_dir(input_path)?
            .ok_or_else(|| crate::Error::Message("param.sfo has no SAVEDATA_BLOCKS".into()))?
            as usize,
    };

    let opts = build_opts(total_blocks);

    let out_path = match output {
        Some(o) => PathBuf::from(o),
        None => {
            let title_id = read_title_id_from_dir(input_path)?;
            let save_name = read_savedata_directory_from_dir(input_path)?
                .unwrap_or_else(|| title_id.clone());
            derive_output_path("encrypted", &title_id, &save_name)
        }
    };

    encrypt_single(&cfg, input_path, &out_path, &opts)
}
