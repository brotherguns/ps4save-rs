use std::path::{Path, PathBuf};

use super::{
    SaveContext, derive_output_path, open_save, read_title_id, resolve_all_save_pairs,
    resolve_save_pair,
};
use crate::pfs::PfsEntryType;

/// Read a single file (e.g. `sce_sys/keystone`) from a save into memory
/// without writing it to disk. Matches on the file name, case-insensitively.
pub fn read_save_file_bytes(ctx: &SaveContext, wanted: &str) -> crate::Result<Option<Vec<u8>>> {
    for e in ctx.fs.enum_user_root_directory()? {
        if e.entry_type != PfsEntryType::File {
            continue;
        }
        let name = Path::new(&e.path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !name.eq_ignore_ascii_case(wanted) {
            continue;
        }
        let f = ctx.fs.get_file(e.ino)?;
        let mut buf = vec![0u8; f.file_size as usize];
        ctx.fs.file_read(&f, 0, &mut buf)?;
        return Ok(Some(buf));
    }
    Ok(None)
}

/// Write every file under the user root to `outdir`, returning
/// (relative path, size, stored-compressed) for each.
pub fn extract_all(ctx: &SaveContext, outdir: &Path) -> crate::Result<Vec<(PathBuf, u64, bool)>> {
    std::fs::create_dir_all(outdir)?;

    let mut written = Vec::new();
    for e in ctx.fs.enum_user_root_directory()? {
        if e.entry_type != PfsEntryType::File {
            continue;
        }
        let f = ctx.fs.get_file(e.ino)?;
        let mut buf = vec![0u8; f.file_size as usize];
        ctx.fs.file_read(&f, 0, &mut buf)?;
        let dest = outdir.join(&e.path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, &buf)?;
        written.push((PathBuf::from(e.path), f.file_size, f.is_compressed()));
    }
    Ok(written)
}

fn decrypt_single(
    config: &str,
    sealed: &str,
    pfs: &str,
    outdir: Option<&str>,
) -> crate::Result<()> {
    let ctx = open_save(config, sealed, pfs)?;

    let outdir = match outdir {
        Some(o) => PathBuf::from(o),
        None => {
            let title_id = read_title_id(&ctx)?;
            derive_output_path("decrypted", &title_id, "")
        }
    };

    let written = extract_all(&ctx, &outdir)?;
    let count = written.len();
    for (path, size, compressed) in &written {
        let marker = if *compressed { " [compressed]" } else { "" };
        println!("{} ({} bytes){marker}", path.display(), size);
    }

    println!("extracted {count} files to {}", outdir.display());
    Ok(())
}

pub fn run_decrypt(
    config: &str,
    save: &str,
    outdir: Option<&str>,
) -> crate::Result<()> {
    let save_path = Path::new(save);

    // Single file: resolve pair and decrypt normally
    if save_path.is_file() {
        let (sealed, pfs) = resolve_save_pair(save)?;
        return decrypt_single(config, sealed.to_str().unwrap(), pfs.to_str().unwrap(), outdir);
    }

    // Directory: scan for all pairs
    let pairs = resolve_all_save_pairs(save).unwrap_or_default();

    if !pairs.is_empty() {
        // Pairs found at top level
        if pairs.len() == 1 {
            let (sealed, pfs) = &pairs[0];
            return decrypt_single(
                config,
                sealed.to_str().unwrap(),
                pfs.to_str().unwrap(),
                outdir,
            );
        }

        // Multiple pairs: decrypt each into a subfolder named after the image
        let title_id = {
            let (sealed, pfs) = &pairs[0];
            let ctx = open_save(config, sealed.to_str().unwrap(), pfs.to_str().unwrap())?;
            read_title_id(&ctx)?
        };

        let base_out = match outdir {
            Some(o) => PathBuf::from(o),
            None => derive_output_path("decrypted", &title_id, ""),
        };
        std::fs::create_dir_all(&base_out)?;

        for (sealed_path, image_path) in &pairs {
            let name = image_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();

            let ctx = open_save(
                config,
                sealed_path.to_str().unwrap(),
                image_path.to_str().unwrap(),
            )?;
            let pair_out = base_out.join(&name);
            let written = extract_all(&ctx, &pair_out)?;
            let count = written.len();
            for (path, size, compressed) in &written {
                let marker = if *compressed { " [compressed]" } else { "" };
                println!("  {} ({} bytes){marker}", path.display(), size);
            }
            println!("{name}: extracted {count} files to {}", pair_out.display());
        }

        let total_pairs = pairs.len();
        println!("extracted {total_pairs} pairs to {}", base_out.display());
        return Ok(());
    }

    // No pairs at top level: check subdirectories (CUSA folder layout)
    let mut cusa_pairs: Vec<(String, PathBuf, PathBuf)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(save_path) {
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
            "no save pairs found in {save}"
        )));
    }

    let base_out = match outdir {
        Some(o) => PathBuf::from(o),
        None => PathBuf::from("decrypted"),
    };
    std::fs::create_dir_all(&base_out)?;

    for (cusa_name, sealed_path, image_path) in &cusa_pairs {
        let pair_name = image_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();

        let ctx = open_save(
            config,
            sealed_path.to_str().unwrap(),
            image_path.to_str().unwrap(),
        )?;
        let pair_out = base_out.join(cusa_name).join(&pair_name);
        let written = extract_all(&ctx, &pair_out)?;
        let count = written.len();
        for (path, size, compressed) in &written {
            let marker = if *compressed { " [compressed]" } else { "" };
            println!("  {} ({} bytes){marker}", path.display(), size);
        }
        println!(
            "{cusa_name}/{pair_name}: extracted {count} files to {}",
            pair_out.display()
        );
    }

    let total = cusa_pairs.len();
    println!("extracted {total} pairs to {}", base_out.display());
    Ok(())
}
