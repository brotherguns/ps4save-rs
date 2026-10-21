//! CLI command implementations (thin layer over the `ps4save-rs` library).

pub mod decrypt;
pub mod keystone;
pub mod encrypt;
#[cfg(any(feature = "cli", feature = "gui", feature = "ios"))]
pub mod inspect;
pub mod list;
pub mod reregion;
pub mod resign;
pub mod selftest;

pub use decrypt::extract_all;
pub use decrypt::read_save_file_bytes;
pub use keystone::run_keystone;
pub use decrypt::run_decrypt;
pub use encrypt::run_encrypt;
#[cfg(any(feature = "cli", feature = "gui", feature = "ios"))]
pub use inspect::inspect_path;
#[cfg(any(feature = "cli", feature = "gui", feature = "ios"))]
pub use inspect::inspect_to_string;
#[cfg(any(feature = "cli", feature = "gui", feature = "ios"))]
pub use inspect::inspect_to_string_from_path;
#[cfg(any(feature = "cli", feature = "gui", feature = "ios"))]
pub use inspect::run_inspect;
pub use list::list_path;
pub use list::run_list;
pub use reregion::run_reregion;
pub use reregion::reregion_from_paths;
pub use resign::run_resign;
pub use selftest::run_selftest;

/// Given a save path (file or directory), resolve all sealed key + PFS image pairs.
/// For a directory this returns every matching `.bin` + image pair found inside.
pub fn resolve_all_save_pairs(path: &str) -> crate::Result<Vec<(PathBuf, PathBuf)>> {
    let p = PathBuf::from(path);
    if p.is_dir() {
        return resolve_all_save_pairs_from_dir(&p);
    }
    // Single file: return one pair via the existing resolver
    let pair = resolve_save_pair(path)?;
    Ok(vec![pair])
}

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::keys::TitleKeyset;
use crate::keys::sizes::SEALED_KEY_MAGIC;
use crate::pfs::{Pfs, PfsOpenOptions, PfsSdHeader, prepare_sd_keyset_from_sealed};
use crate::sfo::{read_savedata_blocks, read_string};

/// Hardcoded workdir shared by resign/reregion: source files are extracted
/// here, patched in place, then the directory is repacked. Contents are wiped
/// after each run but the directory itself is kept.
pub const WORKDIR: &str = "workdir";

/// Remove any previous contents and recreate the workdir, returning its path.
pub fn prepare_workdir() -> crate::Result<PathBuf> {
    let workdir = Path::new(WORKDIR);
    if workdir.exists() {
        std::fs::remove_dir_all(workdir)?;
    }
    std::fs::create_dir_all(workdir)?;
    println!("workdir: {}", workdir.display());
    Ok(workdir.to_path_buf())
}

/// Empty the workdir for the next run but leave the directory itself.
pub fn cleanup_workdir(workdir: &Path) -> crate::Result<()> {
    for entry in std::fs::read_dir(workdir)? {
        let p = entry?.path();
        if p.is_dir() {
            std::fs::remove_dir_all(&p)?;
        } else {
            std::fs::remove_file(&p)?;
        }
    }
    Ok(())
}

fn walkdir_find(dir: &Path) -> crate::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walkdir_find(&p)?);
            } else {
                out.push(p);
            }
        }
    }
    Ok(out)
}

/// Find a named system file (e.g. `param.sfo`, `keystone`) in an extracted tree.
pub fn locate_file(
    tmp: &Path,
    written: &[(PathBuf, u64, bool)],
    name: &str,
) -> crate::Result<PathBuf> {
    let rel = written
        .iter()
        .map(|(p, _, _)| p)
        .find(|p| p.file_name().map(|n| n == name).unwrap_or(false) && p.components().count() >= 2);
    let path = match rel {
        Some(p) => tmp.join(p),
        None => {
            // Fallback: any matching file under the tree.
            let mut found = None;
            for entry in walkdir_find(tmp)? {
                if entry.file_name().and_then(|n| n.to_str()) == Some(name) {
                    found = Some(entry);
                    break;
                }
            }
            found.ok_or_else(|| {
                crate::Error::Message(format!("no {name} found in source save"))
            })?
        }
    };
    Ok(path)
}

/// Given a save path (file or directory), resolve the sealed key + PFS image pair.
/// Returns `(sealed_path, image_path)`.
///
/// - If path is a file: detect by magic and derive the sibling.
/// - If path is a directory: scan inside for a `.bin` + image pair.
pub fn resolve_save_pair(path: &str) -> crate::Result<(PathBuf, PathBuf)> {
    let p = PathBuf::from(path);

    // Directory: scan for save pairs inside
    if p.is_dir() {
        let pairs = resolve_all_save_pairs_from_dir(&p)?;
        if pairs.len() == 1 {
            return Ok(pairs.into_iter().next().unwrap());
        }
        return Err(crate::Error::Message(format!(
            "{} contains {} save pairs — use decrypt or encrypt to handle all at once",
            p.display(),
            pairs.len()
        )));
    }

    // File: detect by magic and derive sibling
    let mut file = std::fs::File::open(&p)?;
    let mut magic = [0u8; 8];
    if file.read_exact(&mut magic).is_err() {
        // File too short for magic → treat as image (sealed key is always 0x60 bytes).
        let sibling = PathBuf::from(format!("{path}.bin"));
        if !sibling.exists() {
            return Err(crate::Error::Message(format!(
                "cannot find sealed key {sibling:?} next to image {path:?}"
            )));
        }
        return Ok((sibling, p));
    }
    if magic == *SEALED_KEY_MAGIC {
        // Sealed key file → derive image by stripping .bin
        let sealed = p.clone();
        let image = if p.extension().map(|e| e == "bin").unwrap_or(false) {
            p.with_extension("")
        } else {
            p.clone()
        };
        if !image.exists() {
            return Err(crate::Error::Message(format!(
                "cannot find PFS image {:?} next to sealed key {sealed:?}",
                image
            )));
        }
        Ok((sealed, image))
    } else {
        // PFS image → derive sealed key by appending .bin
        let image = p.clone();
        let sealed = PathBuf::from(format!("{path}.bin"));
        if !sealed.exists() {
            return Err(crate::Error::Message(format!(
                "cannot find sealed key {sealed:?} next to image {image:?}"
            )));
        }
        Ok((sealed, image))
    }
}

/// Scan a directory for save pairs: `.bin` files (sealed keys) matched with
/// non-`.bin` files (PFS images) sharing the same base name.
fn resolve_all_save_pairs_from_dir(dir: &Path) -> crate::Result<Vec<(PathBuf, PathBuf)>> {
    let mut bins: Vec<PathBuf> = Vec::new();
    let mut images: Vec<PathBuf> = Vec::new();

    for entry in std::fs::read_dir(dir)?.flatten() {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let name = p.file_name().unwrap_or_default().to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        if name.ends_with(".bin") {
            bins.push(p);
        } else {
            images.push(p);
        }
    }

    let mut pairs = Vec::new();
    let mut used_images = Vec::new();

    for bin in &bins {
        let stem = bin.file_stem().unwrap_or_default().to_string_lossy();
        if let Some(idx) = images.iter().position(|i| {
            i.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .eq_ignore_ascii_case(&stem)
        }) {
            pairs.push((bin.clone(), images.remove(idx)));
            used_images.push(idx);
        }
    }

    if pairs.is_empty() {
        return Err(crate::Error::Message(format!(
            "no save pair found in {} (need a .bin + image)",
            dir.display()
        )));
    }

    Ok(pairs)
}

/// Read TITLE_ID from an opened save's param.sfo.
pub fn read_title_id(ctx: &SaveContext) -> crate::Result<String> {
    let sfo = read_save_file_bytes(ctx, "param.sfo")?
        .ok_or_else(|| crate::Error::Message("save has no param.sfo".into()))?;
    read_string(&sfo, "TITLE_ID")?
        .ok_or_else(|| crate::Error::Message("save has no TITLE_ID".into()))
}

/// Read TITLE_ID from a param.sfo on disk (e.g. inside an extracted folder).
pub fn read_title_id_from_dir(dir: &Path) -> crate::Result<String> {
    let sfo_path = dir.join("sce_sys").join("param.sfo");
    let sfo = std::fs::read(&sfo_path).map_err(|_| {
        crate::Error::Message(format!("cannot read {}", sfo_path.display()))
    })?;
    read_string(&sfo, "TITLE_ID")?
        .ok_or_else(|| crate::Error::Message("param.sfo has no TITLE_ID".into()))
}

/// Read SAVEDATA_DIRECTORY from a param.sfo on disk (e.g. inside an extracted folder).
pub fn read_savedata_directory_from_dir(dir: &Path) -> crate::Result<Option<String>> {
    let sfo_path = dir.join("sce_sys").join("param.sfo");
    let sfo = std::fs::read(&sfo_path).map_err(|_| {
        crate::Error::Message(format!("cannot read {}", sfo_path.display()))
    })?;
    read_string(&sfo, "SAVEDATA_DIRECTORY")
}

/// Read SAVEDATA_BLOCKS from a param.sfo on disk (e.g. inside an extracted folder).
pub fn read_savedata_blocks_from_dir(dir: &Path) -> crate::Result<Option<u64>> {
    let sfo_path = dir.join("sce_sys").join("param.sfo");
    let sfo = std::fs::read(&sfo_path).map_err(|_| {
        crate::Error::Message(format!("cannot read {}", sfo_path.display()))
    })?;
    read_savedata_blocks(&sfo)
}

/// Derive output path: `{operation}/{title_id}/{name}` (name is optional).
pub fn derive_output_path(operation: &str, title_id: &str, name: &str) -> PathBuf {
    let base = PathBuf::from(operation).join(title_id);
    if name.is_empty() {
        base
    } else {
        base.join(name)
    }
}

/// Everything needed by a save-oriented command: config, SD header, derived
/// keys, and the opened PFS.
pub struct SaveContext {
    pub cfg: Config,
    pub hdr: PfsSdHeader,
    pub keyset: TitleKeyset,
    pub fs: Pfs,
    pub sealed_key_version: u16,
}

/// Shared boilerplate: load config, read the SD header, derive keys, open the PFS.
pub fn open_save(config: &str, sealed: &str, pfs: &str) -> crate::Result<SaveContext> {
    let cfg = Config::load(config)?;
    open_save_cfg(&cfg, sealed, pfs)
}

/// Same as `open_save` but accepts an already-loaded Config.
pub fn open_save_cfg(cfg: &Config, sealed: &str, pfs: &str) -> crate::Result<SaveContext> {
    let hdr = PfsSdHeader::from_file(pfs)?;
    let sealed = crate::keys::SealedKey::from_file(sealed)?;
    let sealed_key_version = sealed.version;
    let keyset = prepare_sd_keyset_from_sealed(&cfg.common, &sealed, &hdr)?;
    let fs = Pfs::open(pfs, &keyset, &PfsOpenOptions::default())?;
    Ok(SaveContext {
        cfg: cfg.clone(),
        hdr,
        keyset,
        fs,
        sealed_key_version,
    })
}
