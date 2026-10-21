use std::collections::HashMap;
use std::path::Path;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use crate::config::Config;
use crate::keys::decrypt_sealed_key;
use crate::pfs::{Pfs, PfsOpenOptions, PfsSdHeader, prepare_sd_keyset_from_sealed};
use crate::pfs::{EncryptOptions, encrypt_dir};
use crate::pfs::PfsEntryType;
use crate::sfo;

fn to_py_err(e: crate::Error) -> PyErr {
    PyValueError::new_err(e.to_string())
}

fn io_err(e: std::io::Error) -> PyErr {
    PyValueError::new_err(e.to_string())
}

/// Derive the sealed key + image pair from a path.
fn resolve_pair(path: &str) -> PyResult<(std::path::PathBuf, std::path::PathBuf)> {
    let p = std::path::PathBuf::from(path);
    if p.is_dir() {
        super::commands::resolve_all_save_pairs(path)
            .map_err(to_py_err)?
            .into_iter()
            .next()
            .ok_or_else(|| PyValueError::new_err(format!("no save pair found in {path}")))
    } else {
        super::commands::resolve_save_pair(path).map_err(to_py_err)
    }
}

/// Combine `outdir` with a file `name`. Existing directories (or paths ending
/// in a path separator) receive the named file inside; otherwise `outdir` is
/// used as the output file prefix itself (pair written to `outdir` + `.bin`).
fn output_with_name(outdir: &str, name: &str) -> std::path::PathBuf {
    let p = std::path::PathBuf::from(outdir);
    let wants_dir = p.is_dir() || outdir.ends_with('/') || outdir.ends_with('\\');
    if wants_dir {
        p.join(name)
    } else {
        p
    }
}

/// Resolve config from either a file path string or a Config object.
/// None defaults to "config.ini".
fn resolve_config(config: Option<&PyObject>, py: Python<'_>) -> PyResult<Config> {
    match config {
        None => Config::load("config.ini").map_err(to_py_err),
        Some(obj) => {
            let any = obj.bind(py);
            if let Ok(s) = any.extract::<String>() {
                Config::load(&s).map_err(to_py_err)
            } else if let Ok(py_cfg) = any.extract::<PyConfig>() {
                Ok(py_cfg.0.clone())
            } else {
                Err(PyValueError::new_err("config must be a file path string or Config object"))
            }
        }
    }
}

/// Python wrapper around Config.
#[pyclass(name = "Config")]
#[derive(Clone)]
struct PyConfig(Config);

#[pymethods]
impl PyConfig {
    #[staticmethod]
    fn from_file(path: &str) -> PyResult<Self> {
        Ok(PyConfig(Config::load(path).map_err(to_py_err)?))
    }

    #[staticmethod]
    fn from_str(content: &str) -> PyResult<Self> {
        Ok(PyConfig(Config::from_str(content).map_err(to_py_err)?))
    }
}

/// Parse an account ID string (hex, 0x-prefixed hex, or decimal) to an integer.
#[pyfunction]
fn parse_account_id(input: &str) -> PyResult<u64> {
    sfo::parse_account_id(input).map_err(to_py_err)
}

/// Decrypt a single save pair to `outdir`. Returns list of (path, size, compressed).
fn decrypt_one_pair(
    cfg: &Config,
    sealed: &std::path::Path,
    pfs_path: &std::path::Path,
    outdir: &std::path::Path,
) -> PyResult<Vec<(String, u64, bool)>> {
    let hdr = PfsSdHeader::from_file(pfs_path).map_err(to_py_err)?;
    let sealed_key = crate::keys::SealedKey::from_file(sealed).map_err(to_py_err)?;
    let keyset = prepare_sd_keyset_from_sealed(&cfg.common, &sealed_key, &hdr).map_err(to_py_err)?;
    let fs = Pfs::open(pfs_path, &keyset, &PfsOpenOptions::default()).map_err(to_py_err)?;

    std::fs::create_dir_all(outdir).map_err(io_err)?;

    let mut written = Vec::new();
    for e in fs.enum_user_root_directory().map_err(to_py_err)? {
        if e.entry_type != PfsEntryType::File { continue; }
        let f = fs.get_file(e.ino).map_err(to_py_err)?;
        let mut buf = vec![0u8; f.file_size as usize];
        fs.file_read(&f, 0, &mut buf).map_err(to_py_err)?;
        let dest = outdir.join(&e.path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(io_err)?;
        }
        std::fs::write(&dest, &buf).map_err(io_err)?;
        written.push((e.path, f.file_size, f.is_compressed()));
    }

    Ok(written)
}

/// Decrypt a save to a directory. Accepts a single save pair (file, or directory
/// containing one pair) or a directory containing multiple pairs (e.g. DATA,
/// DATA1, DATA2 under the same CUSA folder, which are decrypted into
/// `<outdir>/<image_name>/`). Returns list of (path, size, compressed).
#[pyfunction]
#[pyo3(signature = (save, outdir=None, config=None))]
fn decrypt_save(py: Python<'_>, save: &str, outdir: Option<&str>, config: Option<PyObject>) -> PyResult<Vec<(String, u64, bool)>> {
    let cfg = resolve_config(config.as_ref(), py)?;
    let pairs = super::commands::resolve_all_save_pairs(save).map_err(to_py_err)?;
    if pairs.is_empty() {
        return Err(PyValueError::new_err(format!("no save pair found in {save}")));
    }

    // Single pair (or single file): decrypt flat into outdir as before.
    if pairs.len() == 1 {
        let (sealed, pfs_path) = &pairs[0];
        let out_path = match outdir {
            Some(o) => std::path::PathBuf::from(o),
            None => {
                let title_id = {
                    let ctx = super::commands::open_save_cfg(
                        &cfg,
                        sealed.to_str().unwrap(),
                        pfs_path.to_str().unwrap(),
                    )
                        .map_err(to_py_err)?;
                    super::commands::read_title_id(&ctx).map_err(to_py_err)?
                };
                super::commands::derive_output_path("decrypted", &title_id, "")
            }
        };
        return decrypt_one_pair(&cfg, sealed, pfs_path, &out_path);
    }

    // Multiple pairs: decrypt each into `<outdir>/<image_name>/`.
    let title_id = {
        let ctx = super::commands::open_save_cfg(
            &cfg,
            pairs[0].0.to_str().unwrap(),
            pairs[0].1.to_str().unwrap(),
        )
            .map_err(to_py_err)?;
        super::commands::read_title_id(&ctx).map_err(to_py_err)?
    };
    let base_out = match outdir {
        Some(o) => std::path::PathBuf::from(o),
        None => super::commands::derive_output_path("decrypted", &title_id, ""),
    };

    let mut written = Vec::new();
    for (sealed, pfs_path) in &pairs {
        let name = pfs_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        written.extend(decrypt_one_pair(&cfg, sealed, pfs_path, &base_out.join(&name))?);
    }
    Ok(written)
}

/// Encrypt a directory back into a save. Returns stats dict.
#[pyfunction]
#[pyo3(signature = (input, outdir=None, compress=false, blocks=None, config=None))]
fn encrypt_save(
    py: Python<'_>,
    input: &str,
    outdir: Option<&str>,
    compress: bool,
    blocks: Option<usize>,
    config: Option<PyObject>,
) -> PyResult<HashMap<&'static str, u64>> {
    let cfg = resolve_config(config.as_ref(), py)?;
    let input_path = Path::new(input);

    let total_blocks = match blocks {
        Some(b) => b,
        None => {
            let sfo_path = input_path.join("sce_sys").join("param.sfo");
            let sfo = std::fs::read(&sfo_path).map_err(io_err)?;
            sfo::read_savedata_blocks(&sfo)
                .map_err(to_py_err)?
                .unwrap_or_else(|| {
                    eprintln!("warning: param.sfo has no SAVEDATA_BLOCKS, autosizing");
                    0
                }) as usize
        }
    };

    let out_path = match outdir {
        Some(o) => {
            let name = input_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "output".into());
            output_with_name(o, &name)
        }
        None => {
            let sfo_path = input_path.join("sce_sys").join("param.sfo");
            let sfo = std::fs::read(&sfo_path).map_err(io_err)?;
            let title_id = sfo::read_string(&sfo, "TITLE_ID")
                .map_err(to_py_err)?
                .ok_or_else(|| PyValueError::new_err("param.sfo has no TITLE_ID"))?;
            let save_name = sfo::read_string(&sfo, "SAVEDATA_DIRECTORY")
                .map_err(to_py_err)?
                .unwrap_or_else(|| title_id.clone());
            super::commands::derive_output_path("encrypted", &title_id, &save_name)
        }
    };

    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).map_err(io_err)?;
    }

    let opts = EncryptOptions {
        total_blocks,
        auto_blocks: blocks.is_none(),
        compress_files: compress,
        ..Default::default()
    };
    let stats = encrypt_dir(&cfg.common, input_path, &out_path, &opts).map_err(to_py_err)?;

    let mut result = HashMap::new();
    result.insert("used_blocks", stats.used_blocks);
    result.insert("used_inodes", stats.used_inodes as u64);
    result.insert("backup_block", stats.backup_block);
    result.insert("total_blocks", stats.total_blocks as u64);
    result.insert("total_inodes", stats.total_inodes as u64);
    result.insert("image_size", stats.image_size as u64);
    Ok(result)
}

/// Resign a save (patch ACCOUNT_ID) in-place, preserving the original block layout.
/// Accepts a single save pair (file or directory with one pair) or a directory with
/// multiple pairs (e.g. DATA, DATA1, DATA2 under the same CUSA folder).
#[pyfunction]
#[pyo3(signature = (save, account_id, outdir=None, compress=false, config=None))]
fn resign_save(
    py: Python<'_>,
    save: &str,
    account_id: &str,
    outdir: Option<&str>,
    compress: bool,
    config: Option<PyObject>,
) -> PyResult<HashMap<&'static str, u64>> {
    let cfg = resolve_config(config.as_ref(), py)?;
    let new_id = sfo::parse_account_id(account_id).map_err(to_py_err)?;

    // For directories with multiple pairs, iterate them.
    let pairs = super::commands::resolve_all_save_pairs(save).map_err(to_py_err)?;
    if pairs.is_empty() {
        return Err(PyValueError::new_err(format!("no save pair found in {save}")));
    }

    for (sealed, pfs) in &pairs {
        let original_name = pfs.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "output".into());

        let out_path = match outdir {
            Some(o) => {
                if pairs.len() > 1 {
                    std::path::PathBuf::from(o).join(&original_name)
                } else {
                    output_with_name(o, &original_name)
                }
            }
            None => {
                let title_id = {
                    let ctx = super::commands::open_save_cfg(&cfg, sealed.to_str().unwrap(), pfs.to_str().unwrap())
                        .map_err(to_py_err)?;
                    super::commands::read_title_id(&ctx).map_err(to_py_err)?
                };
                super::commands::derive_output_path("resigned", &title_id, &original_name)
            }
        };
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent).map_err(io_err)?;
        }

        super::commands::resign::resign_inplace(&cfg, sealed.to_str().unwrap(), pfs.to_str().unwrap(), new_id, &out_path)
            .map_err(to_py_err)?;
        let _ = compress;
    }

    let mut result = HashMap::new();
    result.insert("ok", 1u64);
    Ok(result)
}

/// Re-region a save in-place using a sample save from the target region.
/// Copies the source PFS image, patches TITLE_ID / SAVEDATA_DIRECTORY / ACCOUNT_ID
/// from the sample, replaces keystone, and recomputes hashes — preserving the original block layout.
#[pyfunction]
#[pyo3(signature = (save, sample, account_id=None, outdir=None, compress=false, config=None))]
fn reregion_save(
    py: Python<'_>,
    save: &str,
    sample: &str,
    account_id: Option<&str>,
    outdir: Option<&str>,
    compress: bool,
    config: Option<PyObject>,
) -> PyResult<HashMap<&'static str, u64>> {
    let cfg = resolve_config(config.as_ref(), py)?;
    let new_id = account_id.map(|a| sfo::parse_account_id(a)).transpose().map_err(to_py_err)?;

    let pairs = super::commands::resolve_all_save_pairs(save).map_err(to_py_err)?;
    if pairs.is_empty() {
        return Err(PyValueError::new_err(format!("no save pair found in {save}")));
    }
    let (sample_sealed, sample_pfs) = super::commands::resolve_save_pair(sample).map_err(to_py_err)?;

    // Read sample identity once.
    let sample_ctx = super::commands::open_save_cfg(&cfg, sample_sealed.to_str().unwrap(), sample_pfs.to_str().unwrap())
        .map_err(to_py_err)?;
    let sample_sfo = super::commands::read_save_file_bytes(&sample_ctx, "param.sfo").map_err(to_py_err)?
        .ok_or_else(|| PyValueError::new_err("sample save has no param.sfo"))?;
    let sample_keystone = super::commands::read_save_file_bytes(&sample_ctx, "keystone").map_err(to_py_err)?
        .ok_or_else(|| PyValueError::new_err("sample save has no keystone"))?;
    let target_title_id = sfo::read_string(&sample_sfo, "TITLE_ID").map_err(to_py_err)?
        .ok_or_else(|| PyValueError::new_err("sample save has no TITLE_ID"))?;
    let target_dir = sfo::read_string(&sample_sfo, "SAVEDATA_DIRECTORY").map_err(to_py_err)?;

    for (src_sealed, src_pfs) in &pairs {
        let original_name = src_pfs
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "output".into());

        let out_path = match outdir {
            Some(o) => {
                if pairs.len() > 1 {
                    std::path::PathBuf::from(o).join(&original_name)
                } else {
                    output_with_name(o, &original_name)
                }
            }
            None => {
                if pairs.len() > 1 {
                    super::commands::derive_output_path("reregioned", &target_title_id, &original_name)
                } else {
                    let save_name = target_dir.as_deref().unwrap_or("ManualSave");
                    super::commands::derive_output_path("reregioned", &target_title_id, save_name)
                }
            }
        };
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent).map_err(io_err)?;
        }

        super::commands::reregion::reregion_inplace(
            &cfg,
            src_sealed.to_str().unwrap(),
            src_pfs.to_str().unwrap(),
            &sample_sfo,
            &sample_keystone,
            &target_title_id,
            target_dir.as_deref(),
            new_id,
            &out_path,
        ).map_err(to_py_err)?;
    }
    let _ = compress;

    let mut result = HashMap::new();
    result.insert("ok", 1u64);
    Ok(result)
}

/// Inspect a save and return its info as a dict.
#[pyfunction]
#[pyo3(signature = (save, config=None))]
fn inspect_save(py: Python<'_>, save: &str, config: Option<PyObject>) -> PyResult<HashMap<String, PyObject>> {
    let cfg = resolve_config(config.as_ref(), py)?;
    let (sealed, pfs_path) = resolve_pair(save)?;
    let hdr = PfsSdHeader::from_file(&pfs_path).map_err(to_py_err)?;
    let sealed_key = crate::keys::SealedKey::from_file(&sealed).map_err(to_py_err)?;
    let sealed_key_version = sealed_key.version;
    let keyset = prepare_sd_keyset_from_sealed(&cfg.common, &sealed_key, &hdr).map_err(to_py_err)?;
    let fs = Pfs::open(&pfs_path, &keyset, &PfsOpenOptions::default()).map_err(to_py_err)?;

    let mut info = HashMap::new();

    let _mkey = decrypt_sealed_key(&cfg.common, &sealed_key).map_err(to_py_err)?;
    info.insert("sealed_key_version".into(), sealed_key_version.into_pyobject(py)?.into_any().unbind());
    info.insert("block_size".into(), hdr.basic_block_size.into_pyobject(py)?.into_any().unbind());
    info.insert("sd_key_ver".into(), hdr.sd_key_ver.into_pyobject(py)?.into_any().unbind());
    info.insert("encrypted".into(), (hdr.is_encrypted() as u8).into_pyobject(py)?.into_any().unbind());
    info.insert("signed".into(), (hdr.is_signed() as u8).into_pyobject(py)?.into_any().unbind());
    info.insert("dinode_count".into(), fs.hdr.dinode_count.into_pyobject(py)?.into_any().unbind());
    info.insert("data_block_count".into(), fs.hdr.data_block_count.into_pyobject(py)?.into_any().unbind());
    info.insert("super_root_ino".into(), fs.super_root_dir_ino.into_pyobject(py)?.into_any().unbind());

    for e in fs.enum_user_root_directory().map_err(to_py_err)? {
        if e.entry_type != PfsEntryType::File { continue; }
        let name = std::path::Path::new(&e.path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name.eq_ignore_ascii_case("param.sfo") {
            let f = fs.get_file(e.ino).map_err(to_py_err)?;
            let mut buf = vec![0u8; f.file_size as usize];
            fs.file_read(&f, 0, &mut buf).map_err(to_py_err)?;

            if let Ok(Some(tid)) = sfo::read_string(&buf, "TITLE_ID") {
                info.insert("title_id".into(), tid.into_pyobject(py)?.into_any().unbind());
            }
            if let Ok(id) = sfo::read_account_id(&buf) {
                info.insert("account_id".into(), format!("{id:016x}").into_pyobject(py)?.into_any().unbind());
            }
            break;
        }
    }

    let files: Vec<HashMap<String, PyObject>> = fs.enum_user_root_directory()
        .map_err(to_py_err)?
        .into_iter()
        .filter(|e| e.entry_type == PfsEntryType::File)
        .filter_map(|e| {
            let f = fs.get_file(e.ino).ok()?;
            let mut m = HashMap::new();
            m.insert("path".into(), e.path.into_pyobject(py).ok()?.into_any().unbind());
            m.insert("size".into(), (f.file_size as u64).into_pyobject(py).ok()?.into_any().unbind());
            m.insert("compressed".into(), (f.is_compressed() as u8).into_pyobject(py).ok()?.into_any().unbind());
            Some(m)
        })
        .collect();
    info.insert("files".into(), files.into_pyobject(py)?.into_any().unbind());

    Ok(info)
}

/// List files inside a save. Returns list of (path, size).
#[pyfunction]
#[pyo3(signature = (save, config=None))]
fn list_files(py: Python<'_>, save: &str, config: Option<PyObject>) -> PyResult<Vec<(String, u64)>> {
    let cfg = resolve_config(config.as_ref(), py)?;
    let (sealed, pfs_path) = resolve_pair(save)?;
    let hdr = PfsSdHeader::from_file(&pfs_path).map_err(to_py_err)?;
    let sealed_key = crate::keys::SealedKey::from_file(&sealed).map_err(to_py_err)?;
    let keyset = prepare_sd_keyset_from_sealed(&cfg.common, &sealed_key, &hdr).map_err(to_py_err)?;
    let fs = Pfs::open(&pfs_path, &keyset, &PfsOpenOptions::default()).map_err(to_py_err)?;

    let mut files = Vec::new();
    for e in fs.enum_user_root_directory().map_err(to_py_err)? {
        if e.entry_type == PfsEntryType::File {
            files.push((e.path, e.size));
        }
    }
    Ok(files)
}

/// Harvest a save's keystone (whole 96-byte stone) + identity into a dict
/// for a keystone database, or None when the save has no `sce_sys/keystone`.
#[pyfunction]
#[pyo3(signature = (save, config=None))]
fn keystone_extract(py: Python<'_>, save: &str, config: Option<PyObject>) -> PyResult<Option<HashMap<String, PyObject>>> {
    let cfg = resolve_config(config.as_ref(), py)?;
    let (sealed, pfs_path) = resolve_pair(save)?;
    let ctx = super::commands::open_save_cfg(
        &cfg,
        sealed.to_str().unwrap(),
        pfs_path.to_str().unwrap(),
    )
    .map_err(to_py_err)?;
    let stone = match super::commands::read_save_file_bytes(&ctx, "keystone").map_err(to_py_err)? {
        Some(b) => b,
        None => return Ok(None),
    };
    let title_id = super::commands::read_title_id(&ctx).map_err(to_py_err)?;
    let mut m = HashMap::new();
    m.insert("title_id".to_string(), title_id.into_pyobject(py)?.into_any().unbind());
    m.insert("stone".to_string(), stone.into_pyobject(py)?.into_any().unbind());
    Ok(Some(m))
}

/// Harvest a keystone from an already-decrypted folder tree
/// (`{dir}/sce_sys/keystone`). Returns dict or None when no keystone exists.
#[pyfunction]
fn keystone_extract_dir(py: Python<'_>, dir: &str) -> PyResult<Option<HashMap<String, PyObject>>> {
    let stone_path = std::path::Path::new(dir).join("sce_sys").join("keystone");
    let stone = match std::fs::read(&stone_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_err(e)),
    };
    let title_id = super::commands::read_title_id_from_dir(&stone_path.parent().and_then(|p| p.parent()).unwrap().to_path_buf()).map_err(to_py_err)?;
    let mut m = HashMap::new();
    m.insert("title_id".to_string(), title_id.into_pyobject(py)?.into_any().unbind());
    m.insert("stone".to_string(), stone.into_pyobject(py)?.into_any().unbind());
    Ok(Some(m))
}

/// Python module definition
#[pymodule]
fn ps4save_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyConfig>()?;
    m.add_function(wrap_pyfunction!(parse_account_id, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_save, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_save, m)?)?;
    m.add_function(wrap_pyfunction!(resign_save, m)?)?;
    m.add_function(wrap_pyfunction!(reregion_save, m)?)?;
    m.add_function(wrap_pyfunction!(inspect_save, m)?)?;
    m.add_function(wrap_pyfunction!(list_files, m)?)?;
    m.add_function(wrap_pyfunction!(keystone_extract, m)?)?;
    m.add_function(wrap_pyfunction!(keystone_extract_dir, m)?)?;
    Ok(())
}
