//! Minimal param.sfo parser for resigning / re-regioning.
//!
//! Mirrors htos `utils/orbis.py`: the header is `<IIIII` (magic, version,
//! key_table_offset, data_table_offset, num_entries) and each index entry is
//! `<HHIII` (key_offset, param_format, param_length, param_max_length,
//! data_offset). Keys are NUL-terminated strings at key_table_offset +
//! key_offset; values live at data_table_offset + data_offset.
//!
//! ACCOUNT_ID is a uint64 (param_format 0x0404) stored little-endian, exactly
//! 8 bytes, so resigning is an in-place 8-byte overwrite that leaves the rest
//! of the file byte-identical. TITLE_ID / SAVEDATA_DIRECTORY are UTF-8
//! (0x0204) strings patched in place for re-regioning.

use crate::{Error, Result};

const SFO_MAGIC: u32 = 0x4653_5000; // "PSF\0" little-endian
const SFO_HEADER_SIZE: usize = 20;
const SFO_INDEX_SIZE: usize = 16;

const SFO_FORMAT_BINARY: u16 = 0x0004;
const SFO_FORMAT_UTF8: u16 = 0x0204;
const SFO_FORMAT_UINT64: u16 = 0x0604;

const ACCOUNT_ID_KEY: &str = "ACCOUNT_ID";
const ACCOUNT_ID_SIZE: usize = 8;
const SAVEDATA_BLOCKS_KEY: &str = "SAVEDATA_BLOCKS";
const SAVEDATA_BLOCKS_SIZE: usize = 8;

#[derive(Debug, Clone, Copy)]
struct SfoIndex {
    format: u16,
    length: u32,
    max_length: u32,
    data_offset: u32,
}

fn u16_at(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(data[off..off + 2].try_into().unwrap())
}

fn u32_at(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}

fn parse_header(data: &[u8]) -> Result<(usize, usize, u32, usize)> {
    if data.len() < SFO_HEADER_SIZE {
        return Err(Error::Message("param.sfo too small for header".into()));
    }
    if u32_at(data, 0) != SFO_MAGIC {
        return Err(Error::Message("invalid param.sfo magic".into()));
    }
    let key_table_offset = u32_at(data, 8) as usize;
    let data_table_offset = u32_at(data, 12) as usize;
    let num_entries = u32_at(data, 16) as usize;
    if num_entries > 12 {
        return Err(Error::Message("param.sfo has too many entries".into()));
    }
    Ok((key_table_offset, data_table_offset, u32_at(data, 4), num_entries))
}

/// Locate the index entry for `wanted`, returning
/// (index entry offset, entry fields, value offset) if present.
fn find_entry(data: &[u8], wanted: &str) -> Result<Option<(usize, SfoIndex, usize)>> {
    let (key_table_offset, data_table_offset, _version, num_entries) = parse_header(data)?;
    for i in 0..num_entries {
        let off = SFO_HEADER_SIZE + i * SFO_INDEX_SIZE;
        let key_start = key_table_offset + u16_at(data, off) as usize;
        let key_end = data[key_start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| key_start + p)
            .ok_or_else(|| Error::Message("param.sfo key not NUL-terminated".into()))?;
        let key = std::str::from_utf8(&data[key_start..key_end])
            .map_err(|_| Error::Message("param.sfo key is not valid UTF-8".into()))?;
        if key == wanted {
            let idx = SfoIndex {
                format: u16_at(data, off + 2),
                length: u32_at(data, off + 4),
                max_length: u32_at(data, off + 8),
                data_offset: u32_at(data, off + 12),
            };
            let value_off = data_table_offset + idx.data_offset as usize;
            return Ok(Some((off, idx, value_off)));
        }
    }
    Ok(None)
}

fn find_account_id(data: &[u8]) -> Result<(SfoIndex, usize)> {
    let (index_off, idx, value_off) = find_entry(data, ACCOUNT_ID_KEY)?
        .ok_or_else(|| Error::Message("param.sfo missing ACCOUNT_ID".into()))?;
    if idx.format != SFO_FORMAT_BINARY && idx.format != SFO_FORMAT_UINT64 {
        return Err(Error::Message("param.sfo ACCOUNT_ID is not a uint64".into()));
    }
    if idx.max_length < ACCOUNT_ID_SIZE as u32 || idx.length < ACCOUNT_ID_SIZE as u32 {
        return Err(Error::Message("param.sfo ACCOUNT_ID is too small".into()));
    }
    if value_off + ACCOUNT_ID_SIZE > data.len() {
        return Err(Error::Message("param.sfo ACCOUNT_ID value out of range".into()));
    }
    let _ = index_off;
    Ok((idx, value_off))
}

/// Read the account id (uint64 LE) stored in a param.sfo.
pub fn read_account_id(data: &[u8]) -> Result<u64> {
    let (_idx, value_off) = find_account_id(data)?;
    Ok(u64::from_le_bytes(data[value_off..value_off + ACCOUNT_ID_SIZE].try_into().unwrap()))
}

/// Byte offset of the ACCOUNT_ID value within a param.sfo (for in-place patch).
pub fn account_id_offset(data: &[u8]) -> Result<usize> {
    let (_idx, value_off) = find_account_id(data)?;
    Ok(value_off)
}

/// Read the SAVEDATA_BLOCKS (uint64 LE) stored in a param.sfo.
pub fn read_savedata_blocks(data: &[u8]) -> Result<Option<u64>> {
    let Some((_index_off, idx, value_off)) = find_entry(data, SAVEDATA_BLOCKS_KEY)? else {
        return Ok(None);
    };
    if idx.max_length < SAVEDATA_BLOCKS_SIZE as u32 || idx.length < SAVEDATA_BLOCKS_SIZE as u32 {
        return Err(Error::Message("param.sfo SAVEDATA_BLOCKS is too small".into()));
    }
    if value_off + SAVEDATA_BLOCKS_SIZE > data.len() {
        return Err(Error::Message("param.sfo SAVEDATA_BLOCKS value out of range".into()));
    }
    Ok(Some(u64::from_le_bytes(
        data[value_off..value_off + SAVEDATA_BLOCKS_SIZE]
            .try_into()
            .unwrap(),
    )))
}

/// Replace the ACCOUNT_ID value with `new_id`, leaving all other bytes intact.
pub fn patch_account_id(data: &[u8], new_id: u64) -> Result<Vec<u8>> {
    let (_idx, value_off) = find_account_id(data)?;
    let mut out = data.to_vec();
    out[value_off..value_off + ACCOUNT_ID_SIZE].copy_from_slice(&new_id.to_le_bytes());
    Ok(out)
}

/// Byte offset of the SAVEDATA_BLOCKS value within a param.sfo, if present
/// (for an in-place 8-byte overwrite).
pub fn savedata_blocks_offset(data: &[u8]) -> Result<Option<usize>> {
    let Some((_index_off, idx, value_off)) = find_entry(data, SAVEDATA_BLOCKS_KEY)? else {
        return Ok(None);
    };
    if idx.max_length < SAVEDATA_BLOCKS_SIZE as u32 || idx.length < SAVEDATA_BLOCKS_SIZE as u32 {
        return Err(Error::Message("param.sfo SAVEDATA_BLOCKS is too small".into()));
    }
    if value_off + SAVEDATA_BLOCKS_SIZE > data.len() {
        return Err(Error::Message("param.sfo SAVEDATA_BLOCKS value out of range".into()));
    }
    Ok(Some(value_off))
}

/// Replace the SAVEDATA_BLOCKS value with `new_blocks`, leaving all other
/// bytes intact. Returns `Ok(None)` if the key is not present.
pub fn patch_savedata_blocks(data: &[u8], new_blocks: u64) -> Result<Option<Vec<u8>>> {
    let Some(value_off) = savedata_blocks_offset(data)? else {
        return Ok(None);
    };
    let mut out = data.to_vec();
    out[value_off..value_off + SAVEDATA_BLOCKS_SIZE].copy_from_slice(&new_blocks.to_le_bytes());
    Ok(Some(out))
}

/// Read a UTF-8 string value (e.g. TITLE_ID, SAVEDATA_DIRECTORY). Returns
/// `Ok(None)` if the key is not present.
pub fn read_string(data: &[u8], key: &str) -> Result<Option<String>> {
    let Some((_index_off, idx, value_off)) = find_entry(data, key)? else {
        return Ok(None);
    };
    if idx.format != SFO_FORMAT_UTF8 {
        return Err(Error::Message(format!("param.sfo {key} is not a UTF-8 string")));
    }
    let len = idx.length as usize;
    if value_off + len > data.len() {
        return Err(Error::Message(format!("param.sfo {key} value out of range")));
    }
    let raw = &data[value_off..value_off + len];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let value = std::str::from_utf8(&raw[..end])
        .map_err(|_| Error::Message(format!("param.sfo {key} is not valid UTF-8")))?
        .to_owned();
    Ok(Some(value))
}

/// Replace all occurrences of `old_title` with `new_title` as raw bytes.
/// Used to patch the TITLE_ID embedded inside binary SFO fields like PARAMS.
pub fn patch_title_id_raw(data: &mut [u8], old_title: &str, new_title: &str) {
    let old = old_title.as_bytes();
    let new = new_title.as_bytes();
    if old.len() != new.len() || old.len() == 0 {
        return;
    }
    let mut off = 0;
    while let Some(pos) = data[off..].windows(old.len()).position(|w| w == old) {
        let abs = off + pos;
        data[abs..abs + old.len()].copy_from_slice(new);
        off = abs + old.len();
    }
}

/// Replace a UTF-8 string value with `value`, updating the entry length and
/// zero-filling the remainder of the slot. Fails if it does not fit the slot.
pub fn patch_string(data: &[u8], key: &str, value: &str) -> Result<Vec<u8>> {
    let (index_off, idx, value_off) = find_entry(data, key)?
        .ok_or_else(|| Error::Message(format!("param.sfo missing {key}")))?;
    if idx.format != SFO_FORMAT_UTF8 {
        return Err(Error::Message(format!("param.sfo {key} is not a UTF-8 string")));
    }
    let max_len = idx.max_length as usize;
    let need = value.len() + 1; // NUL terminator
    if need > max_len {
        return Err(Error::Message(format!(
            "param.sfo {key} value too long for slot ({need} > {max_len})"
        )));
    }
    if value_off + max_len > data.len() {
        return Err(Error::Message(format!("param.sfo {key} value out of range")));
    }
    let mut out = data.to_vec();
    out[value_off..value_off + max_len].fill(0);
    out[value_off..value_off + value.len()].copy_from_slice(value.as_bytes());
    out[index_off + 4..index_off + 8].copy_from_slice(&(need as u32).to_le_bytes());
    Ok(out)
}

/// Parse a user-supplied account id: bare 16-hex, `0x`-prefixed hex, or a
/// decimal PSN user id (mirrors htos `handle_accid`/`checkid`).
pub fn parse_account_id(input: &str) -> Result<u64> {
    let s = input.trim();
    let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let is_hex_prefixed = hex.len() != s.len();
    if (is_hex_prefixed || hex.len() == 16) && hex.len() == 16 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return u64::from_str_radix(hex, 16)
            .map_err(|_| Error::Message("invalid account id hex".into()));
    }
    if s.chars().all(|c| c.is_ascii_digit()) {
        return s
            .parse::<u64>()
            .map_err(|_| Error::Message("invalid decimal account id".into()));
    }
    Err(Error::Message(
        "account id must be 16 hex chars, 0x-prefixed hex, or a decimal user id".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_sfo(account_id: u64) -> Vec<u8> {
        // 4 entries: TITLE_ID (utf8), ACCOUNT_ID (uint64), ATTRIBUTE (uint32),
        // SAVEDATA_BLOCKS (uint64)
        let keys = [
            "TITLE_ID\0",
            "ACCOUNT_ID\0",
            "ATTRIBUTE\0",
            "SAVEDATA_BLOCKS\0",
        ];
        let vals: Vec<Vec<u8>> = vec![
            b"CUSA12345\0".to_vec(),
            account_id.to_le_bytes().to_vec(),
            0x0000_0001u32.to_le_bytes().to_vec(),
            960u64.to_le_bytes().to_vec(),
        ];
        let num = keys.len();
        let key_table_offset = SFO_HEADER_SIZE + num * SFO_INDEX_SIZE;
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
            let fmt = if key == "ACCOUNT_ID\0" || key == "SAVEDATA_BLOCKS\0" {
                SFO_FORMAT_BINARY
            } else {
                0x0204
            }; // 0x0204 = UTF-8
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
        out
    }

    #[test]
    fn account_id_roundtrip() {
        let sfo = build_sfo(0x0123_4567_89AB_CDEF);
        assert_eq!(read_account_id(&sfo).unwrap(), 0x0123_4567_89AB_CDEF);

        let new_id = 0xC0A8_0000_0000_0001;
        let patched = patch_account_id(&sfo, new_id).unwrap();
        assert_eq!(read_account_id(&patched).unwrap(), new_id);
        // Only the 8 ACCOUNT_ID bytes change.
        assert_eq!(patched.len(), sfo.len());
        assert_eq!(
            patched
                .iter()
                .zip(sfo.iter())
                .filter(|(a, b)| a != b)
                .count(),
            8
        );
    }

    #[test]
    fn savedata_blocks_roundtrip() {
        let sfo = build_sfo(0);
        assert_eq!(read_savedata_blocks(&sfo).unwrap(), Some(960));
        assert!(savedata_blocks_offset(&sfo).unwrap().is_some());

        let new_blocks = 0x0123_4567_89AB_CDEF;
        let patched = patch_savedata_blocks(&sfo, new_blocks).unwrap().unwrap();
        assert_eq!(read_savedata_blocks(&patched).unwrap(), Some(new_blocks));
        // Only the 8 SAVEDATA_BLOCKS bytes change.
        assert_eq!(patched.len(), sfo.len());
        assert_eq!(
            patched
                .iter()
                .zip(sfo.iter())
                .filter(|(a, b)| a != b)
                .count(),
            8
        );

        // Missing key -> None.
        let sans_sfo = build_sfo_without_blocks(0);
        assert!(patch_savedata_blocks(&sans_sfo, 3704).unwrap().is_none());
    }

    fn build_sfo_without_blocks(account_id: u64) -> Vec<u8> {
        // Same layout as build_sfo but without the SAVEDATA_BLOCKS entry.
        let keys = ["TITLE_ID\0", "ACCOUNT_ID\0", "ATTRIBUTE\0"];
        let vals: Vec<Vec<u8>> = vec![
            b"CUSA12345\0".to_vec(),
            account_id.to_le_bytes().to_vec(),
            0x0000_0001u32.to_le_bytes().to_vec(),
        ];
        let num = keys.len();
        let key_table_offset = SFO_HEADER_SIZE + num * SFO_INDEX_SIZE;
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
            let fmt = if key == "ACCOUNT_ID\0" {
                SFO_FORMAT_BINARY
            } else {
                0x0204
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
        out
    }

    #[test]
    fn parse_account_id_forms() {
        assert_eq!(parse_account_id("0123456789ABCDEF").unwrap(), 0x0123_4567_89AB_CDEF);
        assert_eq!(parse_account_id("0x0123456789ABCDEF").unwrap(), 0x0123_4567_89AB_CDEF);
        assert_eq!(parse_account_id("12345678901234567890").unwrap(), 12_345_678_901_234_567_890);
        assert!(parse_account_id("zz").is_err());
    }

    #[test]
    fn string_read_patch() {
        let sfo = build_sfo(0xDEADBEEF);
        assert_eq!(read_string(&sfo, "TITLE_ID").unwrap().as_deref(), Some("CUSA12345"));
        assert_eq!(read_string(&sfo, "MISSING_KEY").unwrap(), None);
        // ACCOUNT_ID is binary, not a string.
        assert!(read_string(&sfo, "ACCOUNT_ID").is_err());

        let patched = patch_string(&sfo, "TITLE_ID", "CUSA99999").unwrap();
        assert_eq!(read_string(&patched, "TITLE_ID").unwrap().as_deref(), Some("CUSA99999"));
        assert_eq!(read_account_id(&patched).unwrap(), 0xDEADBEEF);

        // Shorter replacement must zero-fill the rest of the slot.
        let short = patch_string(&sfo, "TITLE_ID", "X").unwrap();
        assert_eq!(read_string(&short, "TITLE_ID").unwrap().as_deref(), Some("X"));
        // Value that exceeds the slot must fail.
        assert!(patch_string(&sfo, "TITLE_ID", "CUSA123456").is_err());
    }
}
