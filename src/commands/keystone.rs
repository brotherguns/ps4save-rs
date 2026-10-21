use std::path::Path;

use super::{read_title_id, resolve_all_save_pairs, open_save};

/// Render the 96-byte keystone of an opened save as an uppercase hex string.
/// Uses the exact sibling of the credential helper used by resign/reregion
/// (case-insensitive filename match on `keystone`).
/// Returns `Ok(None)` when the save has no keystone file.
pub fn keystone_hex(ctx: &super::SaveContext) -> crate::Result<Option<String>> {
    let Some(bytes) = crate::commands::read_save_file_bytes(ctx, "keystone")? else {
        return Ok(None);
    };
    let hex: String = bytes.iter().map(|b| format!("{b:02X}")).collect();
    Ok(Some(hex))
}

/// Dump keystones from a save: a single sealed-key/PFS pair or a directory
/// of save pairs. For each pair prints `TITLE_ID\tkeystone_hex` (or `-` when
/// there is no keystone). If `outfile` is given the same lines are appended
/// there instead, one per line — ready to feed a keystone database.
pub fn run_keystone(config: &str, save: &str, outfile: Option<&str>) -> crate::Result<()> {
    let pairs = resolve_all_save_pairs(save)?;
    if pairs.is_empty() {
        return Err(crate::Error::Message(format!("no save pairs in {save}")));
    }

    let mut lines = Vec::with_capacity(pairs.len());
    for (sealed, pfs) in &pairs {
        let ctx = open_save(
            config,
            sealed.to_str().unwrap_or_default(),
            pfs.to_str().unwrap_or_default(),
        )?;
        let title_id = read_title_id(&ctx)?;
        let hex = keystone_hex(&ctx)?;
        let line = match hex {
            Some(h) => format!("{title_id}\t{h}"),
            None => format!("{title_id}\t-"),
        };
        println!("{line}");
        lines.push(line);
    }

    if let Some(out) = outfile {
        let path = Path::new(out);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut body = lines.join("\n");
        body.push('\n');
        std::fs::write(path, body)?;
    }
    Ok(())
}
