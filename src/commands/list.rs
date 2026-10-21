use super::{open_save, resolve_save_pair};
use crate::pfs::PfsEntryType;

pub fn list_path(config: &str, save: &str) -> crate::Result<()> {
    let (sealed, pfs) = resolve_save_pair(save)?;
    run_list(config, sealed.to_str().unwrap(), pfs.to_str().unwrap())
}

pub fn run_list(config: &str, sealed: &str, pfs: &str) -> crate::Result<()> {
    let ctx = open_save(config, sealed, pfs)?;

    println!(
        "super_root_dir_ino={} user_root_dir_ino={}",
        ctx.fs.super_root_dir_ino, ctx.fs.user_root_dir_ino
    );

    let entries = ctx.fs.enum_user_root_directory()?;
    for e in entries {
        match e.entry_type {
            PfsEntryType::Directory => println!("{}/", e.path),
            PfsEntryType::File => println!("{} (size: 0x{:X})", e.path, e.size),
            other => println!("{} (type: {other:?})", e.path),
        }
    }
    Ok(())
}
