//! Directory entry parsing and root directory walking (pfs_lookup.c / pfs_parsers.c).

use super::Pfs;
use crate::error::{Error, Result};
use crate::pfs::header::{PfsDirEntry, PFS_MIN_DIR_ENTRY_SIZE};
use crate::pfs::io::PfsFile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PfsEntryType {
    None,
    File,
    Directory,
    This,
    Parent,
    Other(u32),
}

impl PfsEntryType {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => PfsEntryType::None,
            2 => PfsEntryType::File,
            3 => PfsEntryType::Directory,
            4 => PfsEntryType::This,
            5 => PfsEntryType::Parent,
            other => PfsEntryType::Other(other),
        }
    }
}

/// A file/directory discovered under the user root.
#[derive(Debug, Clone)]
pub struct PfsEntry {
    pub path: String,
    pub ino: u32,
    pub entry_type: PfsEntryType,
    pub size: u64,
    pub flags: u32,
    pub last_modified: u64,
    pub last_access: u64,
    pub creation: u64,
}

impl Pfs {
    /// Parse a directory data buffer into entries (pfs_parse_dir_entries).
    pub fn parse_dir_entries<F>(&self, data: &[u8], mut cb: F)
    where
        F: FnMut(&PfsDirEntry),
    {
        if data.len() <= PFS_MIN_DIR_ENTRY_SIZE {
            return;
        }

        let mut offset = 0usize;
        loop {
            let ino = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            let entry_size = u32::from_le_bytes(data[offset + 12..offset + 16].try_into().unwrap());
            if ino == 0 || entry_size == 0 {
                break;
            }
            let entry_type = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap());
            let name_size = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap());

            let avail = data.len().saturating_sub(offset + 16);
            let name_len = (name_size as usize).min(avail);
            let name = data[offset + 16..offset + 16 + name_len].to_vec();

            cb(&PfsDirEntry {
                ino,
                entry_type,
                name_size,
                entry_size,
                name,
            });

            offset += entry_size as usize;
            if offset + PFS_MIN_DIR_ENTRY_SIZE >= data.len() {
                break;
            }
        }
    }

    /// Walk the super-root directory and record the well-known inodes.
    pub fn parse_super_root_directory(&mut self) -> Result<()> {
        let file = self.get_file(self.super_root_dir_ino)?;
        let mut data = vec![0u8; file.file_size as usize];
        self.file_read(&file, 0, &mut data)?;

        let mut block_bitmap_ino = 0u32;
        let mut ino_bitmap_ino = 0u32;
        let mut user_root_dir_ino = 0u32;
        let mut block_addr_table_ino = 0u32;
        let mut flat_path_table_ino = 0u32;
        let mut collision_resolver_ino = 0u32;

        self.parse_dir_entries(&data, |e| {
            let name = String::from_utf8_lossy(&e.name);
            match name.as_ref() {
                "blk_bitmap" => block_bitmap_ino = e.ino,
                "ino_bitmap" => ino_bitmap_ino = e.ino,
                "uroot" => user_root_dir_ino = e.ino,
                "block_addr_table" => block_addr_table_ino = e.ino,
                "flat_path_table" => flat_path_table_ino = e.ino,
                "collision_resolver" => collision_resolver_ino = e.ino,
                _ => {}
            }
        });

        self.block_bitmap_ino = block_bitmap_ino;
        self.ino_bitmap_ino = ino_bitmap_ino;
        self.user_root_dir_ino = user_root_dir_ino;
        self.block_addr_table_ino = block_addr_table_ino;
        self.flat_path_table_ino = flat_path_table_ino;
        self.collision_resolver_ino = collision_resolver_ino;
        Ok(())
    }

    /// Depth-first walk of the user root, mirroring pfs_enum_user_root_directory.
    pub fn enum_user_root_directory(&self) -> Result<Vec<PfsEntry>> {
        let mut out = Vec::new();
        self.enum_directory(self.user_root_dir_ino, "", &mut out)?;
        Ok(out)
    }

    /// List direct children of the super root directory (system inodes 0-5).
    pub fn enum_super_root_directory(&self) -> Result<Vec<PfsEntry>> {
        let file = self.get_file(self.super_root_dir_ino)?;
        let mut data = vec![0u8; file.file_size as usize];
        self.file_read(&file, 0, &mut data)?;

        let mut out = Vec::new();
        self.parse_dir_entries(&data, |e| {
            let name = String::from_utf8_lossy(&e.name).into_owned();
            let child = self.get_file(e.ino);
            let (size, flags, entry_type, last_modified, last_access, creation) = match child {
                Ok(f) => (f.file_size, f.flags, PfsEntryType::from_u32(e.entry_type),
                    f.dinode.last_modified_time, f.dinode.last_access_time, f.dinode.creation_time),
                Err(_) => (0, 0, PfsEntryType::from_u32(e.entry_type), 0, 0, 0),
            };
            out.push(PfsEntry {
                path: name,
                ino: e.ino,
                entry_type,
                size,
                flags,
                last_modified,
                last_access,
                creation,
            });
        });
        Ok(out)
    }

    /// Resolve an absolute path under the user root to a file.
    pub fn get_file_by_path(&self, path: &str) -> Result<PfsFile> {
        let mut ino = self.user_root_dir_ino;
        for comp in path.trim_matches('/').split('/') {
            let file = self.get_file(ino)?;
            let mut data = vec![0u8; file.file_size as usize];
            self.file_read(&file, 0, &mut data)?;
            let mut found = None;
            self.parse_dir_entries(&data, |e| {
                if found.is_none() && String::from_utf8_lossy(&e.name) == comp {
                    found = Some(e.ino);
                }
            });
            ino = found.ok_or_else(|| {
                Error::Message(format!("path component '{comp}' not found in ino {ino}"))
            })?;
        }
        self.get_file(ino)
    }

    fn enum_directory(&self, ino: u32, parent: &str, out: &mut Vec<PfsEntry>) -> Result<()> {
        let file = self.get_file(ino)?;
        let mut data = vec![0u8; file.file_size as usize];
        self.file_read(&file, 0, &mut data)?;

        let mut entries: Vec<(PfsDirEntry, u64)> = Vec::new();
        self.parse_dir_entries(&data, |e| {
            let child_size = self.get_file(e.ino).map(|f| f.file_size).unwrap_or(0);
            entries.push((e.clone(), child_size));
        });

        for (e, child_size) in entries {
            let name = String::from_utf8_lossy(&e.name).into_owned();
            if name == "." || name == ".." {
                continue;
            }
            let path = if parent.is_empty() {
                name.clone()
            } else {
                format!("{parent}/{name}")
            };
            let entry_type = PfsEntryType::from_u32(e.entry_type);
            match self.get_file(e.ino) {
                Ok(child) => {
                    out.push(PfsEntry {
                        path: path.clone(),
                        ino: e.ino,
                        entry_type,
                        size: child_size,
                        flags: child.flags,
                        last_modified: child.dinode.last_modified_time,
                        last_access: child.dinode.last_access_time,
                        creation: child.dinode.creation_time,
                    });
                    if entry_type == PfsEntryType::Directory {
                        self.enum_directory(e.ino, &path, out)?;
                    }
                }
                Err(_) => {
                    eprintln!("warning: ino {0}: skipping unreadable inode", e.ino);
                    out.push(PfsEntry {
                        path: path.clone(),
                        ino: e.ino,
                        entry_type,
                        size: child_size,
                        flags: 0,
                        last_modified: 0,
                        last_access: 0,
                        creation: 0,
                    });
                }
            }
        }
        Ok(())
    }
}
