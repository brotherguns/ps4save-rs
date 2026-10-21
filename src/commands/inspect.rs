use std::io::Write;

use colored::Colorize;
use super::open_save;
use crate::keys::decrypt_sealed_key;
use crate::pfs::header::{PFS_FILE_COMPRESSED, PFS_FS_MAGIC, PfsHeader};
use crate::pfs::{PfsEntry, PfsEntryType};
use crate::sfo;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("")
}

fn human_size(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut val = bytes as f64;
    for unit in &["KB", "MB", "GB"] {
        val /= 1024.0;
        if val < 1024.0 {
            return format!("{val:.1} {unit}");
        }
    }
    format!("{:.1} TB", val / 1024.0)
}

fn ok(msg: &str, color: bool) -> String {
    if color { msg.green().to_string() } else { msg.to_string() }
}

fn ok_bold(msg: &str, color: bool) -> String {
    if color { msg.green().bold().to_string() } else { msg.to_string() }
}

fn bad(msg: &str, color: bool) -> String {
    if color { msg.red().bold().to_string() } else { msg.to_string() }
}

fn warn(msg: &str, color: bool) -> String {
    if color { msg.yellow().to_string() } else { msg.to_string() }
}

fn blue(msg: &str, color: bool) -> String {
    if color { msg.blue().to_string() } else { msg.to_string() }
}

fn cyan_bold(msg: &str, color: bool) -> String {
    if color { msg.cyan().bold().to_string() } else { msg.to_string() }
}

fn dimmed(msg: &str, color: bool) -> String {
    if color { msg.dimmed().to_string() } else { msg.to_string() }
}

fn format_timestamp(ts: u64) -> String {
    if ts == 0 {
        return String::new();
    }
    let secs = ts % 60;
    let mins = (ts / 60) % 60;
    let hours = (ts / 3600) % 24;
    let days = (ts / 86400) as u32;
    let mut y = 1970u32;
    let mut remaining = days;
    loop {
        let leap = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 366 } else { 365 };
        if remaining < leap { break; }
        remaining -= leap;
        y += 1;
    }
    let month_days = [31,28,31,30,31,30,31,31,30,31,30,31];
    let mut m = 1u32;
    for (i, &d) in month_days.iter().enumerate() {
        let dim = if i == 1 && y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 29 } else { d };
        if remaining < dim { break; }
        remaining -= dim;
        m += 1;
    }
    format!("{y:04}-{m:02}-{:02} {hours:02}:{mins:02}:{secs:02}", remaining + 1)
}

pub fn run_inspect(config: &str, sealed: &str, pfs: &str) -> crate::Result<()> {
    let mut out = std::io::stdout();
    inspect_to(config, sealed, pfs, &mut out, true)
}

pub fn inspect_path(config: &str, save: &str) -> crate::Result<()> {
    let (sealed, pfs) = super::resolve_save_pair(save)?;
    let mut out = std::io::stdout();
    inspect_to(config, sealed.to_str().unwrap(), pfs.to_str().unwrap(), &mut out, true)
}

pub fn inspect_to_string_from_path(config: &str, save: &str) -> crate::Result<String> {
    let (sealed, pfs) = super::resolve_save_pair(save)?;
    let mut buf = Vec::new();
    inspect_to(config, sealed.to_str().unwrap(), pfs.to_str().unwrap(), &mut buf, true)?;
    Ok(String::from_utf8(buf).unwrap_or_default())
}

pub fn inspect_to_string(config: &str, sealed: &str, pfs: &str) -> crate::Result<String> {
    let mut buf = Vec::new();
    inspect_to(config, sealed, pfs, &mut buf, true)?;
    Ok(String::from_utf8(buf).unwrap_or_default())
}

fn inspect_to(config: &str, sealed: &str, pfs: &str, out: &mut dyn Write, color: bool) -> crate::Result<()> {
    let ctx = open_save(config, sealed, pfs)?;

    // --- PFS Info ---
    writeln!(out, "{} v{} magic={:#X} mode={:#X}",
        cyan_bold("PFS", color), ctx.hdr.version, ctx.hdr.magic, ctx.hdr.mode)?;
    writeln!(out, "  block_size={} sd_key_ver={} encrypted={} signed={}",
        ctx.hdr.basic_block_size, ctx.hdr.sd_key_ver,
        ok_bold(&ctx.hdr.is_encrypted().to_string(), color),
        ok_bold(&ctx.hdr.is_signed().to_string(), color))?;

    ctx.hdr.verify_sd_header_signature(&ctx.cfg.common)?;
    writeln!(out, "  sd_header_sig:  {}", ok("valid", color))?;

    // --- Sealed Key ---
    let sealed_key = crate::keys::SealedKey::from_file(sealed)?;
    let mkey = decrypt_sealed_key(&ctx.cfg.common, &sealed_key)?;
    writeln!(out, "  sealed_key:     v{}", sealed_key.version)?;
    writeln!(out, "  mkey:           {}", ok(&hex(&mkey), color))?;
    if let Some(ref k) = ctx.keyset.image_key {
        writeln!(out, "  image_key:      {}", ok(&hex(k), color))?;
    }
    if let Some(k) = ctx.keyset.enc_tweak_key {
        writeln!(out, "  enc_tweak:      {}", ok(&hex(&k), color))?;
    }
    if let Some(k) = ctx.keyset.enc_data_key {
        writeln!(out, "  enc_data:       {}", ok(&hex(&k), color))?;
    }
    if let Some(ref k) = ctx.keyset.sig_hmac_key {
        writeln!(out, "  sig_hmac:       {}", ok(&hex(k), color))?;
    }

    // --- Derived Keys ---
    if let (Some(tweak), Some(data)) = (ctx.keyset.enc_tweak_key, ctx.keyset.enc_data_key) {
        use crate::crypto::{EncDecDevice, PFS_ENCDEC_SECTOR_SIZE};
        use std::io::{Read, Seek, SeekFrom};

        let mut file = std::fs::File::open(pfs)?;
        let mut sector = vec![0u8; PFS_ENCDEC_SECTOR_SIZE];
        file.seek(SeekFrom::Start(PFS_ENCDEC_SECTOR_SIZE as u64))?;
        file.read_exact(&mut sector)?;
        let mut out_buf = vec![0u8; PFS_ENCDEC_SECTOR_SIZE];
        let dev = EncDecDevice::new(&tweak, &data, PFS_ENCDEC_SECTOR_SIZE)?;
        dev.decrypt(&sector, &mut out_buf, 1)?;
        writeln!(out, "  xts_smoke:      first8={}", hex(&out_buf[..8]))?;
    }

    // --- Header ---
    use std::io::Read;
    let mut hdr_buf = vec![0u8; crate::pfs::header::PFS_HEADER_SIZE];
    std::fs::File::open(pfs)?.read_exact(&mut hdr_buf)?;
    let full_hdr = PfsHeader::parse(&hdr_buf)?;

    writeln!(out)?;
    writeln!(out, "{}", cyan_bold("Header", color))?;
    writeln!(out, "  nbackup={} dinode_count={} data_blocks={} dinode_blocks={}",
        full_hdr.nbackup, full_hdr.dinode_count, full_hdr.data_block_count, full_hdr.dinode_block_count)?;
    writeln!(out, "  super_root_ino={:#X} sd_key_ver={}", full_hdr.super_root_dir_ino, full_hdr.sd_key_ver)?;
    writeln!(out, "  crypt_seed:     {}", hex(&full_hdr.crypt_seed))?;

    // Scan for all PFS headers in the image
    {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(pfs)?;
        let file_len = f.metadata()?.len() as usize;
        let mut buf = vec![0u8; file_len];
        f.seek(SeekFrom::Start(0))?;
        f.read_exact(&mut buf)?;

        let magic = PFS_FS_MAGIC.to_le_bytes();
        let mut offsets = Vec::new();
        for i in 0..file_len.saturating_sub(4) {
            if &buf[i..i + 4] == &magic {
                offsets.push(i);
            }
        }
        if offsets.len() > 1 {
            let primary = &buf[offsets[0]..offsets[0] + 0x5A0];
            let max_w = offsets.iter().map(|o| format!("{:#X}", o).len()).max().unwrap_or(0);
            writeln!(out, "  headers_found:  {}", ok(&format!("{}", offsets.len()), color))?;
            for (i, off) in offsets.iter().enumerate() {
                let hdr = &buf[*off..*off + 0x5A0];
                let matches = hdr == primary;
                let label = if i == 0 {
                    ok("primary", color)
                } else if matches {
                    blue("backup", color)
                } else {
                    warn("backup (differs from primary)", color)
                };
                writeln!(out, "    {:>width$}  {}", format!("{:#X}", off), label, width = max_w)?;
            }
        }
    }

    let mut hdr_for_hash = full_hdr.raw;
    hdr_for_hash[0x380..0x5A0].fill(0);
    if let Some(ref sig_key) = ctx.keyset.sig_hmac_key {
        use crate::crypto::hmac_sha256;
        let computed = hmac_sha256(sig_key, &hdr_for_hash);
        let stored = &full_hdr.raw[0x380..0x3A0];
        writeln!(out, "  header_hash:    {}", if computed == *stored { ok(&hex(stored), color) } else { bad(&format!("{} != {}", hex(stored), hex(&computed)), color) })?;
    }

    // Bottom signature: HMAC over first 0x580 bytes using sd_hdr_sig_key
    {
        let bottom_sig = &full_hdr.raw[0x580..0x5A0];
        if let Some(ref sig_key) = ctx.cfg.common.sd_hdr_sig_key {
            use crate::crypto::hmac_sha256;
            let computed = hmac_sha256(sig_key, &full_hdr.raw[..0x580]);
            writeln!(out, "  bottom_sig:     {}", if computed == *bottom_sig { ok(&hex(bottom_sig), color) } else { bad(&format!("{} != {}", hex(bottom_sig), hex(&computed)), color) })?;
        } else {
            writeln!(out, "  bottom_sig:     {}", hex(bottom_sig))?;
        }
    }

    // --- SD Info Data ---
    let sd_info_data = &full_hdr.raw[0x3A0..0x580];
    let iv_offset = full_hdr.basic_block_size as u64 - 16;
    let mut iv = [0u8; 16];
    {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(pfs)?;
        f.seek(SeekFrom::Start(iv_offset))?;
        f.read_exact(&mut iv)?;
    }

    if let Some(ref data_key) = ctx.cfg.common.sd_hdr_data_key {
        use crate::crypto::aes_decrypt_cbc_cts;

        let mut decrypted = vec![0u8; sd_info_data.len()];
        let mut iv_copy = iv;
        aes_decrypt_cbc_cts(data_key, Some(&mut iv_copy), sd_info_data, &mut decrypted)?;

        let game_paid = u64::from_le_bytes(decrypted[0x20..0x28].try_into().unwrap());
        let shellui_paid = u64::from_le_bytes(decrypted[0x30..0x38].try_into().unwrap());
        let partial_idps = &decrypted[0x38..0x3C];

        writeln!(out)?;
        writeln!(out, "{}", cyan_bold("SD Info", color))?;
        writeln!(out, "  game_paid:      0x{game_paid:016X}")?;
        writeln!(out, "  shellui_paid:   0x{shellui_paid:016X} ({})", lookup_shellui_paid(shellui_paid))?;
        writeln!(out, "  partial_idps:   {} ({})", hex(partial_idps), lookup_partial_idps(partial_idps))?;
    }

    // --- Auth Code ---
    const AUTH_CODE_OFF: usize = 0x7F90;
    const AUTH_CODE_SIZE: usize = 0x70;
    const AUTH_CODE_ENC_START: usize = 0x10;
    const AUTH_CODE_MAGIC: [u8; 8] = [0x79, 0x2B, 0x1A, 0xC1, 0xBB, 0x9B, 0x9A, 0x45];

    {
        use std::io::{Read, Seek, SeekFrom};
        let pfs_meta = std::fs::File::open(pfs)?;
        let file_len = pfs_meta.metadata()?.len() as usize;

        if file_len >= AUTH_CODE_OFF + AUTH_CODE_SIZE {
            let mut auth_buf = vec![0u8; AUTH_CODE_SIZE];
            let mut f = std::fs::File::open(pfs)?;
            f.seek(SeekFrom::Start(AUTH_CODE_OFF as u64))?;
            f.read_exact(&mut auth_buf)?;

            writeln!(out)?;
            writeln!(out, "{}", cyan_bold("Auth Code", color))?;

            if auth_buf[..8] != AUTH_CODE_MAGIC {
                writeln!(out, "  {}", bad("missing (decrypted or unsupported)", color))?;
            } else {
                writeln!(out, "  version:  {}.{}",
                    u32::from_le_bytes(auth_buf[8..12].try_into().unwrap()),
                    u32::from_le_bytes(auth_buf[12..16].try_into().unwrap()))?;

                if let Some(ref auth_key) = ctx.cfg.common.sd_auth_code_key {
                    use crate::crypto::aes_decrypt_cbc_cts;

                    let mut dec_body = vec![0u8; auth_buf.len() - AUTH_CODE_ENC_START];
                    let mut iv = [0u8; 16];
                    aes_decrypt_cbc_cts(auth_key, Some(&mut iv), &auth_buf[AUTH_CODE_ENC_START..], &mut dec_body)?;

                    let mut auth_code = vec![0u8; AUTH_CODE_SIZE];
                    auth_code[..AUTH_CODE_ENC_START].copy_from_slice(&auth_buf[..AUTH_CODE_ENC_START]);
                    auth_code[AUTH_CODE_ENC_START..].copy_from_slice(&dec_body);

                    let auth_hash2 = &auth_code[0x40..0x60];
                    let copy_ctr = u64::from_le_bytes(auth_code[0x60..0x68].try_into().unwrap());
                    let hdr_hash = &full_hdr.raw[0x380..0x3A0];

                    let hash2_ok = auth_hash2 == hdr_hash;
                    let copy_ok = copy_ctr != 0;

                    writeln!(out, "  hash2:          {}", if hash2_ok { ok(&hex(auth_hash2), color) } else { bad(&hex(auth_hash2), color) })?;
                    writeln!(out, "  copy_counter:   {}", if copy_ok { ok(&format!("{copy_ctr}"), color) } else { bad(&format!("{copy_ctr}"), color) })?;
                } else {
                    writeln!(out, "  {}", warn("sd_auth_code_key not set", color))?;
                }
            }
        }
    }

    // --- System inodes + Files ---
    let mut all_entries = vec![PfsEntry {
        path: "(super_root)".into(),
        ino: 0,
        entry_type: PfsEntryType::Directory,
        size: 0,
        flags: 0,
        last_modified: 0,
        last_access: 0,
        creation: 0,
    }];
    all_entries.extend(ctx.fs.enum_super_root_directory()?);
    let mut user_entries = ctx.fs.enum_user_root_directory()?;
    all_entries.append(&mut user_entries);
    let entries = all_entries;
    let file_count = entries.iter().filter(|e| e.entry_type == PfsEntryType::File).count();
    let dir_count = entries.iter().filter(|e| e.entry_type == PfsEntryType::Directory).count();

    // Compute recursive total sizes for directories
    let dir_total: std::collections::HashMap<String, u64> = {
        let mut map = std::collections::HashMap::new();
        let dirs: Vec<String> = entries.iter()
            .filter(|e| e.entry_type == PfsEntryType::Directory)
            .map(|e| e.path.clone())
            .collect();
        for dir in &dirs {
            let prefix = format!("{}/", dir);
            let total: u64 = entries.iter()
                .filter(|e| e.entry_type == PfsEntryType::File && e.path.starts_with(&prefix))
                .map(|e| e.size)
                .sum();
            map.insert(dir.clone(), total);
        }
        let uroot_total: u64 = entries.iter()
            .filter(|e| e.entry_type == PfsEntryType::File && !e.path.starts_with("sce_sys/"))
            .map(|e| e.size)
            .sum();
        map.insert("uroot".into(), uroot_total);
        let super_total: u64 = entries.iter()
            .filter(|e| e.entry_type == PfsEntryType::File)
            .map(|e| e.size)
            .sum();
        map.insert("(super_root)".into(), super_total);
        map
    };
    writeln!(out)?;
    writeln!(out, "{} ({})", cyan_bold("Inodes", color), entries.len())?;

    let max_name = entries.iter().map(|e| if e.entry_type == PfsEntryType::Directory { e.path.len() + 1 } else { e.path.len() }).max().unwrap_or(0);
    let hdr = format!("  {:>4}  {:<4}  {:<width$}  {:>10}  {}", "ino", "type", "name", "size", "timestamp", width = max_name);
    writeln!(out, "{}", dimmed(&hdr, color))?;
    for e in &entries {
        let ts = format_timestamp(e.last_modified);
        let compressed = if e.flags & PFS_FILE_COMPRESSED != 0 { warn(" [compressed]", color) } else { String::new() };
        let is_sce = e.path.starts_with("sce_sys/");
        let ino = format!("{:>4}", e.ino);
        let ty = format!("{:<4}", match e.entry_type {
            PfsEntryType::Directory => "dir",
            PfsEntryType::File => "file",
            _ => "?",
        });
        match e.entry_type {
            PfsEntryType::Directory => {
                let name = format!("{}/", e.path);
                let name_padded = format!("{:<width$}", name, width = max_name);
                let total = dir_total.get(&e.path).copied().unwrap_or(0);
                let size = format!("{:>10}", human_size(total));
                writeln!(out, "  {}  {}  {}  {}  {}", blue(&ino, color), blue(&ty, color), blue(&name_padded, color), blue(&size, color), if ts.is_empty() { String::new() } else { dimmed(&ts, color) })?;
            }
            PfsEntryType::File => {
                let name = format!("{:<width$}", e.path, width = max_name);
                let colored_name = if is_sce {
                    if color { name.magenta().to_string() } else { name }
                } else {
                    name
                };
                let size = format!("{:>10}", human_size(e.size));
                writeln!(out, "  {}  {}  {}  {}  {}{}", blue(&ino, color), ty, colored_name, ok(&size, color), if ts.is_empty() { String::new() } else { dimmed(&ts, color) }, compressed)?;
            }
            _ => {}
        }
    }
    writeln!(out, "  {} files, {} directories", file_count, dir_count)?;

    // --- param.sfo ---
    if let Ok(sfo_file) = ctx.fs.get_file_by_path("sce_sys/param.sfo") {
        let mut sfo_data = vec![0u8; sfo_file.file_size as usize];
        ctx.fs.file_read(&sfo_file, 0, &mut sfo_data)?;

        writeln!(out)?;
        writeln!(out, "{}", cyan_bold("param.sfo", color))?;
        if let Ok(Some(id)) = sfo::read_string(&sfo_data, "TITLE_ID") {
            writeln!(out, "  TITLE_ID:            {id}")?;
        }
        if let Ok(Some(name)) = sfo::read_string(&sfo_data, "TITLE_NAME") {
            writeln!(out, "  TITLE_NAME:          {name}")?;
        }
        if let Ok(Some(dir)) = sfo::read_string(&sfo_data, "SAVEDATA_DIRECTORY") {
            writeln!(out, "  SAVEDATA_DIRECTORY:  {dir}")?;
        }
        if let Ok(Some(content_id)) = sfo::read_string(&sfo_data, "CONTENT_ID") {
            writeln!(out, "  CONTENT_ID:          {content_id}")?;
        }
        if let Ok(Some(cat)) = sfo::read_string(&sfo_data, "ITEM_CATEGORY") {
            writeln!(out, "  ITEM_CATEGORY:       {cat}")?;
        }
        if let Ok(Some(name)) = sfo::read_string(&sfo_data, "SAVEDATA_NAME") {
            writeln!(out, "  SAVEDATA_NAME:       {name}")?;
        }
        if let Ok(Some(detail)) = sfo::read_string(&sfo_data, "SAVEDATA_DETAIL") {
            writeln!(out, "  SAVEDATA_DETAIL:     {detail}")?;
        }
        if let Ok(Some(sub)) = sfo::read_string(&sfo_data, "SUBTITLE") {
            writeln!(out, "  SUBTITLE:            {sub}")?;
        }
        if let Ok(Some(parent)) = sfo::read_string(&sfo_data, "PARENT_DIRECTORY") {
            writeln!(out, "  PARENT_DIRECTORY:    {parent}")?;
        }
        if let Ok(id) = sfo::read_account_id(&sfo_data) {
            writeln!(out, "  ACCOUNT_ID:          {id:016x}")?;
        }
        if let Ok(Some(blocks)) = sfo::read_savedata_blocks(&sfo_data) {
            writeln!(out, "  SAVEDATA_BLOCKS:     {blocks} (0x{blocks:X})")?;
        }
        if let Ok(Some(size)) = sfo::read_string(&sfo_data, "SAVEDATA_SIZE") {
            writeln!(out, "  SAVEDATA_SIZE:       {size}")?;
        }
        if let Ok(Some(version)) = sfo::read_string(&sfo_data, "SAVEDATA_VERSION") {
            writeln!(out, "  SAVEDATA_VERSION:    {version}")?;
        }
    }

    Ok(())
}

fn lookup_shellui_paid(paid: u64) -> &'static str {
    match paid {
        0x3800000000000003 => "SceVdecProxy",
        0x3800000000000004 => "SceVencProxy",
        0x3800000000000005 => "orbis_audiod",
        0x3800000000000006 => "coredump",
        0x3800000000000007 => "SceSysCore",
        0x3800000000000008 => "orbis_setip",
        0x3800000000000009 => "GnmCompositor",
        0x380000000000000F => "NPXS20001",
        0x3800000000000010 => "SceShellCore",
        0x3800000000000011 => "NPXS20103",
        0x3800000000000012 => "NPXS21000",
        0x3800000000000013 => "NPXS21001",
        0x3800000000000014 => "NPXS21002",
        0x3800000000000015 => "NPXS21003",
        0x3800000000000016 => "NPXS21004",
        0x3800000000000017 => "becore",
        0x3800000000000018 => "avbase",
        0x3800000000000019 => "NPXS21006",
        0x380000000000001C => "NPXS22010",
        0x380000000000001D => "fs_cleaner",
        0x380000000000001E => "FirstImageWriter",
        0x3800000000000022 => "mini_syscore",
        0x3800000000000023 => "sce_video_service",
        0x3800000000000024 => "ScePlayReady",
        0x3800000000000026 => "swagner",
        0x3800000000000028 => "SceCloudClientDaemon",
        0x3800000000000029 => "swreset",
        0x3800000000000031 => "webapp",
        0x3800000000000033 => "SECURE_UI_PROCESS",
        0x3800000000000034 => "UIProcess",
        0x3800000000000035 => "WebBrowserUIProcess",
        0x3800000000000036 => "gpudump",
        0x380000000000003C => "SceNKUIProcess",
        0x3800000010000003 => "SecureWebProcess",
        0x3800000010000004 => "WebProcess",
        0x3800000010000005 => "Bdjava",
        0x3800000010000006 => "orbis-jsc-compiler",
        0x3800000010000008 => "MonoCompiler",
        0x3800000010000009 => "sceSblACMgr",
        0x380000001000000B => "custom_video_core",
        0x380000001000000E => "SceSpZeroConf",
        0x380000001000000F => "WebProcessWebApp",
        0x3800000000010001 => "set_upper",
        0x3800000000010002 => "mount_fusefs",
        0x3800000000010003 => "Decid",
        0x3800000000010004 => "newfs",
        0x3800000000010005 => "fsck_ufs",
        0x3800000000010006 => "NPXS21008",
        0x3800800000000002 => "VTRM_ADMIN",
        0x380100000000000A => "UNK_PFS",
        0x3801000000000024 => "OS_UPDATE",
        0x380100000000002C => "sceSblACMgr",
        0x3800100000000001 => "orbis_swu",
        0x3900000000000002 => "sprx",
        0x3901000000000001 => "sdll",
        0x3C00000000000001 => "Kernel",
        0x3F00000000000001 => "Secure Kernel",
        0x3E00000000000003 => "PUPMgr",
        0x3E00000000000004 => "80010007",
        0x3E00000000000005 => "AuthMgr",
        0x3E00000000000006 => "Individual Data Mgr",
        0x3E00000000000007 => "KeyMgr",
        0x3E00000000000008 => "FSM Mgr",
        0x3E00000000000009 => "AuthMgr + KeyMgr",
        _ => "unknown",
    }
}

fn lookup_partial_idps(idps: &[u8]) -> &'static str {
    if idps.len() < 2 { return "??"; }
    match format!("{:02X}{:02X}", idps[0], idps[1]).as_str() {
        "0180" => "DIAG, TEST",
        "0181" => "Devkit, TOOL, DUH-D",
        "0182" => "Testkit, DEX, DUH-T",
        "0183" => "Retail, CEX, CUH, Japan",
        "0184" => "Retail, CEX, CUH, United States",
        "0185" => "Retail, CEX, CUH, Europe",
        "0186" => "Retail, CEX, CUH, Korea",
        "0187" => "Retail, CEX, CUH, United Kingdom",
        "0188" => "Retail, CEX, CUH, Mexico",
        "0189" => "Retail, CEX, CUH, Australia & New Zealand",
        "018A" => "Retail, CEX, CUH, South Asia",
        "018B" => "Retail, CEX, CUH, Taiwan",
        "018C" => "Retail, CEX, CUH, Russia",
        "018D" => "Retail, CEX, CUH, China",
        "018E" => "Retail, CEX, CUH",
        "018F" => "Retail, CEX, CUH, Brazil",
        _ => "unknown",
    }
}
