use std::path::PathBuf;

use ini::Ini;

#[derive(Debug, Clone)]
pub struct Settings {
    pub config_path: String,
    pub account_id: String,
    pub save_path: String,
    pub output_path: String,
    pub sample_path: String,
    pub zoom: f32,
    pub bg: [u8; 3],
    pub bg2: [u8; 3],
    pub border: [u8; 3],
    pub fg: [u8; 3],
    pub accent: [u8; 3],
    pub muted: [u8; 3],
    pub ok: [u8; 3],
    pub err: [u8; 3],
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            config_path: String::from("config.ini"),
            account_id: String::from("0000000000000000"),
            save_path: String::new(),
            output_path: String::new(),
            sample_path: String::new(),
            zoom: 1.0,
            bg: [24, 24, 24],
            bg2: [31, 31, 31],
            border: [69, 61, 65],
            fg: [228, 228, 239],
            accent: [255, 204, 102],
            muted: [140, 140, 150],
            ok: [140, 200, 120],
            err: [220, 100, 100],
        }
    }
}

impl Settings {
    pub fn load() -> Self {
        let path = settings_path();
        match Ini::load_from_file(&path) {
            Ok(ini) => Self::from_ini(&ini),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) {
        let path = settings_path();
        let mut ini = Ini::load_from_file(&path).unwrap_or_else(|_| Ini::new());

        ini.set_to(Some("general"), "config_path".into(), self.config_path.clone());
        ini.set_to(Some("general"), "account_id".into(), self.account_id.clone());
        ini.set_to(Some("general"), "save_path".into(), self.save_path.clone());
        ini.set_to(Some("general"), "output_path".into(), self.output_path.clone());
        ini.set_to(Some("general"), "sample_path".into(), self.sample_path.clone());
        ini.set_to(Some("general"), "zoom".into(), format!("{:.1}", self.zoom));

        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = ini.write_to_file(&path);
    }

    fn from_ini(ini: &Ini) -> Self {
        let mut s = Self::default();
        if let Some(section) = ini.section(Some("general")) {
            if let Some(v) = section.get("config_path") { s.config_path = v.to_string(); }
            if let Some(v) = section.get("account_id") { s.account_id = v.to_string(); }
            if let Some(v) = section.get("save_path") { s.save_path = v.to_string(); }
            if let Some(v) = section.get("output_path") { s.output_path = v.to_string(); }
            if let Some(v) = section.get("sample_path") { s.sample_path = v.to_string(); }
            if let Some(v) = section.get("zoom") { s.zoom = v.parse::<f32>().unwrap_or(s.zoom); }
        }
        if let Some(section) = ini.section(Some("gui")) {
            if let Some(v) = section.get("bg") { s.bg = parse_color(v).unwrap_or(s.bg); }
            if let Some(v) = section.get("bg2") { s.bg2 = parse_color(v).unwrap_or(s.bg2); }
            if let Some(v) = section.get("border") { s.border = parse_color(v).unwrap_or(s.border); }
            if let Some(v) = section.get("fg") { s.fg = parse_color(v).unwrap_or(s.fg); }
            if let Some(v) = section.get("accent") { s.accent = parse_color(v).unwrap_or(s.accent); }
            if let Some(v) = section.get("muted") { s.muted = parse_color(v).unwrap_or(s.muted); }
            if let Some(v) = section.get("ok") { s.ok = parse_color(v).unwrap_or(s.ok); }
            if let Some(v) = section.get("err") { s.err = parse_color(v).unwrap_or(s.err); }
        }
        s
    }
}

pub fn settings_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ps4save-rs")
        .join("settings.ini")
}

fn parse_color(s: &str) -> Option<[u8; 3]> {
    let s = s.trim().trim_start_matches('#');
    if s.len() != 6 { return None; }
    let r = u8::from_str_radix(&s[0..2], 16).ok()?;
    let g = u8::from_str_radix(&s[2..4], 16).ok()?;
    let b = u8::from_str_radix(&s[4..6], 16).ok()?;
    Some([r, g, b])
}
