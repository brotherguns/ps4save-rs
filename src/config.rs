//! config.ini loader matching pkg_pfs_tool keymgr config callback.

use std::collections::HashMap;
use std::path::Path;

use ini::Ini;

use crate::error::{Error, Result};
use crate::keys::sizes::*;
use crate::keys::{CommonKeys, RsaKeyset, TitleKeyset};

/// Parsed configuration: global `[common]` keys plus per-title sections.
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub common: CommonKeys,
    pub titles: HashMap<String, TitleKeyset>,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let ini = Ini::load_from_file(path)
            .map_err(|e| Error::Config(format!("failed to read {}: {e}", path.display())))?;

        Self::from_ini(ini)
    }

    pub fn from_str(s: &str) -> Result<Self> {
        let ini = Ini::load_from_str(s)
            .map_err(|e| Error::Config(format!("failed to parse config: {e}")))?;

        Self::from_ini(ini)
    }

    fn from_ini(ini: Ini) -> Result<Self> {

        let mut cfg = Config::default();

        for (section, props) in ini.iter() {
            let section = section.unwrap_or("");
            if section.eq_ignore_ascii_case("common") {
                for (name, value) in props.iter() {
                    apply_common(&mut cfg.common, name, value)?;
                }
            } else if !section.is_empty() {
                let keyset = cfg
                    .titles
                    .entry(section.to_string())
                    .or_insert_with(|| TitleKeyset::new(section));
                for (name, value) in props.iter() {
                    apply_title(keyset, name, value)?;
                }
            }
        }

        Ok(cfg)
    }

    pub fn title(&self, content_id: &str) -> Option<&TitleKeyset> {
        self.titles.get(content_id)
    }

    pub fn title_mut(&mut self, content_id: &str) -> Option<&mut TitleKeyset> {
        self.titles.get_mut(content_id)
    }

    pub fn get_or_create_title(&mut self, content_id: &str) -> &mut TitleKeyset {
        self.titles
            .entry(content_id.to_string())
            .or_insert_with(|| TitleKeyset::new(content_id))
    }

    /// Serialize back to INI text (lossless round-trip for the subset we parse).
    pub fn to_ini_string(&self) -> String {
        let mut out = String::new();

        out.push_str("[common]\n");
        if let Some(v) = &self.common.idps {
            out.push_str(&format!("idps={}\n", hex(v)));
        }
        if let Some(v) = &self.common.open_psid {
            out.push_str(&format!("open_psid={}\n", hex(v)));
        }
        if let Some(v) = &self.common.sd_auth_code_key {
            out.push_str(&format!("sd_auth_code_key={}\n", hex(v)));
        }
        if let Some(v) = &self.common.sd_hdr_data_key {
            out.push_str(&format!("sd_hdr_data_key={}\n", hex(v)));
        }
        if let Some(v) = &self.common.sd_hdr_sig_key {
            out.push_str(&format!("sd_hdr_sig_key={}\n", hex(v)));
        }
        if let Some(v) = &self.common.open_psid_sig_key {
            out.push_str(&format!("open_psid_sig_key={}\n", hex(v)));
        }
        if let Some(v) = &self.common.gdgp_content_key_obf_key {
            out.push_str(&format!("gdgp_content_key_obf_key={}\n", hex(v)));
        }
        if let Some(v) = &self.common.ac_content_key {
            out.push_str(&format!("ac_content_key={}\n", hex(v)));
        }
        for (i, slot) in self.common.sealed_key_enc.iter().enumerate() {
            if let Some(v) = slot {
                out.push_str(&format!("sealed_key_enc_key_{}={}\n", i + 1, hex(v)));
            }
        }
        for (i, slot) in self.common.sealed_key_sign.iter().enumerate() {
            if let Some(v) = slot {
                out.push_str(&format!("sealed_key_sign_key_{}={}\n", i + 1, hex(v)));
            }
        }
        for (i, slot) in self.common.sd_content_key.iter().enumerate() {
            if let Some(v) = slot {
                out.push_str(&format!("sd_content_key_{}={}\n", i + 1, hex(v)));
            }
        }
        for (i, slot) in self.common.ekpfs_obf_key.iter().enumerate() {
            if let Some(v) = slot {
                out.push_str(&format!("ekpfs_obf_key_{}={}\n", i + 1, hex(v)));
            }
        }
        for (i, slot) in self.common.gdgp_ekc_key.iter().enumerate() {
            if let Some(v) = slot {
                out.push_str(&format!("gdgp_ekc_key_{}={}\n", i, hex(v)));
            }
        }
        write_rsa(&mut out, "pkg_entry_key_3", &self.common.pkg_entry_key_3);
        write_rsa(&mut out, "debug_ekpfs_key", &self.common.debug_ekpfs_key);
        write_rsa(&mut out, "retail_ekpfs_key_0", &self.common.retail_ekpfs_key_0);
        write_rsa(&mut out, "retail_ekpfs_key_1", &self.common.retail_ekpfs_key_1);
        write_rsa(&mut out, "fake_ekpfs_key", &self.common.fake_ekpfs_key);
        write_rsa(&mut out, "pfs_sig_key", &self.common.pfs_sig_key);

        for (content_id, t) in &self.titles {
            out.push_str(&format!("\n[{content_id}]\n"));
            if let Some(v) = &t.passcode {
                out.push_str(&format!("passcode={}\n", String::from_utf8_lossy(v)));
            }
            if let Some(v) = &t.enc_tweak_key {
                out.push_str(&format!("enc_tweak_key={}\n", hex(v)));
            }
            if let Some(v) = &t.enc_data_key {
                out.push_str(&format!("enc_data_key={}\n", hex(v)));
            }
            if let Some(v) = &t.sig_hmac_key {
                out.push_str(&format!("sig_hmac_key={}\n", hex(v)));
            }
            if let Some(v) = &t.image_key {
                out.push_str(&format!("image_key={}\n", hex(v)));
            }
            if let Some(v) = &t.sc0_key {
                out.push_str(&format!("sc0_key={}\n", hex(v)));
            }
            if let Some(v) = &t.content_key_seed {
                out.push_str(&format!("content_key_seed={}\n", hex(v)));
            }
            if let Some(v) = &t.self_key_seed {
                out.push_str(&format!("self_key_seed={}\n", hex(v)));
            }
        }

        out
    }
}

fn apply_common(common: &mut CommonKeys, name: &str, value: &str) -> Result<()> {
    let name_l = name.to_ascii_lowercase();
    match name_l.as_str() {
        "idps" => common.idps = Some(parse_hex_array(value, "idps")?),
        "open_psid" => common.open_psid = Some(parse_hex_array(value, "open_psid")?),
        "sd_auth_code_key" => {
            common.sd_auth_code_key = Some(parse_hex_array(value, "sd_auth_code_key")?)
        }
        "sd_hdr_data_key" => {
            common.sd_hdr_data_key = Some(parse_hex_array(value, "sd_hdr_data_key")?)
        }
        "sd_hdr_sig_key" => {
            common.sd_hdr_sig_key = Some(parse_hex_array(value, "sd_hdr_sig_key")?)
        }
        "open_psid_sig_key" => {
            common.open_psid_sig_key = Some(parse_hex_array(value, "open_psid_sig_key")?)
        }
        "gdgp_content_key_obf_key" => {
            common.gdgp_content_key_obf_key =
                Some(parse_hex_array(value, "gdgp_content_key_obf_key")?)
        }
        "ac_content_key" => {
            common.ac_content_key = Some(parse_hex_array(value, "ac_content_key")?)
        }
        _ => {
            if let Some(n) = strip_indexed(&name_l, "sealed_key_enc_key_") {
                set_indexed_vec(&mut common.sealed_key_enc, n, value, "sealed_key_enc_key")?;
            } else if let Some(n) = strip_indexed(&name_l, "sealed_key_sign_key_") {
                set_indexed_vec(&mut common.sealed_key_sign, n, value, "sealed_key_sign_key")?;
            } else if let Some(n) = strip_indexed(&name_l, "sd_content_key_") {
                set_indexed_vec(&mut common.sd_content_key, n, value, "sd_content_key")?;
            } else if let Some(n) = strip_indexed(&name_l, "ekpfs_obf_key_") {
                set_indexed_vec(&mut common.ekpfs_obf_key, n, value, "ekpfs_obf_key")?;
            } else if let Some(n) = strip_indexed(&name_l, "gdgp_ekc_key_") {
                set_indexed_vec_zero_based(&mut common.gdgp_ekc_key, n, value, "gdgp_ekc_key")?;
            } else if let Some((base, field)) = name_l.split_once(':') {
                apply_rsa(common, base, field, value)?;
            }
            // Unknown common keys are ignored (same spirit as C tool).
        }
    }
    Ok(())
}

fn apply_rsa(common: &mut CommonKeys, base: &str, field: &str, value: &str) -> Result<()> {
    let keyset = match base {
        "pkg_entry_key_3" => &mut common.pkg_entry_key_3,
        "debug_ekpfs_key" => &mut common.debug_ekpfs_key,
        "retail_ekpfs_key_0" => &mut common.retail_ekpfs_key_0,
        "retail_ekpfs_key_1" => &mut common.retail_ekpfs_key_1,
        "fake_ekpfs_key" => &mut common.fake_ekpfs_key,
        "pfs_sig_key" => &mut common.pfs_sig_key,
        _ => return Ok(()),
    };
    set_rsa_field(keyset, field, value);
    Ok(())
}

fn set_rsa_field(keyset: &mut RsaKeyset, field: &str, value: &str) {
    let v = Some(value.to_string());
    match field {
        "n" => keyset.n = v,
        "e" => keyset.e = v,
        "d" => keyset.d = v,
        "p" => keyset.p = v,
        "q" => keyset.q = v,
        "dp" => keyset.dp = v,
        "dq" => keyset.dq = v,
        "qp" => keyset.qp = v,
        _ => {}
    }
}

fn apply_title(keyset: &mut TitleKeyset, name: &str, value: &str) -> Result<()> {
    match name.to_ascii_lowercase().as_str() {
        "passcode" => {
            let bytes = value.as_bytes();
            if bytes.len() != PASSCODE_SIZE {
                return Err(Error::InvalidLength {
                    what: "passcode",
                    expected: PASSCODE_SIZE,
                    got: bytes.len(),
                });
            }
            let mut pc = [0u8; PASSCODE_SIZE];
            pc.copy_from_slice(bytes);
            keyset.passcode = Some(pc);
        }
        "enc_tweak_key" => {
            keyset.enc_tweak_key = Some(parse_hex_array(value, "enc_tweak_key")?)
        }
        "enc_data_key" => keyset.enc_data_key = Some(parse_hex_array(value, "enc_data_key")?),
        "sig_hmac_key" => keyset.sig_hmac_key = Some(parse_hex_array(value, "sig_hmac_key")?),
        "image_key" => keyset.image_key = Some(parse_hex_array(value, "image_key")?),
        "sc0_key" => keyset.sc0_key = Some(parse_hex_array(value, "sc0_key")?),
        "content_key_seed" => {
            keyset.content_key_seed = Some(parse_hex_array(value, "content_key_seed")?)
        }
        "self_key_seed" => {
            keyset.self_key_seed = Some(parse_hex_array(value, "self_key_seed")?)
        }
        "ekc" => {
            let bytes = parse_hex(value)?;
            if bytes.len() != CONTENT_KEY_SIZE + SELF_KEY_SIZE {
                return Err(Error::InvalidLength {
                    what: "ekc",
                    expected: CONTENT_KEY_SIZE + SELF_KEY_SIZE,
                    got: bytes.len(),
                });
            }
            let mut cks = [0u8; CONTENT_KEY_SIZE];
            let mut sks = [0u8; SELF_KEY_SIZE];
            cks.copy_from_slice(&bytes[..CONTENT_KEY_SIZE]);
            sks.copy_from_slice(&bytes[CONTENT_KEY_SIZE..]);
            keyset.content_key_seed = Some(cks);
            keyset.self_key_seed = Some(sks);
        }
        _ => {}
    }
    Ok(())
}

fn strip_indexed<'a>(name: &'a str, prefix: &str) -> Option<u32> {
    name.strip_prefix(prefix)?.parse().ok()
}

fn ensure_slot<T>(slots: &mut Vec<Option<T>>, idx: usize) {
    if slots.len() <= idx {
        slots.resize_with(idx + 1, || None);
    }
}

fn set_indexed_vec<const L: usize>(
    slots: &mut Vec<Option<[u8; L]>>,
    one_based: u32,
    value: &str,
    what: &'static str,
) -> Result<()> {
    let idx = one_based
        .checked_sub(1)
        .ok_or_else(|| Error::Config(format!("{what} index must be >= 1")))? as usize;
    ensure_slot(slots, idx);
    slots[idx] = Some(parse_hex_array(value, what)?);
    Ok(())
}

fn set_indexed_vec_zero_based<const L: usize>(
    slots: &mut Vec<Option<[u8; L]>>,
    zero_based: u32,
    value: &str,
    what: &'static str,
) -> Result<()> {
    let idx = zero_based as usize;
    ensure_slot(slots, idx);
    slots[idx] = Some(parse_hex_array(value, what)?);
    Ok(())
}

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(Error::InvalidHex(format!("odd length: {s}")));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| Error::InvalidHex(format!("bad byte at {i}")))
        })
        .collect()
}

fn parse_hex_array<const N: usize>(s: &str, what: &'static str) -> Result<[u8; N]> {
    let bytes = parse_hex(s)?;
    if bytes.len() != N {
        return Err(Error::InvalidLength {
            what,
            expected: N,
            got: bytes.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join("")
}

fn write_rsa(out: &mut String, base: &str, key: &RsaKeyset) {
    let fields = [
        ("n", &key.n),
        ("e", &key.e),
        ("d", &key.d),
        ("p", &key.p),
        ("q", &key.q),
        ("dp", &key.dp),
        ("dq", &key.dq),
        ("qp", &key.qp),
    ];
    for (field, val) in &fields {
        if let Some(v) = val {
            out.push_str(&format!("{base}:{field}={v}\n"));
        }
    }
}
