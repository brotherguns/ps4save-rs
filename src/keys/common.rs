use crate::keys::sizes::*;

/// RSA key components stored as uppercase hex strings (as in config.ini).
#[derive(Debug, Clone, Default)]
pub struct RsaKeyset {
    pub n: Option<String>,
    pub e: Option<String>,
    pub d: Option<String>,
    pub p: Option<String>,
    pub q: Option<String>,
    pub dp: Option<String>,
    pub dq: Option<String>,
    pub qp: Option<String>,
}

/// Global keys loaded from the `[common]` section of config.ini.
///
/// Indexed key tables grow as needed (1-based versions in config become 0-based indices).
#[derive(Debug, Clone, Default)]
pub struct CommonKeys {
    pub idps: Option<[u8; IDPS_SIZE]>,
    pub open_psid: Option<[u8; OPEN_PSID_SIZE]>,

    pub sealed_key_enc: Vec<Option<[u8; SEALED_KEY_ENC_KEY_SIZE]>>,
    pub sealed_key_sign: Vec<Option<[u8; SEALED_KEY_SIGN_KEY_SIZE]>>,

    pub sd_auth_code_key: Option<[u8; SD_AUTH_CODE_KEY_SIZE]>,
    pub sd_hdr_data_key: Option<[u8; SD_HEADER_DATA_KEY_SIZE]>,
    pub sd_hdr_sig_key: Option<[u8; SD_HEADER_SIG_KEY_SIZE]>,
    pub open_psid_sig_key: Option<[u8; OPEN_PSID_SIG_KEY_SIZE]>,

    pub sd_content_key: Vec<Option<[u8; CONTENT_KEY_SIZE]>>,

    pub ekpfs_obf_key: Vec<Option<[u8; AES_KEY_SIZE]>>,
    /// Indexed from 0 in config (`gdgp_ekc_key_0` …).
    pub gdgp_ekc_key: Vec<Option<[u8; AES_KEY_SIZE]>>,
    pub gdgp_content_key_obf_key: Option<[u8; AES_KEY_SIZE]>,
    pub ac_content_key: Option<[u8; AES_KEY_SIZE]>,

    pub pkg_entry_key_3: RsaKeyset,
    pub debug_ekpfs_key: RsaKeyset,
    pub retail_ekpfs_key_0: RsaKeyset,
    pub retail_ekpfs_key_1: RsaKeyset,
    pub fake_ekpfs_key: RsaKeyset,
    pub pfs_sig_key: RsaKeyset,
}

impl CommonKeys {
    pub fn sealed_enc_key(&self, version: u16) -> Option<&[u8; SEALED_KEY_ENC_KEY_SIZE]> {
        let idx = version.checked_sub(1)? as usize;
        self.sealed_key_enc.get(idx)?.as_ref()
    }

    pub fn sealed_sign_key(&self, version: u16) -> Option<&[u8; SEALED_KEY_SIGN_KEY_SIZE]> {
        let idx = version.checked_sub(1)? as usize;
        self.sealed_key_sign.get(idx)?.as_ref()
    }

    pub fn get_sd_content_key(&self, version: u32) -> Option<&[u8; CONTENT_KEY_SIZE]> {
        let idx = version.checked_sub(1)? as usize;
        self.sd_content_key.get(idx)?.as_ref()
    }

    pub fn ekpfs_obf(&self, one_based: u32) -> Option<&[u8; AES_KEY_SIZE]> {
        let idx = one_based.checked_sub(1)? as usize;
        self.ekpfs_obf_key.get(idx)?.as_ref()
    }
}
