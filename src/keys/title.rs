use crate::keys::sizes::*;

/// Per-title key material from a non-`[common]` config section, plus derived fields.
#[derive(Debug, Clone, Default)]
pub struct TitleKeyset {
    pub content_id: String,

    pub passcode: Option<[u8; PASSCODE_SIZE]>,
    pub mkey: Option<[u8; MKEY_SIZE]>,
    pub image_key: Option<[u8; HASH_SIZE]>,

    pub enc_tweak_key: Option<[u8; AES_KEY_SIZE]>,
    pub enc_data_key: Option<[u8; AES_KEY_SIZE]>,
    pub sig_hmac_key: Option<[u8; HMAC_KEY_SIZE]>,
    pub sc0_key: Option<[u8; SC0_KEY_SIZE]>,

    pub content_key_seed: Option<[u8; CONTENT_KEY_SIZE]>,
    pub self_key_seed: Option<[u8; SELF_KEY_SIZE]>,
}

impl TitleKeyset {
    pub fn new(content_id: impl Into<String>) -> Self {
        Self {
            content_id: content_id.into(),
            passcode: None,
            mkey: None,
            image_key: None,
            enc_tweak_key: None,
            enc_data_key: None,
            sig_hmac_key: None,
            sc0_key: None,
            content_key_seed: None,
            self_key_seed: None,
        }
    }

    pub fn has_passcode(&self) -> bool {
        self.passcode.is_some()
    }

    pub fn has_mkey(&self) -> bool {
        self.mkey.is_some()
    }

    pub fn has_image_key(&self) -> bool {
        self.image_key.is_some()
    }

    pub fn has_encryption_key(&self) -> bool {
        self.enc_tweak_key.is_some() && self.enc_data_key.is_some()
    }

    pub fn has_signing_key(&self) -> bool {
        self.sig_hmac_key.is_some()
    }

    pub fn has_sc0_key(&self) -> bool {
        self.sc0_key.is_some()
    }

    pub fn has_ekc(&self) -> bool {
        self.content_key_seed.is_some() && self.self_key_seed.is_some()
    }
}
