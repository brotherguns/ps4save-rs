//! Key and buffer sizes from pkg_pfs_tool keymgr.h / pfs.h.

pub const CONTENT_ID_SIZE: usize = 0x24;
pub const PASSCODE_SIZE: usize = 0x20;
pub const AES_KEY_SIZE: usize = 0x10;
pub const HMAC_KEY_SIZE: usize = 0x20;
pub const HASH_SIZE: usize = 0x20;
pub const SEED_SIZE: usize = 0x10;
pub const EKPFS_SIZE: usize = 0x20;
pub const CONTENT_KEY_SIZE: usize = 0x10;
pub const SC0_KEY_SIZE: usize = 0x10;
pub const SELF_KEY_SIZE: usize = 0x10;
pub const MKEY_SIZE: usize = 0x20;
pub const SEALED_KEY_ENC_KEY_SIZE: usize = 0x10;
pub const SEALED_KEY_SIGN_KEY_SIZE: usize = 0x10;
pub const SD_HEADER_SIG_KEY_SIZE: usize = 0x10;
pub const SD_HEADER_DATA_KEY_SIZE: usize = 0x10;
pub const SD_AUTH_CODE_KEY_SIZE: usize = 0x10;
pub const IDPS_SIZE: usize = 0x10;
pub const OPEN_PSID_SIZE: usize = 0x10;
pub const OPEN_PSID_SIG_KEY_SIZE: usize = 0x10;

pub const SEALED_KEY_SIZE: usize = 0x60;
pub const SEALED_KEY_COVER_SIZE: usize = 0x40;
pub const SEALED_KEY_MAGIC: &[u8; 8] = b"pfsSKKey";

pub const FAKE_CONTENT_ID: &str = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

/// Historical defaults from pkg_pfs_tool; real configs may have more entries.
pub const MAX_SEALED_KEY_VERSION: usize = 10;
pub const MAX_SD_CONTENT_KEY_VERSION: usize = 9;
pub const MAX_EKPFS_OBF_KEY: usize = 19;
