use crate::config::Config;
use crate::keys::{decrypt_sealed_key, encrypt_sealed_key};

pub fn run_selftest(path: &str, version: u16) -> crate::Result<()> {
    let cfg = Config::load(path)?;
    let mkey = [0x42u8; 32];
    let iv = [0x11u8; 16];
    let sealed = encrypt_sealed_key(&cfg.common, version, iv, &mkey)?;
    let out = decrypt_sealed_key(&cfg.common, &sealed)?;
    if out != mkey {
        return Err(crate::Error::Message(
            "mkey mismatch after sealed-key roundtrip".into(),
        ));
    }
    Ok(())
}
