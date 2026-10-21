//! C ABI shim exposing the ps4save-rs core to the iOS app.
//!
//! The ObjC side calls `ps4save_ios_run(...)` on a background thread and gets
//! back a malloc'd UTF-8 string containing the command output (captured
//! stdout) or "error: ...". Strings are freed with `ps4save_ios_free`.

#![allow(clippy::missing_safety_doc)]

use std::ffi::{CStr, CString, c_char, c_int};
use std::os::fd::FromRawFd;
use std::path::PathBuf;

const CMD_SELFTEST: c_int = 0;
const CMD_DECRYPT: c_int = 1;
const CMD_ENCRYPT: c_int = 2;
const CMD_RESIGN: c_int = 3;
const CMD_REREGION: c_int = 4;
const CMD_INSPECT: c_int = 5;
const CMD_KEYSTONE: c_int = 6;
const CMD_LIST: c_int = 7;
const CMD_CHECK_CONFIG: c_int = 8;

/// Resolve the app's Documents directory (sandbox root HOME/Documents).
fn documents_dir() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join("Documents"))
}

fn opt_str(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn dup_str(s: &str) -> *mut c_char {
    match CString::new(s.replace('\0', "")) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn capture_stdout<F: FnOnce()>(f: F) -> String {
    unsafe {
        let orig = libc::dup(1);
        let mut pipe = [0i32; 2];
        libc::pipe(pipe.as_mut_ptr());
        libc::dup2(pipe[1], 1);
        libc::close(pipe[1]);

        let reader = std::thread::spawn(move || {
            use std::io::BufRead;
            let file = std::fs::File::from_raw_fd(pipe[0]);
            std::io::BufReader::new(file)
                .lines()
                .filter_map(|l| l.ok())
                .collect::<Vec<_>>()
        });

        f();

        libc::dup2(orig, 1);
        libc::close(orig);
        reader.join().unwrap_or_default().join("\n")
    }
}

/// One dispatched command; errors bubble so the caller can print them into the
/// same captured stream the app renders.
fn dispatch(
    cmd: c_int,
    config: &str,
    input: Option<String>,
    output: Option<String>,
    sample: Option<String>,
    account: Option<String>,
) -> ps4save_rs::Result<()> {
    match cmd {
        CMD_SELFTEST => ps4save_rs::commands::run_selftest(config, 2),
        CMD_DECRYPT => ps4save_rs::commands::run_decrypt(config, &input.unwrap_or_default(), output.as_deref()),
        CMD_ENCRYPT => ps4save_rs::commands::run_encrypt(
            config,
            &input.unwrap_or_default(),
            output.as_deref(),
            None,
            None,
            None,
            false,
        ),
        CMD_RESIGN => ps4save_rs::commands::run_resign(
            config,
            &input.unwrap_or_default(),
            account.as_deref().unwrap_or("0000000000000000"),
            output.as_deref(),
            false,
        ),
        CMD_REREGION => ps4save_rs::commands::reregion_from_paths(
            config,
            &input.unwrap_or_default(),
            &sample.unwrap_or_default(),
            account.as_deref(),
            output.as_deref(),
            false,
        ),
        CMD_INSPECT => ps4save_rs::commands::inspect_path(config, &input.unwrap_or_default()),
        CMD_KEYSTONE => ps4save_rs::commands::run_keystone(config, &input.unwrap_or_default(), output.as_deref()),
        CMD_LIST => ps4save_rs::commands::list_path(config, &input.unwrap_or_default()),
        CMD_CHECK_CONFIG => {
            let c = ps4save_rs::config::Config::load(config)?;
            println!(
                "loaded {config}: {} sealed enc, {} sealed sign, {} sd content, {} ekpfs obf, {} title sections",
                c.common.sealed_key_enc.iter().filter(|k| k.is_some()).count(),
                c.common.sealed_key_sign.iter().filter(|k| k.is_some()).count(),
                c.common.sd_content_key.iter().filter(|k| k.is_some()).count(),
                c.common.ekpfs_obf_key.iter().filter(|k| k.is_some()).count(),
                c.titles.len()
            );
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Run a command. All path arguments may be NULL/empty; the app drives which
/// are required. Returns a malloc'd C string (use ps4save_ios_free) with the
/// captured output, or an "error: ..." message on failure.
#[no_mangle]
pub extern "C" fn ps4save_ios_run(
    cmd: c_int,
    config: *const c_char,
    input: *const c_char,
    output: *const c_char,
    sample: *const c_char,
    account: *const c_char,
) -> *mut c_char {
    // iOS gives us "/" as cwd; ops with WORKDIR ("workdir") must write
    // somewhere writable, so anchor everything at Documents for this call.
    if let Some(docs) = documents_dir() {
        if std::env::set_current_dir(&docs).is_err() {
            let _ = std::fs::create_dir_all(&docs);
            let _ = std::env::set_current_dir(&docs);
        }
    }
    let config = opt_str(config).unwrap_or_default();
    let input = opt_str(input);
    let output = opt_str(output);
    let sample = opt_str(sample);
    let account = opt_str(account);

    let res: String = capture_stdout(|| {
        if let Err(e) = dispatch(cmd, &config, input, output, sample, account) {
            println!("error: {e}");
        }
    });

    dup_str(&res)
}

/// Version string (static, no free needed).
#[no_mangle]
pub extern "C" fn ps4save_ios_version() -> *const c_char {
    concat!("ps4save-rs core v", env!("CARGO_PKG_VERSION"), " (ios)\n").as_ptr() as *const c_char
}

/// App Documents dir as malloc'd C string.
#[no_mangle]
pub extern "C" fn ps4save_ios_documents_dir() -> *mut c_char {
    match documents_dir() {
        Some(d) => dup_str(&d.to_string_lossy()),
        None => std::ptr::null_mut(),
    }
}

/// Default settings path (Documents/config.ini) as malloc'd C string.
#[no_mangle]
pub extern "C" fn ps4save_ios_default_config() -> *mut c_char {
    match documents_dir() {
        Some(d) => dup_str(&d.join("config.ini").to_string_lossy()),
        None => std::ptr::null_mut(),
    }
}

/// Free a string previously returned by this shim.
#[no_mangle]
pub unsafe extern "C" fn ps4save_ios_free(p: *mut c_char) {
    if !p.is_null() {
        drop(CString::from_raw(p));
    }
}
