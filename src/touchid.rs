//! Touch ID unlock on macOS (optional, per device). The password or passphrase of one identity
//! is sealed by `nepomuk-touchid` with a Secure Enclave key that is usable only after Touch ID
//! with the currently enrolled fingers. The CLI stores only the opaque blob.
//!
//! Deviation from §4 by design: on a Mac where it is enabled, the password can be recovered with
//! the owner's finger instead of being typed – like a password manager's biometric unlock.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::config;
use crate::error::{Code, Error, Result};
use crate::model::Id;

/// Which identity the sealed password belongs to.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Who {
    Email { email: String },
    File { path: PathBuf },
}

#[derive(Serialize, Deserialize)]
struct Record {
    who: Who,
    blob: Value,
    created: i64,
}

fn record_path(vault: Id) -> PathBuf {
    config::state_dir()
        .join("touchid")
        .join(format!("{}.json", vault.hex()))
}

/// The helper installed next to this program (symlinks resolved). Not from PATH, and the
/// `NEPOMUK_TOUCHID_HELPER` override only in debug builds (tests): `seal` hands the helper the
/// plain password, and the helper shows the Touch ID prompt.
fn helper() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os("NEPOMUK_TOUCHID_HELPER") {
        return Some(PathBuf::from(p));
    }
    let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
    exe.parent()
        .map(|d| d.join("nepomuk-touchid"))
        .filter(|p| p.is_file())
}

fn unavailable() -> Error {
    Error::new(Code::Usage, "Touch ID is not available on this computer")
}

pub fn available() -> bool {
    cfg!(target_os = "macos")
        && helper().is_some_and(|h| {
            Command::new(h)
                .arg("available")
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        })
}

fn run(args: &[&str], input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut child = Command::new(helper().ok_or_else(unavailable)?)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| unavailable())?;
    child.stdin.take().unwrap().write_all(input)?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stderr)
            .trim()
            .trim_start_matches("nepomuk-touchid: ")
            .to_string();
        return Err(Error::new(
            Code::BadCredentials,
            if msg.is_empty() {
                "Touch ID failed".into()
            } else {
                msg
            },
        ));
    }
    Ok(Zeroizing::new(out.stdout))
}

/// Seals the password for this vault and identity (no prompt).
pub fn enable(vault: Id, who: Who, password: &str) -> Result<()> {
    if !available() {
        return Err(unavailable());
    }
    let blob = run(&["seal"], password.as_bytes())?;
    let blob: Value = serde_json::from_slice(&blob)
        .map_err(|_| Error::general("unexpected Touch ID helper output"))?;
    let rec = Record {
        who,
        blob,
        created: crate::tx::now(),
    };
    config::write_private(
        &record_path(vault),
        &serde_json::to_vec_pretty(&rec).unwrap(),
    )
}

pub fn disable(vault: Id) -> bool {
    std::fs::remove_file(record_path(vault)).is_ok()
}

pub fn enabled_for(vault: Id) -> Option<Who> {
    let bytes = std::fs::read(record_path(vault)).ok()?;
    serde_json::from_slice::<Record>(&bytes).ok().map(|r| r.who)
}

/// Asks for Touch ID and returns the identity and its password.
pub fn unlock(vault: Id, reason: &str) -> Result<(Who, Zeroizing<String>)> {
    let bytes = std::fs::read(record_path(vault)).map_err(|_| {
        Error::new(
            Code::PasswordRequired,
            "Touch ID is not set up for this vault",
        )
    })?;
    let rec: Record =
        serde_json::from_slice(&bytes).map_err(|_| Error::format("corrupt Touch ID record"))?;
    let secret = run(&["open", reason], rec.blob.to_string().as_bytes())?;
    let password = String::from_utf8(secret.to_vec())
        .map_err(|_| Error::general("unexpected Touch ID helper output"))?;
    Ok((rec.who, Zeroizing::new(password)))
}

/// Whether the screen is locked (macOS); used by the agent to forget identities.
pub fn screen_locked() -> bool {
    screen::locked()
}

#[cfg(target_os = "macos")]
mod screen {
    use std::ffi::{c_char, c_void};

    type CFTypeRef = *const c_void;

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGSessionCopyCurrentDictionary() -> CFTypeRef;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFDictionaryGetValue(dict: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
        fn CFStringCreateWithCString(
            alloc: CFTypeRef,
            s: *const c_char,
            encoding: u32,
        ) -> CFTypeRef;
        fn CFBooleanGetValue(b: CFTypeRef) -> u8;
        fn CFRelease(cf: CFTypeRef);
    }

    pub fn locked() -> bool {
        unsafe {
            let dict = CGSessionCopyCurrentDictionary();
            if dict.is_null() {
                return false;
            }
            let key = CFStringCreateWithCString(
                std::ptr::null(),
                c"CGSSessionScreenIsLocked".as_ptr(),
                0x0800_0100,
            );
            let v = CFDictionaryGetValue(dict, key);
            let locked = !v.is_null() && CFBooleanGetValue(v) != 0;
            CFRelease(key);
            CFRelease(dict);
            locked
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod screen {
    pub fn locked() -> bool {
        false
    }
}
