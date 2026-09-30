//! Detects a locked screen so that the session can be locked (§13). Polls the platform state.

/// Returns `Some(true)` when the screen is locked, `None` when it cannot be determined.
pub fn screen_locked() -> Option<bool> {
    imp::screen_locked()
}

#[cfg(target_os = "macos")]
mod imp {
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

    const UTF8: u32 = 0x0800_0100;

    pub fn screen_locked() -> Option<bool> {
        unsafe {
            let dict = CGSessionCopyCurrentDictionary();
            if dict.is_null() {
                return None;
            }
            let key = CFStringCreateWithCString(
                std::ptr::null(),
                c"CGSSessionScreenIsLocked".as_ptr(),
                UTF8,
            );
            let v = CFDictionaryGetValue(dict, key);
            let locked = !v.is_null() && CFBooleanGetValue(v) != 0;
            CFRelease(key);
            CFRelease(dict);
            Some(locked)
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;

    #[link(name = "user32")]
    unsafe extern "system" {
        fn OpenInputDesktop(flags: u32, inherit: i32, access: u32) -> *mut c_void;
        fn CloseDesktop(desktop: *mut c_void) -> i32;
    }

    const DESKTOP_SWITCHDESKTOP: u32 = 0x0100;

    /// The input desktop cannot be opened while the workstation is locked.
    pub fn screen_locked() -> Option<bool> {
        unsafe {
            let d = OpenInputDesktop(0, 0, DESKTOP_SWITCHDESKTOP);
            if d.is_null() {
                return Some(true);
            }
            CloseDesktop(d);
            Some(false)
        }
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod imp {
    /// systemd-logind's LockedHint of the current session.
    pub fn screen_locked() -> Option<bool> {
        let session = std::env::var("XDG_SESSION_ID").ok()?;
        let out = std::process::Command::new("loginctl")
            .args(["show-session", &session, "-p", "LockedHint", "--value"])
            .output()
            .ok()?;
        match String::from_utf8_lossy(&out.stdout).trim() {
            "yes" => Some(true),
            "no" => Some(false),
            _ => None,
        }
    }
}
