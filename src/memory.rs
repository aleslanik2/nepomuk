//! Memory hygiene (§3): seeds in locked, zeroized memory; core dumps disabled.

use zeroize::Zeroize;

use crate::error::{Error, Result};

/// A 64-byte identity or group seed kept in a page locked against swapping.
pub struct LockedSeed(Box<[u8; 64]>);

impl LockedSeed {
    pub fn random() -> Self {
        let s = Self::zeroed();
        let mut s = s;
        getrandom::fill(s.0.as_mut()).expect("OS CSPRNG unavailable");
        s
    }

    fn zeroed() -> Self {
        let b = Box::new([0u8; 64]);
        lock(b.as_ptr(), 64);
        LockedSeed(b)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(Error::decrypt());
        }
        let mut s = Self::zeroed();
        s.0.copy_from_slice(bytes);
        Ok(s)
    }
}

impl AsRef<[u8]> for LockedSeed {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Drop for LockedSeed {
    fn drop(&mut self) {
        self.0.zeroize();
        unlock(self.0.as_ptr(), 64);
    }
}

#[cfg(unix)]
fn lock(ptr: *const u8, len: usize) {
    // Best effort: failure (e.g. RLIMIT_MEMLOCK) is not fatal.
    unsafe {
        libc::mlock(ptr as *const libc::c_void, len);
    }
}

#[cfg(unix)]
fn unlock(ptr: *const u8, len: usize) {
    unsafe {
        libc::munlock(ptr as *const libc::c_void, len);
    }
}

#[cfg(not(unix))]
fn lock(_ptr: *const u8, _len: usize) {}

#[cfg(not(unix))]
fn unlock(_ptr: *const u8, _len: usize) {}

/// Disables core dumps for this process.
pub fn harden_process() {
    #[cfg(unix)]
    unsafe {
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}
