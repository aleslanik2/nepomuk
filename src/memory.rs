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

/// Locked pages and how many live seeds use each: `mlock` works on whole pages and does not
/// count, so unlocking one seed would also unlock the others sharing its page.
#[cfg(unix)]
static LOCKED_PAGES: std::sync::Mutex<std::collections::BTreeMap<usize, usize>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

#[cfg(unix)]
fn page_size() -> usize {
    (unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).max(4096) as usize
}

/// Start addresses of the pages that `[ptr, ptr + len)` touches.
#[cfg(unix)]
fn pages(ptr: *const u8, len: usize) -> impl Iterator<Item = usize> {
    let size = page_size();
    let first = ptr as usize / size;
    let last = (ptr as usize + len - 1) / size;
    (first..=last).map(move |p| p * size)
}

#[cfg(unix)]
fn lock(ptr: *const u8, len: usize) {
    let mut locked = LOCKED_PAGES.lock().unwrap_or_else(|e| e.into_inner());
    for page in pages(ptr, len) {
        let n = locked.entry(page).or_insert(0);
        if *n == 0 {
            // Best effort: failure (e.g. RLIMIT_MEMLOCK) is not fatal.
            unsafe {
                libc::mlock(page as *const libc::c_void, page_size());
            }
        }
        *n += 1;
    }
}

#[cfg(unix)]
fn unlock(ptr: *const u8, len: usize) {
    let mut locked = LOCKED_PAGES.lock().unwrap_or_else(|e| e.into_inner());
    for page in pages(ptr, len) {
        let Some(n) = locked.get_mut(&page) else {
            continue;
        };
        *n -= 1;
        if *n == 0 {
            locked.remove(&page);
            unsafe {
                libc::munlock(page as *const libc::c_void, page_size());
            }
        }
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn dropping_a_seed_keeps_pages_of_live_seeds_locked() {
        let a = LockedSeed::random();
        let b = LockedSeed::random();
        let pages_of = |s: &LockedSeed| pages(s.as_ref().as_ptr(), 64).collect::<Vec<_>>();
        let held = pages_of(&b);
        drop(a);
        let locked = LOCKED_PAGES.lock().unwrap();
        for p in held {
            assert!(locked.get(&p).is_some_and(|n| *n >= 1));
        }
    }
}
