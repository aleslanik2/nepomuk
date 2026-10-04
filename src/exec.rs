//! `nepomuk exec` (§11.4): hands secrets to one child process only for the duration of its run.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};

use zeroize::Zeroizing;

use crate::error::{Error, Result};

const DIR_PREFIX: &str = "nepomuk-exec-";

// ---------------------------------------------------------------- Private temporary files

/// Creates a private `0700` directory for secret files.
pub fn private_dir() -> Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "{DIR_PREFIX}{}-{}",
        std::process::id(),
        crate::model::Id::random().short()
    ));
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(&dir)?;
    Ok(dir)
}

/// Creates a `0600` file (Windows: temporary attribute; ACL left to the private temp directory).
pub fn write_private_file(path: &Path, data: &[u8]) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x100;
        opts.attributes(FILE_ATTRIBUTE_TEMPORARY);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

/// Whether `dir` is a real directory (not a symlink) that only the current user can use. The
/// temporary directory is shared with other users: anything else there may be a trap.
fn is_own_private_dir(dir: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(dir) else {
        return false;
    };
    if !meta.file_type().is_dir() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Opens a regular file for writing without following a symlink in its last component.
fn open_no_follow(p: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW);
    }
    o.open(p)
}

/// Overwrites every file with zeros and deletes the directory. Only a private directory of the
/// current user is touched, and only regular files in it are overwritten (never symlinks).
pub fn remove_dir(dir: &Path) {
    if !is_own_private_dir(dir) {
        return;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if let Ok(meta) = std::fs::symlink_metadata(&p)
                && meta.file_type().is_file()
                && let Ok(mut f) = open_no_follow(&p)
                && f.metadata()
                    .is_ok_and(|m| m.is_file() && m.len() == meta.len())
            {
                let zeros = vec![0u8; meta.len() as usize];
                let _ = f.write_all(&zeros);
                let _ = f.sync_all();
            }
            let _ = std::fs::remove_file(&p);
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}

fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    unsafe {
        libc::kill(pid as libc::pid_t, 0) == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

/// Removes leftovers of crashed runs.
pub fn cleanup_stale() {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let Some(rest) = name.strip_prefix(DIR_PREFIX) else {
            continue;
        };
        let Some(pid) = rest.split('-').next().and_then(|p| p.parse::<u32>().ok()) else {
            continue;
        };
        if pid != std::process::id() && !pid_alive(pid) {
            remove_dir(&e.path());
        }
    }
}

// ---------------------------------------------------------------- Masking

/// Replaces secret values in a byte stream with `***`, holding back a tail so that a secret
/// split across two reads is still caught.
pub struct Masker {
    secrets: Vec<Vec<u8>>,
    /// Bytes read but not yet emitted (raw, before masking).
    buf: Vec<u8>,
    /// How many bytes at the start of `buf` a secret already found covers.
    covered: usize,
    /// The last thing emitted was "***" (a covered run continues it).
    in_mask: bool,
}

impl Masker {
    pub fn new(mut secrets: Vec<Vec<u8>>) -> Masker {
        secrets.retain(|s| s.len() >= 3);
        secrets.sort();
        secrets.dedup();
        Masker {
            secrets,
            buf: Vec::new(),
            covered: 0,
            in_mask: false,
        }
    }

    /// Replaces every byte covered by any occurrence of any secret – overlapping ones
    /// included – with one "***" per covered run. Unless `finish`, it emits only up to the first
    /// position where a secret could still begin (the rest of the buffer is a proper prefix of
    /// a secret) and keeps the rest, newlines included, for the next read.
    fn process(&mut self, finish: bool) -> Vec<u8> {
        let n = self.buf.len();
        let limit = if finish {
            n
        } else {
            (0..n)
                .find(|&k| {
                    let rest = &self.buf[k..];
                    self.secrets
                        .iter()
                        .any(|s| s.len() > rest.len() && s.starts_with(rest))
                })
                .unwrap_or(n)
        };
        let mut cover = vec![false; n];
        for c in cover.iter_mut().take(self.covered.min(n)) {
            *c = true;
        }
        let mut reach = self.covered;
        for k in 0..limit {
            for s in &self.secrets {
                if self.buf[k..].starts_with(s) {
                    for c in &mut cover[k..k + s.len()] {
                        *c = true;
                    }
                    reach = reach.max(k + s.len());
                }
            }
        }
        let mut out = Vec::with_capacity(limit);
        for (j, &b) in self.buf[..limit].iter().enumerate() {
            if cover[j] {
                if !self.in_mask {
                    out.extend_from_slice(b"***");
                    self.in_mask = true;
                }
            } else {
                out.push(b);
                self.in_mask = false;
            }
        }
        self.buf.drain(..limit);
        self.covered = reach.saturating_sub(limit);
        out
    }

    /// Feeds bytes; returns what can be emitted now.
    pub fn feed(&mut self, data: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(data);
        self.process(false)
    }

    pub fn finish(&mut self) -> Vec<u8> {
        self.process(true)
    }
}

#[cfg(test)]
mod masker_tests {
    use super::Masker;

    fn run(secrets: &[&str], chunks: &[&str]) -> String {
        let mut m = Masker::new(secrets.iter().map(|s| s.as_bytes().to_vec()).collect());
        let mut out = Vec::new();
        for c in chunks {
            out.extend(m.feed(c.as_bytes()));
        }
        out.extend(m.finish());
        String::from_utf8(out).unwrap()
    }

    /// Every way of splitting `input` into two or three reads gives the same, fully masked
    /// output.
    fn all_splits(secrets: &[&str], input: &str, expected: &str) {
        let n = input.len();
        for a in 0..=n {
            for b in a..=n {
                let out = run(secrets, &[&input[..a], &input[a..b], &input[b..]]);
                assert!(out == expected, "split at {a}/{b}: wrong output");
            }
        }
    }

    #[test]
    fn overlapping_and_multiline_secrets_never_leak() {
        all_splits(&["abc", "abcdef"], "abcdef\n", "***\n");
        all_splits(&["abc", "abcdef"], "x abc y abcdef z\n", "x *** y *** z\n");
        all_splits(&["ab\ncd"], "ab\ncd\n", "***\n");
        all_splits(
            &["secret-value"],
            "a secret-value b\nsecret-\n",
            "a *** b\nsecret-\n",
        );
        all_splits(&["aaa"], "aaaaa\n", "***\n");
        all_splits(&["abc", "bcdefgh"], "xabcdefgh\n", "x***\n");
        all_splits(&["abcd", "cdefgh"], "abcdefgh!\n", "***!\n");
    }

    /// Random secrets and outputs: streamed in random reads, the result equals masking the
    /// whole output at once, and no secret is ever visible.
    #[test]
    fn fuzz_streamed_equals_whole_and_hides_secrets() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut rnd = |m: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % m
        };
        let alphabet = b"ab\nc";
        // Failure messages name the case number only: the generated values stand for secrets.
        for case in 0..3000 {
            let secrets: Vec<Vec<u8>> = (0..1 + rnd(3))
                .map(|_| (0..3 + rnd(4)).map(|_| alphabet[rnd(4) as usize]).collect())
                .collect();
            let input: Vec<u8> = (0..rnd(30)).map(|_| alphabet[rnd(4) as usize]).collect();
            let mut whole = Masker::new(secrets.clone());
            let mut expected = whole.feed(&input);
            expected.extend(whole.finish());
            let mut m = Masker::new(secrets.clone());
            let mut out = Vec::new();
            let mut i = 0;
            while i < input.len() {
                let j = (i + 1 + rnd(5) as usize).min(input.len());
                out.extend(m.feed(&input[i..j]));
                i = j;
            }
            out.extend(m.finish());
            assert!(out == expected, "case {case}: streamed output differs");
            for s in &secrets {
                assert!(
                    !out.windows(s.len()).any(|w| w == s.as_slice()),
                    "case {case}: a secret is visible"
                );
            }
        }
    }

    #[test]
    fn plain_output_is_emitted_without_delay() {
        let mut m = Masker::new(vec![b"secret".to_vec()]);
        assert_eq!(m.feed(b"hello\n"), b"hello\n");
        assert_eq!(m.feed(b"a se"), b"a ");
        assert_eq!(m.feed(b"xy"), b"sexy");
    }
}

fn pump(mut from: impl Read, mut to: impl Write, secrets: Vec<Vec<u8>>) {
    let mut m = Masker::new(secrets);
    let mut chunk = [0u8; 8192];
    loop {
        match from.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let out = m.feed(&chunk[..n]);
                let _ = to.write_all(&out);
                let _ = to.flush();
            }
        }
    }
    let _ = to.write_all(&m.finish());
    let _ = to.flush();
}

// ---------------------------------------------------------------- Running

pub struct ExecSpec {
    pub env: Vec<(String, Zeroizing<Vec<u8>>)>,
    pub files: Vec<(String, Zeroizing<Vec<u8>>)>,
    pub mask: bool,
}

static CHILD: AtomicI32 = AtomicI32::new(0);

#[cfg(unix)]
extern "C" fn forward(sig: libc::c_int) {
    let pid = CHILD.load(Ordering::SeqCst);
    if pid > 0 {
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

struct Cleanup {
    dir: Option<PathBuf>,
    #[cfg(target_os = "linux")]
    fds: Vec<libc::c_int>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(d) = &self.dir {
            remove_dir(d);
        }
        #[cfg(target_os = "linux")]
        for fd in &self.fds {
            unsafe {
                libc::close(*fd);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn memfd(name: &str, data: &[u8]) -> Result<(libc::c_int, String)> {
    let cname = std::ffi::CString::new(name).unwrap();
    // No MFD_CLOEXEC: the child inherits the descriptor.
    let fd = unsafe { libc::memfd_create(cname.as_ptr(), 0) };
    if fd < 0 {
        return Err(Error::general("memfd_create failed"));
    }
    let mut written = 0;
    while written < data.len() {
        let n = unsafe {
            libc::write(
                fd,
                data[written..].as_ptr() as *const libc::c_void,
                data.len() - written,
            )
        };
        if n <= 0 {
            return Err(Error::general("writing memfd failed"));
        }
        written += n as usize;
    }
    unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    Ok((fd, format!("/proc/self/fd/{fd}")))
}

/// Runs the command with the secrets; returns its exit code.
pub fn run(spec: ExecSpec, command: &[String]) -> Result<i32> {
    run_inner(spec, command, false).map(|(code, _, _)| code)
}

/// Runs the command with masked, captured output (`serve --stdio`).
pub fn run_captured(spec: ExecSpec, command: &[String]) -> Result<(i32, String, String)> {
    run_inner(ExecSpec { mask: true, ..spec }, command, true)
}

fn run_inner(spec: ExecSpec, command: &[String], capture: bool) -> Result<(i32, String, String)> {
    if command.is_empty() {
        return Err(Error::usage("missing command after --"));
    }
    cleanup_stale();
    let mut cleanup = Cleanup {
        dir: None,
        #[cfg(target_os = "linux")]
        fds: Vec::new(),
    };
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);
    // Credentials of nepomuk itself never reach the child.
    for v in ["NEPOMUK_PASSPHRASE", "NEPOMUK_PASSWORD", "NEPOMUK_IDENTITY"] {
        cmd.env_remove(v);
    }
    let mut mask: Vec<Vec<u8>> = Vec::new();
    for (name, value) in &spec.env {
        let s = std::str::from_utf8(value).map_err(|_| {
            Error::usage(format!(
                "{name}: binary value cannot go into an environment variable; use file.{name}"
            ))
        })?;
        cmd.env(name, s);
        mask.push(value.to_vec());
        mask.extend(
            s.lines()
                .filter(|l| l.len() >= 3)
                .map(|l| l.as_bytes().to_vec()),
        );
    }
    for (i, (name, data)) in spec.files.iter().enumerate() {
        #[cfg(target_os = "linux")]
        let path = {
            let (fd, path) = memfd(&format!("nepomuk-{i}"), data)?;
            cleanup.fds.push(fd);
            path
        };
        #[cfg(not(target_os = "linux"))]
        let path = {
            if cleanup.dir.is_none() {
                cleanup.dir = Some(private_dir()?);
            }
            let p = cleanup
                .dir
                .as_ref()
                .unwrap()
                .join(format!("{i}-{}", name.to_lowercase()));
            write_private_file(&p, data)?;
            p.to_string_lossy().to_string()
        };
        cmd.env(name, path);
        if let Ok(s) = std::str::from_utf8(data)
            && s.len() <= 16 * 1024
        {
            mask.extend(
                s.lines()
                    .filter(|l| l.trim().len() >= 8)
                    .map(|l| l.as_bytes().to_vec()),
            );
        }
    }
    if !capture && std::env::var("GITHUB_ACTIONS").is_ok_and(|v| v == "true") {
        let mut out = std::io::stdout().lock();
        for m in &mask {
            if let Ok(s) = std::str::from_utf8(m)
                && !s.contains('\n')
            {
                let _ = writeln!(out, "::add-mask::{s}");
            }
        }
    }
    if spec.mask {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| Error::general(format!("cannot start {}: {e}", command[0])))?;
    CHILD.store(child.id() as i32, Ordering::SeqCst);
    #[cfg(unix)]
    unsafe {
        let h = forward as *const () as libc::sighandler_t;
        libc::signal(libc::SIGTERM, h);
        libc::signal(libc::SIGHUP, h);
        // Ctrl+C on a terminal reaches the whole process group already.
        if libc::isatty(0) == 1 {
            libc::signal(libc::SIGINT, libc::SIG_IGN);
        } else {
            libc::signal(libc::SIGINT, h);
        }
    }
    let mut threads: Vec<std::thread::JoinHandle<Vec<u8>>> = Vec::new();
    if spec.mask {
        let out = child.stdout.take().unwrap();
        let err = child.stderr.take().unwrap();
        let m1 = mask.clone();
        let m2 = mask.clone();
        if capture {
            threads.push(std::thread::spawn(move || {
                let mut buf = Vec::new();
                pump(out, &mut buf, m1);
                buf
            }));
            threads.push(std::thread::spawn(move || {
                let mut buf = Vec::new();
                pump(err, &mut buf, m2);
                buf
            }));
        } else {
            threads.push(std::thread::spawn(move || {
                pump(out, std::io::stdout(), m1);
                Vec::new()
            }));
            threads.push(std::thread::spawn(move || {
                pump(err, std::io::stderr(), m2);
                Vec::new()
            }));
        }
    }
    let status = child.wait()?;
    let mut captured: Vec<String> = Vec::new();
    for t in threads {
        captured.push(String::from_utf8_lossy(&t.join().unwrap_or_default()).to_string());
    }
    captured.resize(2, String::new());
    CHILD.store(0, Ordering::SeqCst);
    drop(cleanup);
    for m in mask.iter_mut() {
        zeroize::Zeroize::zeroize(m);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return Ok((128 + sig, captured[0].clone(), captured[1].clone()));
        }
    }
    Ok((
        status.code().unwrap_or(1),
        captured[0].clone(),
        captured[1].clone(),
    ))
}

#[cfg(test)]
mod tests {
    use super::Masker;

    #[test]
    fn masks_across_chunks() {
        let mut m = Masker::new(vec![b"hunter2secret".to_vec()]);
        let mut out = m.feed(b"password is hunter2");
        out.extend(m.feed(b"secret, ok\n"));
        out.extend(m.finish());
        assert_eq!(String::from_utf8(out).unwrap(), "password is ***, ok\n");
    }
}
