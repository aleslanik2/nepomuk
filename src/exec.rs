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

/// Overwrites every file with zeros and deletes the directory.
pub fn remove_dir(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if let Ok(meta) = std::fs::metadata(&p)
                && meta.is_file()
                && let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&p)
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
    buf: Vec<u8>,
    hold: usize,
}

impl Masker {
    pub fn new(mut secrets: Vec<Vec<u8>>) -> Masker {
        secrets.retain(|s| s.len() >= 3);
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        secrets.dedup();
        let hold = secrets.iter().map(|s| s.len()).max().unwrap_or(1) - 1;
        Masker {
            secrets,
            buf: Vec::new(),
            hold,
        }
    }

    fn replace(&mut self) {
        for s in &self.secrets {
            let mut out = Vec::with_capacity(self.buf.len());
            let mut i = 0;
            while i < self.buf.len() {
                if self.buf[i..].starts_with(s) {
                    out.extend_from_slice(b"***");
                    i += s.len();
                } else {
                    out.push(self.buf[i]);
                    i += 1;
                }
            }
            self.buf = out;
        }
    }

    /// Feeds bytes; returns what can be emitted now.
    pub fn feed(&mut self, data: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(data);
        self.replace();
        let cut = if self.buf.ends_with(b"\n") {
            self.buf.len()
        } else {
            self.buf.len().saturating_sub(self.hold)
        };
        // Never emit a partial "***" boundary problem: the replacement is already done.
        self.buf.drain(..cut).collect()
    }

    pub fn finish(&mut self) -> Vec<u8> {
        self.replace();
        std::mem::take(&mut self.buf)
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
