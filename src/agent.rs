//! A short-lived agent that keeps identities unlocked with Touch ID, so that the CLI asks for a
//! fingerprint at most once per `agent_timeout` (default 10 minutes) – like `sudo` or `ssh-agent`.
//!
//! The agent listens on a Unix socket in the user's private state directory (`0700`, socket
//! `0600`) and serves only peers with the same UID. It forgets everything when the timeout
//! expires, when the screen locks, on `nepomuk lock`, and exits once it holds nothing.
//!
//! Limits on what a cached identity can be used for:
//! - **It gets only the decryption key.** The CLI that unlocked the identity sends the KEM key
//!   material and the public signing key, never the seed (which also derives the signing key),
//!   and only to an agent that is the same program run by the same user (peer UID and
//!   executable checked), not to whatever listens on the socket. Clients get the public keys
//!   and ask the agent to unwrap keys wrapped for the identity (grants, group keys, pending
//!   changes of that vault); like `ssh-agent`, it never hands out the private key, so a program
//!   that reaches it can use the identity only while it is cached, not keep it.
//! - **It never signs.** Every change to the vault needs a fresh unlock; the cache only reads.
//! - **One terminal.** An identity is cached for the terminal session of the program that
//!   unlocked it (terminal device, session and the session leader's start time, taken from the
//!   kernel, not from the client) and is served only to programs in that same session. Other
//!   terminal windows, and programs without a terminal (editors, daemons, cron), get nothing.
//!
//! Remaining trade-offs: within the timeout, any program in that terminal session – including
//! background jobs and a build started by `nepomuk exec` – can read what the identity can read,
//! and a program that can type into the terminal (tmux, screen, AppleScript) can too.

use crate::crypto::{KemPublic, SigPublic, Wrapped};
use crate::error::{Code, Error, Result};
use crate::identity::{Keys, Unlocked};
use crate::model::{Id, IdentityKind};

pub const DEFAULT_TIMEOUT: u64 = 600;

/// Whether this process has a controlling terminal (the agent caches only for those).
pub fn has_terminal() -> bool {
    #[cfg(unix)]
    {
        std::fs::File::open("/dev/tty").is_ok()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// An identity served by the agent: public keys only; unwrapping happens inside the agent.
pub struct AgentKeys {
    pub vault: Id,
    pub name: String,
    pub kind: IdentityKind,
    pub kem: KemPublic,
    pub sig: SigPublic,
}

impl Keys for AgentKeys {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> IdentityKind {
        self.kind
    }
    fn kem_public(&self) -> &KemPublic {
        &self.kem
    }
    fn sig_public(&self) -> &SigPublic {
        &self.sig
    }
    fn unwrap(&self, w: &Wrapped, aad: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        unwrap_remote(self.vault, w, aad)
    }
    fn sign(&self, _label: &str, _data: &[u8]) -> Result<Vec<u8>> {
        Err(Error::new(
            Code::PasswordRequired,
            "changing the vault needs a fresh unlock",
        ))
    }
}

#[cfg(unix)]
pub use imp::*;

#[cfg(not(unix))]
mod fallback {
    use super::*;

    pub fn keys(_vault: Id) -> Option<AgentKeys> {
        None
    }
    pub(super) fn unwrap_remote(
        _vault: Id,
        _w: &Wrapped,
        _aad: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        Err(Error::decrypt())
    }
    pub fn put(_vault: Id, _id: &Unlocked, _ttl: u64) -> Result<()> {
        Ok(())
    }
    pub fn forget(_vault: Option<Id>) -> bool {
        false
    }
    pub fn status() -> Option<serde_json::Value> {
        None
    }
    pub fn run_daemon() -> i32 {
        1
    }
}

#[cfg(not(unix))]
pub use fallback::*;

#[cfg(unix)]
mod imp {
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use base64::Engine;
    use serde_json::{Value, json};
    use zeroize::Zeroizing;

    use super::*;

    /// A private directory of this user, short enough for a socket path (about 100 bytes):
    /// `$TMPDIR` on macOS, `$XDG_RUNTIME_DIR` on Linux, otherwise the state directory.
    fn dir() -> PathBuf {
        let private = |p: PathBuf| -> Option<PathBuf> {
            use std::os::unix::fs::MetadataExt;
            let m = std::fs::metadata(&p).ok()?;
            let mine = m.uid() == unsafe { libc::getuid() } && m.mode() & 0o022 == 0;
            (m.is_dir() && mine).then_some(p)
        };
        let var = if cfg!(target_os = "macos") {
            "TMPDIR"
        } else {
            "XDG_RUNTIME_DIR"
        };
        std::env::var_os(var)
            .map(PathBuf::from)
            .and_then(private)
            .unwrap_or_else(|| crate::config::state_dir().join("agent"))
    }

    /// One agent per state directory (tests and multiple setups do not mix).
    fn socket() -> PathBuf {
        let state = crate::config::state_dir();
        let tag = hex::encode(&crate::crypto::sha3(&[state.to_string_lossy().as_bytes()])[..6]);
        dir().join(format!("nepomuk-agent-{tag}.sock"))
    }

    fn b64() -> base64::engine::GeneralPurpose {
        base64::engine::general_purpose::STANDARD
    }

    fn request(msg: &Value) -> Option<Value> {
        request_line(&Zeroizing::new(format!("{msg}\n")))
    }

    /// Sends one request line, only to an agent that is this program run by this user: another
    /// process of the user could have put its own socket in place.
    fn request_line(line: &Zeroizing<String>) -> Option<Value> {
        let mut s = UnixStream::connect(socket()).ok()?;
        if !server_is_agent(&s) {
            return None;
        }
        s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        s.set_write_timeout(Some(Duration::from_secs(5))).ok()?;
        s.write_all(line.as_bytes()).ok()?;
        let mut resp = Zeroizing::new(String::new());
        BufReader::new(s).read_line(&mut resp).ok()?;
        serde_json::from_str(&resp).ok()
    }

    /// The identity cached for this vault in this terminal, if any (public keys only).
    pub fn keys(vault: Id) -> Option<AgentKeys> {
        let r = request(&json!({ "op": "info", "vault": vault.hex() }))?;
        if r["ok"] != true {
            return None;
        }
        let (kem, sig): (KemPublic, SigPublic) =
            crate::format::from_cbor(&b64().decode(r["public"].as_str()?).ok()?).ok()?;
        let kind = if r["kind"] == "password" {
            IdentityKind::Password
        } else {
            IdentityKind::Local
        };
        Some(AgentKeys {
            vault,
            name: r["name"].as_str()?.to_string(),
            kind,
            kem,
            sig,
        })
    }

    /// Asks the agent to unwrap a key wrapped for the cached identity of `vault`.
    pub(super) fn unwrap_remote(vault: Id, w: &Wrapped, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let msg = json!({
            "op": "unwrap",
            "vault": vault.hex(),
            "wrapped": b64().encode(crate::format::to_cbor(w)),
            "aad": b64().encode(aad),
        });
        let r = request(&msg).ok_or_else(|| {
            Error::new(
                Code::PasswordRequired,
                "the nepomuk agent no longer holds the identity; run the command again",
            )
        })?;
        if r["ok"] != true {
            return Err(Error::decrypt());
        }
        let plain = r["plain"].as_str().ok_or_else(Error::decrypt)?;
        b64()
            .decode(plain)
            .map(Zeroizing::new)
            .map_err(|_| Error::decrypt())
    }

    /// Caches an identity for `ttl` seconds for the caller's terminal, starting the agent when
    /// needed. Fails when the caller has no terminal.
    pub fn put(vault: Id, id: &Unlocked, ttl: u64) -> Result<()> {
        if request(&json!({ "op": "ping" })).is_none() {
            start()?;
        }
        // Only what decrypting needs: the KEM key material and the public signing key. The seed
        // (which also derives the signing key) never leaves this process.
        let kem = Zeroizing::new(
            b64().encode(crate::crypto::KemSecret::material(id.seed.as_ref(), "identity").as_ref()),
        );
        let sig_public = b64().encode(crate::format::to_cbor(id.sig.public()));
        let kind = if id.kind == IdentityKind::Password {
            "password"
        } else {
            "local"
        };
        // Built by hand, so the key material is only in zeroized buffers.
        let head = json!({ "op": "put", "vault": vault.hex(), "name": id.name, "kind": kind, "sig_public": sig_public, "ttl": ttl }).to_string();
        let mut line = Zeroizing::new(String::with_capacity(head.len() + kem.len() + 16));
        line.push_str(&head[..head.len() - 1]);
        line.push_str(",\"kem\":\"");
        line.push_str(&kem);
        line.push_str("\"}\n");
        match request_line(&line) {
            Some(r) if r["ok"] == true => Ok(()),
            Some(r) if r["error"] == "no-terminal" => Err(Error::general(
                "it is remembered only for programs in a terminal",
            )),
            _ => Err(Error::general(
                "the nepomuk agent did not accept the identity",
            )),
        }
    }

    pub fn forget(vault: Option<Id>) -> bool {
        let msg = match vault {
            Some(v) => json!({ "op": "forget", "vault": v.hex() }),
            None => json!({ "op": "forget" }),
        };
        request(&msg).is_some_and(|r| r["ok"] == true)
    }

    pub fn status() -> Option<Value> {
        request(&json!({ "op": "status" }))
    }

    fn start() -> Result<()> {
        use std::os::unix::process::CommandExt;
        let exe = agent_exe().ok_or_else(|| Error::general("cannot find the nepomuk program"))?;
        std::process::Command::new(exe)
            .args(["agent", "--daemon"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            // Its own process group: Ctrl+C in the terminal does not stop it.
            .process_group(0)
            .spawn()?;
        for _ in 0..50 {
            if request(&json!({ "op": "ping" })).is_some() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(Error::general("cannot start the nepomuk agent"))
    }

    // ------------------------------------------------------------ Daemon

    struct Entry {
        name: String,
        kind: String,
        kem: crate::crypto::KemSecret,
        public: String,
        expires: Instant,
    }

    /// Entries by vault and terminal session.
    type Store = Arc<Mutex<HashMap<(String, String), Entry>>>;

    /// The process at the other end of the socket is this user running this same program.
    fn server_is_agent(s: &UnixStream) -> bool {
        if !peer_is_me(s) {
            return false;
        }
        let same = |a: &std::path::Path, b: &std::path::Path| match (
            std::fs::canonicalize(a),
            std::fs::canonicalize(b),
        ) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        };
        match (peer_pid(s).and_then(exe_of), agent_exe()) {
            (Some(peer), Some(me)) => same(&peer, &me),
            _ => false,
        }
    }

    /// The program the agent runs as: this one. Tests that drive the library from a test
    /// binary name the CLI instead (debug builds only).
    fn agent_exe() -> Option<PathBuf> {
        #[cfg(debug_assertions)]
        if let Some(p) = std::env::var_os("NEPOMUK_AGENT_EXE") {
            return Some(PathBuf::from(p));
        }
        std::env::current_exe().ok()
    }

    fn peer_pid(s: &UnixStream) -> Option<libc::pid_t> {
        use std::os::unix::io::AsRawFd;
        #[cfg(target_os = "macos")]
        {
            let mut pid: libc::pid_t = 0;
            let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
            let ok = unsafe {
                libc::getsockopt(
                    s.as_raw_fd(),
                    libc::SOL_LOCAL,
                    libc::LOCAL_PEERPID,
                    &mut pid as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            } == 0;
            (ok && pid > 0).then_some(pid)
        }
        #[cfg(target_os = "linux")]
        {
            let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            let ok = unsafe {
                libc::getsockopt(
                    s.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    &mut cred as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            } == 0;
            (ok && cred.pid > 0).then_some(cred.pid)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = s.as_raw_fd();
            None
        }
    }

    /// The executable of a process.
    fn exe_of(pid: libc::pid_t) -> Option<PathBuf> {
        #[cfg(target_os = "macos")]
        {
            let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
            let n = unsafe {
                libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32)
            };
            if n <= 0 {
                return None;
            }
            buf.truncate(n as usize);
            use std::os::unix::ffi::OsStringExt;
            Some(PathBuf::from(std::ffi::OsString::from_vec(buf)))
        }
        #[cfg(target_os = "linux")]
        {
            std::fs::read_link(format!("/proc/{pid}/exe")).ok()
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = pid;
            None
        }
    }

    fn peer_is_me(s: &UnixStream) -> bool {
        use std::os::unix::io::AsRawFd;
        let me = unsafe { libc::getuid() };
        #[cfg(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        ))]
        unsafe {
            let mut uid: libc::uid_t = 0;
            let mut gid: libc::gid_t = 0;
            libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) == 0 && uid == me
        }
        #[cfg(target_os = "linux")]
        unsafe {
            let mut cred: libc::ucred = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            libc::getsockopt(
                s.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            ) == 0
                && cred.uid == me
        }
        #[cfg(not(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "linux"
        )))]
        {
            let _ = (s, me);
            false
        }
    }

    /// The terminal session of the peer, from the kernel: `<tty device>:<session id>:<start time
    /// of the session leader>`. The start time keeps a recycled session id from matching. None
    /// for a peer without a controlling terminal, or when it cannot be determined reliably.
    #[cfg(target_os = "linux")]
    pub(crate) fn peer_terminal(s: &UnixStream) -> Option<String> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        // A pidfd pins the peer process: if it exits while we look it up, its pid could be
        // reused by another process, and the pidfd then reports it as gone.
        let mut raw: libc::c_int = -1;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let ok = unsafe {
            libc::getsockopt(
                s.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERPIDFD,
                &mut raw as *mut _ as *mut libc::c_void,
                &mut len,
            )
        } == 0;
        if !ok || raw < 0 {
            return None; // older kernel: no caching rather than a racy lookup
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
        let pid = pidfd_pid(&pidfd)?;
        let (sid, tty, _) = proc_stat(pid)?;
        if tty == 0 || sid <= 0 {
            return None;
        }
        let (_, _, leader_start) = proc_stat(sid)?;
        let mut pfd = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let exited = unsafe { libc::poll(&mut pfd, 1, 0) } != 0;
        if exited {
            return None;
        }
        Some(format!("{tty}:{sid}:{leader_start}"))
    }

    /// The pid a pidfd refers to (`Pid:` in `/proc/self/fdinfo`).
    #[cfg(target_os = "linux")]
    fn pidfd_pid(fd: &std::os::fd::OwnedFd) -> Option<i32> {
        use std::os::fd::AsRawFd;
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).ok()?;
        info.lines()
            .find_map(|l| l.strip_prefix("Pid:"))
            .and_then(|p| p.trim().parse().ok())
            .filter(|p: &i32| *p > 0)
    }

    /// Session id, controlling tty and start time of a process (`/proc/<pid>/stat`).
    #[cfg(target_os = "linux")]
    fn proc_stat(pid: i32) -> Option<(i32, i64, u64)> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // The command name may contain spaces and parentheses: fields follow the last ')'.
        let rest = &stat[stat.rfind(')')? + 1..];
        let f: Vec<&str> = rest.split_whitespace().collect();
        // f[0] is field 3 (state): session = field 6, tty_nr = 7, starttime = 22.
        let sid = f.get(3)?.parse().ok()?;
        let tty = f.get(4)?.parse().ok()?;
        let start = f.get(19)?.parse().ok()?;
        Some((sid, tty, start))
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn peer_terminal(s: &UnixStream) -> Option<String> {
        use std::os::fd::AsRawFd;
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        let ok = unsafe {
            libc::getsockopt(
                s.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                &mut pid as *mut _ as *mut libc::c_void,
                &mut len,
            )
        } == 0;
        if !ok || pid <= 0 {
            return None;
        }
        let before = bsd_info(pid)?;
        // NODEV: no controlling terminal.
        if before.e_tdev == u32::MAX || before.e_tdev == 0 {
            return None;
        }
        let sid = unsafe { libc::getsid(pid) };
        if sid <= 0 {
            return None;
        }
        // In Terminal and iTerm the session leader is `login`, owned by root, which
        // proc_pidinfo does not describe to other users; sysctl does.
        let (leader_sec, leader_usec) = start_time(sid)?;
        // The peer must still be the same process (not a recycled pid).
        let after = bsd_info(pid)?;
        if (after.pbi_start_tvsec, after.pbi_start_tvusec, after.e_tdev)
            != (
                before.pbi_start_tvsec,
                before.pbi_start_tvusec,
                before.e_tdev,
            )
        {
            return None;
        }
        Some(format!(
            "{}:{sid}:{leader_sec}.{leader_usec}",
            before.e_tdev
        ))
    }

    /// Start time of any process, from `sysctl(KERN_PROC_PID)`: the `kinfo_proc` it returns
    /// starts with `kp_proc.p_starttime` (a `timeval`). libc does not define `kinfo_proc`.
    #[cfg(target_os = "macos")]
    fn start_time(pid: libc::pid_t) -> Option<(i64, i32)> {
        const KINFO_PROC_SIZE: usize = 648;
        let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
        let mut buf = [0u8; KINFO_PROC_SIZE];
        let mut len = buf.len();
        let ok = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        } == 0;
        if !ok || len != KINFO_PROC_SIZE {
            return None; // no such process, or an unexpected layout
        }
        let sec = i64::from_ne_bytes(buf[0..8].try_into().ok()?);
        let usec = i32::from_ne_bytes(buf[8..12].try_into().ok()?);
        (sec > 0).then_some((sec, usec))
    }

    #[cfg(target_os = "macos")]
    fn bsd_info(pid: libc::pid_t) -> Option<libc::proc_bsdinfo> {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let n = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                size,
            )
        };
        (n == size).then_some(info)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(crate) fn peer_terminal(_s: &UnixStream) -> Option<String> {
        None
    }

    fn handle(store: &Store, s: UnixStream) {
        if !peer_is_me(&s) {
            return;
        }
        let terminal = peer_terminal(&s);
        let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
        let mut reader = BufReader::new(&s);
        let mut line = Zeroizing::new(String::new());
        if reader.read_line(&mut line).is_err() {
            return;
        }
        let Ok(mut msg) = serde_json::from_str::<Value>(&line) else {
            return;
        };
        let mut st = store.lock().unwrap();
        let now = Instant::now();
        st.retain(|_, e| e.expires > now);
        let key = |msg: &Value| -> Option<(String, String)> {
            Some((msg["vault"].as_str()?.to_string(), terminal.clone()?))
        };
        let reply = match msg["op"].as_str() {
            Some("ping") => json!({ "ok": true }),
            Some("info") => match key(&msg).and_then(|k| st.get(&k)) {
                Some(e) => {
                    json!({ "ok": true, "name": e.name, "kind": e.kind, "public": e.public })
                }
                None => json!({ "ok": false }),
            },
            Some("unwrap") => {
                let vault = msg["vault"].as_str().and_then(Id::parse);
                let plain = key(&msg).and_then(|k| st.get(&k)).and_then(|e| {
                    let vault = vault?;
                    let aad = b64().decode(msg["aad"].as_str()?).ok()?;
                    // Only keys of the vault the identity was cached for.
                    if !aad.starts_with(&vault.0) {
                        return None;
                    }
                    let w: Wrapped =
                        crate::format::from_cbor(&b64().decode(msg["wrapped"].as_str()?).ok()?)
                            .ok()?;
                    crate::crypto::unwrap(&e.kem, &w, &aad).ok()
                });
                match plain {
                    Some(p) => json!({ "ok": true, "plain": b64().encode(p.as_slice()) }),
                    None => json!({ "ok": false }),
                }
            }
            Some("put") => {
                let material = match msg["kem"].take() {
                    Value::String(s) => Some(Zeroizing::new(s)),
                    _ => None,
                }
                .and_then(|s| b64().decode(s.as_bytes()).ok().map(Zeroizing::new))
                .and_then(|b| {
                    let mut m = Zeroizing::new([0u8; crate::crypto::KEM_MATERIAL_LEN]);
                    (b.len() == m.len()).then(|| {
                        m.copy_from_slice(&b);
                        m
                    })
                });
                let sig_public = msg["sig_public"]
                    .as_str()
                    .and_then(|s| b64().decode(s).ok())
                    .and_then(|b| crate::format::from_cbor::<SigPublic>(&b).ok());
                match (
                    terminal.as_ref(),
                    msg["vault"].as_str(),
                    msg["name"].as_str(),
                    material,
                    sig_public,
                ) {
                    (None, ..) => json!({ "ok": false, "error": "no-terminal" }),
                    (Some(t), Some(v), Some(name), Some(material), Some(sig_public)) => {
                        let ttl = msg["ttl"]
                            .as_u64()
                            .unwrap_or(DEFAULT_TIMEOUT)
                            .min(24 * 3600);
                        let kem = crate::crypto::KemSecret::from_material(&material);
                        drop(material);
                        let public =
                            b64().encode(crate::format::to_cbor(&(kem.public(), &sig_public)));
                        st.insert(
                            (v.to_string(), t.clone()),
                            Entry {
                                name: name.to_string(),
                                kind: msg["kind"].as_str().unwrap_or("local").to_string(),
                                kem,
                                public,
                                expires: now + Duration::from_secs(ttl),
                            },
                        );
                        json!({ "ok": true })
                    }
                    _ => json!({ "ok": false }),
                }
            }
            Some("forget") => {
                // Forgetting only takes access away, so it works from any program.
                match msg["vault"].as_str() {
                    Some(v) => st.retain(|(vault, _), _| vault != v),
                    None => st.clear(),
                }
                json!({ "ok": true })
            }
            Some("status") => json!({
                "ok": true,
                "terminal": terminal.is_some(),
                "vaults": st.iter()
                    .filter(|((_, t), _)| Some(t) == terminal.as_ref())
                    .map(|((v, _), e)| json!({
                        "vault": v, "identity": e.name, "expires_in": e.expires.saturating_duration_since(now).as_secs(),
                    }))
                    .collect::<Vec<_>>(),
                "cached_elsewhere": st.keys().filter(|(_, t)| Some(t) != terminal.as_ref()).count(),
            }),
            _ => json!({ "ok": false }),
        };
        drop(st);
        let out = Zeroizing::new(format!("{reply}\n"));
        let _ = (&s).write_all(out.as_bytes());
    }

    /// `nepomuk agent --daemon`
    pub fn run_daemon() -> i32 {
        crate::memory::harden_process();
        let path = socket();
        let d = path.parent().unwrap().to_path_buf();
        if !d.is_dir()
            && (std::fs::create_dir_all(&d).is_err()
                || std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).is_err())
        {
            return 1;
        }
        if UnixStream::connect(&path).is_ok() {
            return 0; // already running
        }
        let _ = std::fs::remove_file(&path);
        let Ok(listener) = UnixListener::bind(&path) else {
            return 1;
        };
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        let store: Store = Arc::new(Mutex::new(HashMap::new()));
        let started = Instant::now();

        // Housekeeping: expiry, screen lock, exit when empty.
        let hk = store.clone();
        let sock = path.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(1));
                let mut st = hk.lock().unwrap();
                let now = Instant::now();
                st.retain(|_, e| e.expires > now);
                if crate::touchid::screen_locked() {
                    st.clear();
                }
                if st.is_empty() && now.duration_since(started) > Duration::from_secs(10) {
                    let _ = std::fs::remove_file(&sock);
                    std::process::exit(0);
                }
            }
        });

        // One thread per connection: a client that connects and stays silent must not stall
        // the others.
        for s in listener.incoming().flatten() {
            let store = store.clone();
            std::thread::spawn(move || handle(&store, s));
        }
        0
    }

    #[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
    mod server_tests {
        use super::*;

        /// The client talks only to an agent that is this program: a socket another program
        /// put in place (here a Python listener) gets nothing.
        #[test]
        fn foreign_socket_is_refused() {
            let dir = std::env::temp_dir().join(format!("np-agent-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("s.sock");
            let mut py = std::process::Command::new("python3")
                .args([
                    "-c",
                    "import socket,sys,time\ns=socket.socket(socket.AF_UNIX)\ns.bind(sys.argv[1])\ns.listen(1)\nprint('up',flush=True)\nc,_=s.accept()\ntime.sleep(2)",
                ])
                .arg(&path)
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let mut up = String::new();
            BufReader::new(py.stdout.take().unwrap())
                .read_line(&mut up)
                .unwrap();
            let foreign = UnixStream::connect(&path).unwrap();
            assert!(peer_is_me(&foreign), "same user");
            assert!(!server_is_agent(&foreign), "python is not this program");
            let _ = py.kill();
            let _ = py.wait();

            // This program itself passes.
            let own = dir.join("own.sock");
            let l = UnixListener::bind(&own).unwrap();
            let c = UnixStream::connect(&own).unwrap();
            let (_server_side, _) = l.accept().unwrap();
            assert!(server_is_agent(&c));
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[cfg(all(test, target_os = "macos"))]
    mod tests {
        use super::*;

        /// The session leader of a Terminal window is `login`, owned by root: its start time
        /// must be readable although proc_pidinfo refuses to describe it (launchd, pid 1, too).
        #[test]
        fn start_time_of_a_root_process() {
            let (sec, _) = start_time(1).expect("start time of launchd");
            let mine = bsd_info(std::process::id() as libc::pid_t).unwrap();
            assert!(sec > 0 && sec <= mine.pbi_start_tvsec as i64);
            let own = start_time(std::process::id() as libc::pid_t).unwrap();
            assert_eq!(
                own,
                (mine.pbi_start_tvsec as i64, mine.pbi_start_tvusec as i32)
            );
        }
    }
}
