//! A short-lived agent that keeps identities unlocked with Touch ID, so that the CLI asks for a
//! fingerprint at most once per `agent_timeout` (default 10 minutes) – like `sudo` or `ssh-agent`.
//!
//! The agent listens on a Unix socket in the user's private state directory (`0700`, socket
//! `0600`) and serves only peers with the same UID. It forgets everything when the timeout
//! expires, when the screen locks, on `nepomuk lock`, and exits once it holds nothing.
//! Trade-off: within the timeout, any program running as this user can use the identity.

use crate::identity::Unlocked;
use crate::model::{Id, IdentityKind};

pub const DEFAULT_TIMEOUT: u64 = 600;

#[cfg(unix)]
pub use imp::*;

#[cfg(not(unix))]
mod fallback {
    use super::*;
    use crate::error::Result;

    pub fn get(_vault: Id) -> Option<Unlocked> {
        None
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
    use crate::error::{Error, Result};
    use crate::memory::LockedSeed;

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
        let mut s = UnixStream::connect(socket()).ok()?;
        s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        s.set_write_timeout(Some(Duration::from_secs(5))).ok()?;
        let line = Zeroizing::new(format!("{msg}\n"));
        s.write_all(line.as_bytes()).ok()?;
        let mut resp = Zeroizing::new(String::new());
        BufReader::new(s).read_line(&mut resp).ok()?;
        serde_json::from_str(&resp).ok()
    }

    /// The identity cached for this vault, if any.
    pub fn get(vault: Id) -> Option<Unlocked> {
        let r = request(&json!({ "op": "get", "vault": vault.hex() }))?;
        if r["ok"] != true {
            return None;
        }
        let seed = Zeroizing::new(b64().decode(r["seed"].as_str()?).ok()?);
        let kind = if r["kind"] == "password" {
            IdentityKind::Password
        } else {
            IdentityKind::Local
        };
        Some(Unlocked::from_seed(
            LockedSeed::from_slice(&seed).ok()?,
            r["name"].as_str()?,
            kind,
        ))
    }

    /// Caches an identity for `ttl` seconds, starting the agent when needed.
    pub fn put(vault: Id, id: &Unlocked, ttl: u64) -> Result<()> {
        if request(&json!({ "op": "ping" })).is_none() {
            start()?;
        }
        let seed = Zeroizing::new(b64().encode(id.seed.as_ref()));
        let kind = if id.kind == IdentityKind::Password {
            "password"
        } else {
            "local"
        };
        let msg = json!({ "op": "put", "vault": vault.hex(), "name": id.name, "kind": kind, "seed": seed.as_str(), "ttl": ttl });
        match request(&msg) {
            Some(r) if r["ok"] == true => Ok(()),
            _ => Err(Error::general(
                "the nepomuk agent did not accept the identity",
            )),
        }
    }

    /// Forgets one vault, or everything.
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
        let exe = std::env::current_exe()?;
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
        seed: LockedSeed,
        expires: Instant,
    }

    type Store = Arc<Mutex<HashMap<String, Entry>>>;

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

    fn handle(store: &Store, s: UnixStream) {
        if !peer_is_me(&s) {
            return;
        }
        let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
        let mut reader = BufReader::new(&s);
        let mut line = Zeroizing::new(String::new());
        if reader.read_line(&mut line).is_err() {
            return;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            return;
        };
        let mut st = store.lock().unwrap();
        let now = Instant::now();
        st.retain(|_, e| e.expires > now);
        let reply = match msg["op"].as_str() {
            Some("ping") => json!({ "ok": true }),
            Some("get") => match msg["vault"].as_str().and_then(|v| st.get(v)) {
                Some(e) => {
                    json!({ "ok": true, "name": e.name, "kind": e.kind, "seed": b64().encode(e.seed.as_ref()) })
                }
                None => json!({ "ok": false }),
            },
            Some("put") => {
                let seed = msg["seed"]
                    .as_str()
                    .and_then(|s| b64().decode(s).ok())
                    .map(Zeroizing::new);
                match (
                    msg["vault"].as_str(),
                    msg["name"].as_str(),
                    seed.and_then(|s| LockedSeed::from_slice(&s).ok()),
                ) {
                    (Some(v), Some(name), Some(seed)) => {
                        let ttl = msg["ttl"]
                            .as_u64()
                            .unwrap_or(DEFAULT_TIMEOUT)
                            .min(24 * 3600);
                        st.insert(
                            v.to_string(),
                            Entry {
                                name: name.to_string(),
                                kind: msg["kind"].as_str().unwrap_or("local").to_string(),
                                seed,
                                expires: now + Duration::from_secs(ttl),
                            },
                        );
                        json!({ "ok": true })
                    }
                    _ => json!({ "ok": false }),
                }
            }
            Some("forget") => {
                match msg["vault"].as_str() {
                    Some(v) => {
                        st.remove(v);
                    }
                    None => st.clear(),
                }
                json!({ "ok": true })
            }
            Some("status") => json!({
                "ok": true,
                "vaults": st.iter().map(|(v, e)| json!({
                    "vault": v, "identity": e.name, "expires_in": e.expires.saturating_duration_since(now).as_secs(),
                })).collect::<Vec<_>>(),
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

        for s in listener.incoming().flatten() {
            handle(&store, s);
        }
        0
    }
}
