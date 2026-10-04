//! The agent never hands out a seed, serves an identity only to programs in the terminal session
//! that cached it, and caches nothing for programs without a terminal.
//!
//! Each step runs in a child process: one without a controlling terminal (`setsid`), or inside a
//! fresh pseudo-terminal created by `script(1)`.
#![cfg(target_os = "linux")]

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nepomuk::crypto;
use nepomuk::identity::{Keys, Unlocked};
use nepomuk::memory::LockedSeed;
use nepomuk::model::{Id, IdentityKind};

const VAULT: [u8; 16] = [0x42; 16];

fn identity() -> Unlocked {
    Unlocked::from_seed(
        LockedSeed::from_slice(&[7u8; 64]).unwrap(),
        "tester",
        IdentityKind::Local,
    )
}

/// One step, run by a child process (see `agent_step`).
fn step(name: &str) {
    let vault = Id(VAULT);
    match name {
        "put" => match nepomuk::agent::put(vault, &identity(), 60) {
            Ok(()) => println!("PUT:ok"),
            Err(e) => println!("PUT:err:{}", e.message),
        },
        "use" => {
            let Some(k) = nepomuk::agent::keys(vault) else {
                println!("KEYS:none");
                return;
            };
            assert!(k.matches_identity(&identity()));
            println!("KEYS:some");
            let mut aad = VAULT.to_vec();
            aad.extend_from_slice(b"test");
            let w = crypto::wrap(k.kem_public(), b"node key", &aad).unwrap();
            match k.unwrap(&w, &aad) {
                Ok(p) if p.as_slice() == b"node key" => println!("UNWRAP:ok"),
                _ => println!("UNWRAP:err"),
            }
            // Keys of another vault are not unwrapped for this one.
            let other = [0x11u8; 16].to_vec();
            let w = crypto::wrap(k.kem_public(), b"other", &other).unwrap();
            println!(
                "FOREIGN:{}",
                if k.unwrap(&w, &other).is_ok() {
                    "unwrapped"
                } else {
                    "refused"
                }
            );
            // It cannot sign.
            println!(
                "SIGN:{}",
                if k.sign("commit", b"x").is_ok() {
                    "signed"
                } else {
                    "refused"
                }
            );
        }
        other => panic!("unknown step {other}"),
    }
}

trait MatchesIdentity {
    fn matches_identity(&self, id: &Unlocked) -> bool;
}

impl MatchesIdentity for nepomuk::agent::AgentKeys {
    fn matches_identity(&self, id: &Unlocked) -> bool {
        self.kem_public() == id.kem.public() && self.sig_public() == id.sig.public()
    }
}

/// Entry point of the child processes.
#[test]
#[ignore]
fn agent_step() {
    for s in std::env::var("NEPOMUK_AGENT_STEPS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
    {
        step(s);
    }
}

struct Env {
    dir: PathBuf,
}

impl Env {
    fn new() -> Env {
        let dir = std::env::temp_dir().join(format!("nepomuk-agent-term-{}", Id::random().hex()));
        std::fs::create_dir_all(dir.join("state")).unwrap();
        std::fs::create_dir_all(dir.join("run")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.join("run"), std::fs::Permissions::from_mode(0o700)).unwrap();
        Env { dir }
    }

    fn apply(&self, c: &mut Command) {
        c.env("NEPOMUK_STATE_DIR", self.dir.join("state"))
            // The steps run in this test binary; the agent is the CLI.
            .env("NEPOMUK_AGENT_EXE", env!("CARGO_BIN_EXE_nepomuk"))
            .env("NEPOMUK_CONFIG_DIR", self.dir.join("cfg"))
            .env("XDG_RUNTIME_DIR", self.dir.join("run"))
            .env("HOME", &self.dir);
    }

    fn step_cmd(&self, steps: &str) -> String {
        let exe = std::env::current_exe().unwrap();
        format!(
            "NEPOMUK_AGENT_STEPS={steps} {} --exact agent_step --ignored --nocapture --test-threads=1",
            exe.display()
        )
    }

    /// Runs steps in a new pseudo-terminal (a terminal session of its own).
    fn in_terminal(&self, steps: &[&str]) -> String {
        let script = steps
            .iter()
            .map(|s| self.step_cmd(s))
            .collect::<Vec<_>>()
            .join(" && ");
        let mut c = Command::new("script");
        c.args(["-qec", &script, "/dev/null"]);
        self.apply(&mut c);
        let out = c.stdin(Stdio::null()).output().unwrap();
        String::from_utf8_lossy(&out.stdout).replace('\r', "")
    }

    /// Runs steps in a new session without a controlling terminal.
    fn detached(&self, steps: &str) -> String {
        let mut c = Command::new("sh");
        c.args(["-c", &self.step_cmd(steps)]);
        self.apply(&mut c);
        unsafe {
            c.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let out = c.stdin(Stdio::null()).output().unwrap();
        String::from_utf8_lossy(&out.stdout).to_string()
    }
}

fn has(out: &str, marker: &str) -> bool {
    // The test harness may print its own "test agent_step ... " before the first marker.
    out.lines().any(|l| l.trim().ends_with(marker))
}

fn script_available() -> bool {
    Path::new("/usr/bin/script").exists() || Path::new("/bin/script").exists()
}

#[test]
fn agent_serves_only_the_terminal_that_unlocked() {
    if !script_available() {
        eprintln!("skipped: script(1) is not installed");
        return;
    }
    let env = Env::new();
    let mut daemon = Command::new(env!("CARGO_BIN_EXE_nepomuk"));
    daemon.args(["agent", "--daemon"]);
    env.apply(&mut daemon);
    let mut daemon = daemon
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Without a terminal nothing is cached.
    let out = env.detached("put,use");
    assert!(
        has(
            &out,
            "PUT:err:it is remembered only for programs in a terminal"
        ),
        "{out}"
    );
    assert!(has(&out, "KEYS:none"), "{out}");

    // In one terminal: cached, unwraps keys of its vault only, never signs.
    let out = env.in_terminal(&["put", "use"]);
    assert!(has(&out, "PUT:ok"), "{out}");
    assert!(has(&out, "KEYS:some"), "{out}");
    assert!(has(&out, "UNWRAP:ok"), "{out}");
    assert!(has(&out, "FOREIGN:refused"), "{out}");
    assert!(has(&out, "SIGN:refused"), "{out}");

    // Another terminal and a detached program get nothing.
    let out = env.in_terminal(&["use"]);
    assert!(has(&out, "KEYS:none"), "{out}");
    let out = env.detached("use");
    assert!(has(&out, "KEYS:none"), "{out}");

    let _ = daemon.kill();
    let _ = daemon.wait();
    let _ = std::fs::remove_dir_all(&env.dir);
}
