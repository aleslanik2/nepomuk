#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

pub const MASTER_PASS: &str = "master-pass-phrase-long-enough";

pub struct Env {
    pub dir: tempdir::TempDir,
    pub vault: PathBuf,
}

pub mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new(tag: &str) -> TempDir {
            let p = std::env::temp_dir().join(format!(
                "nepomuk-test-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p.canonicalize().unwrap())
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    pub fn join(t: &TempDir, p: &str) -> PathBuf {
        t.0.join(p)
    }
}

/// Fails a test with a message that GitHub Actions also shows as an annotation (CI logs are
/// not always at hand).
pub fn fail(msg: &str) -> ! {
    let one_line = msg.replace('\r', "").replace('\n', " | ");
    let one_line: String = one_line.chars().take(3000).collect();
    panic!("\n::error title=test failure::{one_line}\n");
}

pub struct Res {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Res {
    pub fn json(&self) -> Value {
        serde_json::from_str(self.stdout.lines().last().unwrap_or("null"))
            .unwrap_or_else(|_| fail(&format!("not JSON: {}\n{}", self.stdout, self.stderr)))
    }
    pub fn data(&self) -> Value {
        let j = self.json();
        if j["ok"] != true {
            fail(&format!("command failed: {j}\n{}", self.stderr));
        }
        j["data"].clone()
    }
    pub fn err_code(&self) -> String {
        let j = self.json();
        if j["ok"] != false {
            fail(&format!("expected failure: {j}"));
        }
        j["error"]["code"].as_str().unwrap().to_string()
    }
    pub fn ok(self) -> Res {
        assert_eq!(
            self.code, 0,
            "exit {}:\n{}\n{}",
            self.code, self.stdout, self.stderr
        );
        self
    }
}

pub fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_nepomuk"))
}

impl Env {
    /// A fresh vault in local (non-git) mode, created by the master.
    pub fn new(tag: &str) -> Env {
        let dir = tempdir::TempDir::new(tag);
        let vault = dir.path().join("vault.nepomuk");
        let e = Env { dir, vault };
        e.cmd(&["init"], &[("NEPOMUK_PASSPHRASE", MASTER_PASS)], None)
            .ok();
        e
    }

    pub fn bare(tag: &str) -> Env {
        let dir = tempdir::TempDir::new(tag);
        let vault = dir.path().join("vault.nepomuk");
        Env { dir, vault }
    }

    pub fn path(&self, p: &str) -> PathBuf {
        self.dir.path().join(p)
    }

    pub fn master_identity(&self) -> PathBuf {
        self.path("cfg/master.npk")
    }

    pub fn command(&self, args: &[&str], env: &[(&str, &str)]) -> Command {
        let mut c = Command::new(bin());
        c.current_dir(self.dir.path())
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap())
            .env("HOME", self.dir.path())
            .env("NEPOMUK_CONFIG_DIR", self.path("cfg"))
            .env("NEPOMUK_STATE_DIR", self.path("state"))
            .env("NEPOMUK_INSECURE_TEST_KDF", "1")
            .env("NEPOMUK_NO_UPDATE_CHECK", "1")
            .env("NEPOMUK_VAULT", &self.vault)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com")
            .arg("--json")
            .args(args);
        for (k, v) in env {
            c.env(k, v);
        }
        c
    }

    /// Runs a command in a new session without a controlling terminal, so that results do not
    /// depend on whether the tests themselves run in a terminal.
    pub fn cmd(&self, args: &[&str], env: &[(&str, &str)], stdin: Option<&[u8]>) -> Res {
        let mut c = self.command(args, env);
        #[cfg(unix)]
        unsafe {
            use std::os::unix::process::CommandExt;
            c.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        c.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        {
            let mut i = child.stdin.take().unwrap();
            if let Some(s) = stdin {
                i.write_all(s).unwrap();
            }
        }
        let out: Output = child.wait_with_output().unwrap();
        Res {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        }
    }

    /// Runs as the master.
    pub fn m(&self, args: &[&str]) -> Res {
        let id = self.master_identity();
        let mut a = vec!["--identity", id.to_str().unwrap()];
        a.extend_from_slice(args);
        self.cmd(&a, &[("NEPOMUK_PASSPHRASE", MASTER_PASS)], None)
    }

    pub fn m_in(&self, args: &[&str], stdin: &[u8]) -> Res {
        let id = self.master_identity();
        let mut a = vec!["--identity", id.to_str().unwrap()];
        a.extend_from_slice(args);
        self.cmd(&a, &[("NEPOMUK_PASSPHRASE", MASTER_PASS)], Some(stdin))
    }

    /// Creates a password user and adds it (by the master).
    pub fn add_password_user(&self, email: &str) {
        let req = format!("{email}.request");
        self.cmd(
            &["identity", "request", "--email", email, "--out", &req],
            &[("NEPOMUK_PASSWORD", &password_for(email))],
            None,
        )
        .ok();
        self.m(&["user", "add", &req]).ok();
    }

    /// Creates a local identity file (e.g. a CI identity) and adds it.
    pub fn add_local_user(&self, name: &str) -> PathBuf {
        let file = self.path(&format!("{name}.npk"));
        let pass = password_for(name);
        self.cmd(
            &[
                "identity",
                "new",
                "--name",
                name,
                "--out",
                file.to_str().unwrap(),
            ],
            &[("NEPOMUK_PASSPHRASE", &pass)],
            None,
        )
        .ok();
        let req = format!("{name}.request");
        self.cmd(
            &[
                "--identity",
                file.to_str().unwrap(),
                "identity",
                "request",
                "--local",
                "--out",
                &req,
            ],
            &[("NEPOMUK_PASSPHRASE", &pass)],
            None,
        )
        .ok();
        self.m(&["user", "add", &req]).ok();
        file
    }

    /// Runs as a password user.
    pub fn u(&self, email: &str, args: &[&str]) -> Res {
        let mut a = vec!["--email", email];
        a.extend_from_slice(args);
        self.cmd(&a, &[("NEPOMUK_PASSWORD", &password_for(email))], None)
    }

    pub fn u_in(&self, email: &str, args: &[&str], stdin: &[u8]) -> Res {
        let mut a = vec!["--email", email];
        a.extend_from_slice(args);
        self.cmd(
            &a,
            &[("NEPOMUK_PASSWORD", &password_for(email))],
            Some(stdin),
        )
    }

    /// Runs as a local identity.
    pub fn l(&self, file: &Path, name: &str, args: &[&str]) -> Res {
        let mut a = vec!["--identity", file.to_str().unwrap()];
        a.extend_from_slice(args);
        self.cmd(&a, &[("NEPOMUK_PASSPHRASE", &password_for(name))], None)
    }
}

pub fn password_for(who: &str) -> String {
    format!("long-test-password-for-{}", who.replace('@', "-at-"))
}

pub fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Arguments and extra environment of one command run by [`Env::in_terminal`].
pub type TerminalCmd<'a> = (&'a [&'a str], &'a [(&'a str, &'a str)]);

/// Quotes a word for `sh`.
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

impl Env {
    /// Runs several commands one after another inside one new pseudo-terminal (one terminal
    /// session, as in a terminal window) and returns their results. Needs `script(1)`.
    pub fn in_terminal(&self, cmds: &[TerminalCmd]) -> Vec<Res> {
        let mut body = String::new();
        for (args, env) in cmds {
            // `["@sleep", "<seconds>"]` pauses inside the same terminal.
            if args.first() == Some(&"@sleep") {
                body.push_str(&format!("sleep {}; echo \"@@EXIT 0\"\n", args[1]));
                continue;
            }
            let c = self.command(args, env);
            body.push_str("env -i");
            for (k, v) in c.get_envs() {
                if let Some(v) = v {
                    body.push(' ');
                    body.push_str(&sh_quote(&format!(
                        "{}={}",
                        k.to_string_lossy(),
                        v.to_string_lossy()
                    )));
                }
            }
            body.push(' ');
            body.push_str(&sh_quote(&c.get_program().to_string_lossy()));
            for a in c.get_args() {
                body.push(' ');
                body.push_str(&sh_quote(&a.to_string_lossy()));
            }
            body.push_str(" </dev/null 2>/dev/null; echo \"@@EXIT $?\"\n");
        }
        let mut s = Command::new("script");
        if cfg!(target_os = "macos") {
            s.args(["-q", "/dev/null", "sh", "-c", &body]);
        } else {
            s.args(["-qec", &body, "/dev/null"]);
        }
        // Keep script's stdin open until it is done: some versions stop at end of input.
        let mut child = s
            .current_dir(self.dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("script(1)");
        let stdin = child.stdin.take();
        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut child.stdout.take().unwrap(), &mut raw).unwrap();
        let status = child.wait().unwrap();
        drop(stdin);
        let text = String::from_utf8_lossy(&raw).replace('\r', "");
        let mut res = Vec::new();
        let mut chunk = String::new();
        for line in text.lines() {
            if let Some(code) = line.strip_prefix("@@EXIT ") {
                res.push(Res {
                    code: code.trim().parse().unwrap_or(-1),
                    stdout: std::mem::take(&mut chunk),
                    stderr: String::new(),
                });
            } else {
                chunk.push_str(line);
                chunk.push('\n');
            }
        }
        if res.len() != cmds.len() {
            fail(&format!(
                "script(1) ran {} of {} commands (exit {status}); output:\n{text}",
                res.len(),
                cmds.len()
            ));
        }
        res
    }
}
